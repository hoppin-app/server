#!/usr/bin/env python3
"""
Tests for the hoppin bootstrap server.

Run:  ./venv/bin/python -m unittest discover -s server -v

Every test starts a real BootstrapServer in-process on an ephemeral port and
talks to it over a real socket with server/client.py, so the framing, TLS,
signing and rate limiting paths are all exercised end to end.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import datetime
import io
import json
import os
import re
import shutil
import socket
import ssl
import stat
import struct
import sys
import tempfile
import time
import unittest
import uuid
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for path in (_ROOT, _HERE):
    if path not in sys.path:
        sys.path.insert(0, path)

# The server reads HOPPIN_ENV at import time.
os.environ.setdefault("HOPPIN_ENV", "dev")

import bootstrap as bs  # noqa: E402
import apns as bsapns  # noqa: E402
import hoppin_admin  # noqa: E402
from client import (  # noqa: E402
    hoppinClient,
    ServerError,
    open_envelope,
    raw_public,
    seal_envelope,
)

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402

bs.IS_DEV = True

FIXED_CODE = "123456"
ALICE = "+351912345678"
BOB = "+14155552671"
CAROL = "+447700900123"


def async_test(coro):
    """Run an async test body on a fresh event loop (works on Python 3.9)."""
    def wrapper(self, *args, **kwargs):
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(coro(self, *args, **kwargs))
            finally:
                # The server's background tasks belong to THIS loop, so it has
                # to be shut down here rather than in tearDown.
                server = getattr(self, "server", None)
                if server is not None:
                    loop.run_until_complete(server.stop())
                    self.server = None
        finally:
            loop.close()
            asyncio.set_event_loop(None)
    wrapper.__name__ = coro.__name__
    return wrapper


def make_tls_cert(directory):
    """Self-signed P-256 cert for localhost. Returns (cert_path, key_path)."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.utcnow()
    cert = (x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                           critical=False)
            .sign(key, hashes.SHA256()))

    cert_path = os.path.join(directory, "cert.pem")
    key_path = os.path.join(directory, "key.pem")
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    return cert_path, key_path


class ServerTestCase(unittest.TestCase):
    """Base class: a plaintext dev server on an ephemeral port per test."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hoppin-test-")
        self.state_path = os.path.join(self.tmp, "state.json")
        self.reports_path = os.path.join(self.tmp, "reports.jsonl")
        self.banlist_path = os.path.join(self.tmp, "banned.txt")
        self.identity = Ed25519PrivateKey.generate()
        self.server = None

        # Keep the defaults we monkeypatch so they can be restored.
        self._saved = {
            name: getattr(bs, name) for name in
            ("MAX_CONNECTIONS_PER_IP", "READ_TIMEOUT", "QUEUE_MAX_ENVELOPES",
             "QUEUE_MAX_BYTES", "ENVELOPE_MAX_BYTES", "IP_BUCKET_CAPACITY",
             "GLOBAL_QUEUE_MAX_BYTES")
        }

    def tearDown(self):
        for name, value in self._saved.items():
            setattr(bs, name, value)
        # The server is stopped by the async_test wrapper, on its own loop.
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def start_server(self, **kwargs):
        server = bs.BootstrapServer(
            identity_key=self.identity,
            sms=bs.ConsoleSMSProvider(),
            state_path=self.state_path,
            reports_path=self.reports_path,
            dev_fixed_code=FIXED_CODE,
            banlist_path=self.banlist_path,
            report_alert_to="",
        )
        server.dev_fixed_code = FIXED_CODE
        await server.start(plaintext_port=0, allow_plaintext=True, **kwargs)
        self.server = server
        return server

    async def stop_server(self):
        if self.server is not None:
            await self.server.stop()
            self.server = None

    def client(self, phone, port=None, **kwargs):
        return hoppinClient(
            phone,
            host="127.0.0.1",
            port=port if port is not None else self.server.plaintext_port,
            server_key_b64=self.server.public_b64,
            **kwargs
        )

    async def registered(self, phone, port=None):
        c = self.client(phone, port=port)
        await c.verify_start()
        await c.verify_confirm(FIXED_CODE)
        return c


# ---------------------------------------------------------------------------
# §1 canonical encoding + fixtures
# ---------------------------------------------------------------------------

class CanonicalTests(unittest.TestCase):

    def test_contract_example(self):
        self.assertEqual(bs.canonical(["ab", "", "é"]), "2:ab0:2:é".encode("utf-8"))

    def test_empty_list(self):
        self.assertEqual(bs.canonical([]), b"")

    def test_multibyte_lengths_are_byte_counts(self):
        # "é" is 2 UTF-8 bytes, "👍" is 4.
        self.assertEqual(bs.canonical(["é"]), b"2:\xc3\xa9")
        self.assertEqual(bs.canonical(["\U0001F44D"]), b"4:\xf0\x9f\x91\x8d")

    def test_injection_is_unambiguous(self):
        # Length prefixes make a ':' inside a field harmless.
        self.assertNotEqual(bs.canonical(["a:b", "c"]), bs.canonical(["a", "b:c"]))

    def test_int_and_bool_rendering(self):
        self.assertEqual(bs.cint(0), "0")
        self.assertEqual(bs.cint(1790000000), "1790000000")
        self.assertEqual(bs.cbool(True), "1")
        self.assertEqual(bs.cbool(False), "0")
        self.assertEqual(bs.copt(None), "")

    def test_matches_generated_fixtures(self):
        path = os.path.join(_ROOT, "docs", "fixtures", "crypto_vectors.json")
        if not os.path.exists(path):
            self.skipTest("fixtures not generated yet")
        with open(path, "r", encoding="utf-8") as fh:
            vectors = json.load(fh)
        for case in vectors["canonical"]:
            self.assertEqual(bs.canonical(case["fields"]).hex(), case["hex"],
                             "canonical mismatch for %r" % (case["fields"],))


class PhoneTests(unittest.TestCase):

    def test_normalization_cases(self):
        cases = [
            ("+351 912 345 678", "PT", "+351912345678"),
            ("00351912345678", "PT", "+351912345678"),
            ("912345678", "PT", "+351912345678"),
            ("0912345678", "PT", "+351912345678"),
            ("(415) 555-2671", "US", "+14155552671"),
            ("07700 900123", "GB", "+447700900123"),
            ("12", "PT", None),
            ("abc", "US", None),
        ]
        for raw, region, expected in cases:
            self.assertEqual(bs.normalize_phone(raw, region), expected,
                             "normalize(%r, %r)" % (raw, region))

    def test_e164_validation(self):
        self.assertTrue(bs.is_valid_e164("+351912345678"))
        self.assertFalse(bs.is_valid_e164("+0123456789"))
        self.assertFalse(bs.is_valid_e164("351912345678"))
        self.assertFalse(bs.is_valid_e164("+12"))

    def test_masking_hides_the_number(self):
        masked = bs.mask_phone("+351912345678")
        self.assertTrue(masked.startswith("+35191"))
        self.assertTrue(masked.endswith("78"))
        self.assertNotIn("2345", masked)


# ---------------------------------------------------------------------------
# §2 certificates
# ---------------------------------------------------------------------------

class CertificateTests(ServerTestCase):

    @async_test
    async def test_issue_and_verify(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        cert = alice.certificate

        self.assertEqual(cert["v"], 1)
        self.assertEqual(cert["phone"], ALICE)
        self.assertEqual(cert["signingKey"], alice.signing_key_b64)
        self.assertEqual(cert["expiresAt"] - cert["issuedAt"], bs.CERT_VALIDITY)
        self.assertTrue(bs.certificate_is_valid(cert, self.server.public_b64))

    @async_test
    async def test_tampered_certificate_is_rejected(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        forged = dict(alice.certificate)
        forged["phone"] = "+351999999999"
        self.assertFalse(bs.certificate_is_valid(forged, self.server.public_b64))

    @async_test
    async def test_certificate_from_another_server_key_is_rejected(self):
        await self.start_server()
        other = Ed25519PrivateKey.generate()
        alice = self.client(ALICE)
        rogue = bs.make_certificate(other, ALICE, alice.signing_key_b64,
                                    alice.agreement_key_b64, int(time.time()))
        alice.certificate = rogue
        with self.assertRaises(ServerError) as ctx:
            await alice.ping()
        self.assertEqual(ctx.exception.code, "cert_invalid")

    @async_test
    async def test_expired_certificate_is_rejected(self):
        await self.start_server()
        alice = self.client(ALICE)
        past = int(time.time()) - 40 * 86400
        expired = bs.make_certificate(self.identity, ALICE, alice.signing_key_b64,
                                      alice.agreement_key_b64, past,
                                      past + bs.CERT_VALIDITY)
        alice.certificate = expired
        with self.assertRaises(ServerError) as ctx:
            await alice.ping()
        self.assertEqual(ctx.exception.code, "cert_invalid")

    @async_test
    async def test_cert_renew_rotates_agreement_key_and_keeps_signing_key(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        old_serial = alice.certificate["serial"]

        new_agreement = X25519PrivateKey.generate()
        new_pub = bs.b64e(raw_public(new_agreement))
        alice.agreement = new_agreement
        renewed = await alice.cert_renew(new_pub)

        self.assertEqual(renewed["signingKey"], alice.signing_key_b64)
        self.assertEqual(renewed["agreementKey"], new_pub)
        self.assertNotEqual(renewed["serial"], old_serial)
        self.assertIn(old_serial, self.server.revoked)


# ---------------------------------------------------------------------------
# §3 wire authentication
# ---------------------------------------------------------------------------

class WireAuthTests(ServerTestCase):

    @async_test
    async def test_ping_round_trip(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        reply = await alice.ping()
        self.assertEqual(reply["type"], bs.T_PONG)
        self.assertEqual(reply["senderPhone"], "server")

    @async_test
    async def test_bad_signature_rejected(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        msg = alice.build(bs.T_PING)
        # Flip the signature to a valid-length but wrong one.
        msg["signature"] = bs.b64e(Ed25519PrivateKey.generate().sign(b"nope"))
        with self.assertRaises(ServerError) as ctx:
            await alice.send(msg)
        self.assertEqual(ctx.exception.code, "bad_signature")

    @async_test
    async def test_mutated_field_breaks_the_signature(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        msg = alice.build(bs.T_CERT_LOOKUP, key=BOB)
        msg["key"] = CAROL          # signed field changed after signing
        with self.assertRaises(ServerError) as ctx:
            await alice.send(msg)
        self.assertEqual(ctx.exception.code, "bad_signature")

    @async_test
    async def test_stale_timestamp_rejected(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        stale = alice.build(bs.T_PING, timestamp=int(time.time()) - 400)
        with self.assertRaises(ServerError) as ctx:
            await alice.send(stale)
        self.assertEqual(ctx.exception.code, "stale")

        future = alice.build(bs.T_PING, timestamp=int(time.time()) + 400)
        with self.assertRaises(ServerError) as ctx:
            await alice.send(future)
        self.assertEqual(ctx.exception.code, "stale")

    @async_test
    async def test_replayed_txid_rejected(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        msg = alice.build(bs.T_PING)
        first = await alice.send(msg)
        self.assertEqual(first["type"], bs.T_PONG)
        with self.assertRaises(ServerError) as ctx:
            await alice.send(msg)
        self.assertEqual(ctx.exception.code, "replay")

    @async_test
    async def test_unsupported_type_rejected(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        with self.assertRaises(ServerError) as ctx:
            await alice.request(0x03)       # old FIND_NODE: no longer served
        self.assertEqual(ctx.exception.code, "bad_request")

    @async_test
    async def test_removed_dht_and_peer_lookup_types_are_gone(self):
        """The enumeration surface from v1 must not exist any more."""
        for removed in (0x03, 0x04, 0x05, 0x06, 0x07, 0x0D, 0x0E, 0x0F, 0x10, 0x11):
            self.assertNotIn(removed, bs.SERVER_TYPES)

    @async_test
    async def test_server_replies_are_signed(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        reply = await alice.ping()
        self.assertTrue(bs.verify_ed25519(
            self.server.public_b64,
            bs.canonical(bs.wire_signed_fields(reply)),
            reply["signature"]))

    @async_test
    async def test_response_reuses_request_txid(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        msg = alice.build(bs.T_PING)
        reply = await alice.send(msg)
        self.assertEqual(reply["txID"], msg["txID"])


# ---------------------------------------------------------------------------
# Issue 1: registry / certificate hijack
# ---------------------------------------------------------------------------

class HijackTests(ServerTestCase):

    @async_test
    async def test_attacker_cannot_act_as_victim_with_own_key(self):
        """Mallory presents Alice's phone + certificate but signs with her key."""
        await self.start_server()
        alice = await self.registered(ALICE)

        mallory = self.client(ALICE)          # different keypair, same phone
        msg = mallory.build(bs.T_PING, certificate_json=alice.certificate_json)
        with self.assertRaises(ServerError) as ctx:
            await mallory.send(msg)
        self.assertEqual(ctx.exception.code, "bad_signature")

    @async_test
    async def test_attacker_cannot_reregister_victim_without_the_code(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        original_signing = self.server.certs[ALICE]["signingKey"]

        mallory = self.client(ALICE)
        # No verifyStart for this phone by Mallory => no pending code.
        self.server.pending.pop(ALICE, None)
        with self.assertRaises(ServerError) as ctx:
            await mallory.verify_confirm("000000")
        self.assertIn(ctx.exception.code, ("invalid_code", "code_expired"))

        # The victim's registration is untouched.
        self.assertEqual(self.server.certs[ALICE]["signingKey"], original_signing)

    @async_test
    async def test_unauthenticated_ping_cannot_create_state(self):
        await self.start_server()
        mallory = self.client(ALICE)
        msg = mallory.build(bs.T_PING, with_certificate=False)
        with self.assertRaises(ServerError) as ctx:
            await mallory.send(msg)
        self.assertEqual(ctx.exception.code, "cert_invalid")
        self.assertNotIn(ALICE, self.server.certs)
        # Nothing was marked for saving, and nothing about the number is saved.
        self.assertFalse(self.server._dirty)
        self.server.save_state()
        with open(self.state_path, "r", encoding="utf-8") as fh:
            self.assertNotIn(ALICE, fh.read())

    @async_test
    async def test_superseded_certificate_cannot_act(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        old_cert_json = alice.certificate_json

        await alice.cert_renew()              # supersedes the old certificate

        stale_client = self.client(ALICE, signing_seed=None)
        stale_client.signing = alice.signing  # same key, old certificate
        msg = stale_client.build(bs.T_PING, certificate_json=old_cert_json)
        with self.assertRaises(ServerError) as ctx:
            await stale_client.send(msg)
        self.assertEqual(ctx.exception.code, "cert_invalid")


# ---------------------------------------------------------------------------
# §5 OTP verification
# ---------------------------------------------------------------------------

class VerificationTests(ServerTestCase):

    @async_test
    async def test_wrong_code_rejected(self):
        await self.start_server()
        alice = self.client(ALICE)
        await alice.verify_start()
        with self.assertRaises(ServerError) as ctx:
            await alice.verify_confirm("999999")
        self.assertEqual(ctx.exception.code, "invalid_code")
        self.assertNotIn(ALICE, self.server.certs)

    @async_test
    async def test_expired_code_rejected(self):
        await self.start_server()
        alice = self.client(ALICE)
        await alice.verify_start()
        self.server.pending[ALICE].expires_at = time.monotonic() - 1
        with self.assertRaises(ServerError) as ctx:
            await alice.verify_confirm(FIXED_CODE)
        self.assertEqual(ctx.exception.code, "code_expired")

    @async_test
    async def test_attempt_limit_enforced(self):
        await self.start_server()
        alice = self.client(ALICE)
        await alice.verify_start()

        for _ in range(bs.OTP_MAX_ATTEMPTS - 1):
            with self.assertRaises(ServerError) as ctx:
                await alice.verify_confirm("000000")
            self.assertEqual(ctx.exception.code, "invalid_code")

        with self.assertRaises(ServerError) as ctx:
            await alice.verify_confirm("000000")
        self.assertEqual(ctx.exception.code, "too_many_attempts")

        # The pending verification is gone; the right code no longer works.
        with self.assertRaises(ServerError) as ctx:
            await alice.verify_confirm(FIXED_CODE)
        self.assertEqual(ctx.exception.code, "invalid_code")

    @async_test
    async def test_verify_start_rate_limited_per_phone(self):
        await self.start_server()
        alice = self.client(ALICE)
        for _ in range(bs.VERIFY_START_PER_PHONE):
            await alice.verify_start()
        with self.assertRaises(ServerError) as ctx:
            await alice.verify_start()
        self.assertEqual(ctx.exception.code, "rate_limited")

    @async_test
    async def test_verify_start_rejects_non_e164(self):
        await self.start_server()
        alice = self.client("912345678")
        with self.assertRaises(ServerError) as ctx:
            await alice.verify_start("912345678")
        self.assertEqual(ctx.exception.code, "invalid_phone")

    @async_test
    async def test_confirm_requires_signature_by_the_registered_key(self):
        await self.start_server()
        alice = self.client(ALICE)
        await alice.verify_start()

        # Claim Mallory's signing key in the body but sign with Alice's key.
        mallory_key = Ed25519PrivateKey.generate()
        body = json.dumps({
            "code": FIXED_CODE,
            "signingKey": bs.b64e(raw_public(mallory_key)),
            "agreementKey": alice.agreement_key_b64,
        }, separators=(",", ":"))
        msg = alice.build(bs.T_VERIFY_CONFIRM, key=ALICE, value=body,
                          with_certificate=False)
        with self.assertRaises(ServerError) as ctx:
            await alice.send(msg)
        self.assertEqual(ctx.exception.code, "bad_signature")

    @async_test
    async def test_code_is_never_returned_to_the_client(self):
        await self.start_server()
        alice = self.client(ALICE)
        reply = await alice.request(bs.T_VERIFY_START, key=ALICE,
                                    with_certificate=False)
        self.assertNotIn(FIXED_CODE, json.dumps(reply))


# ---------------------------------------------------------------------------
# App Review number (guideline 2.1)
# ---------------------------------------------------------------------------

REVIEW_PHONE = "+447700900555"
REVIEW_CODE = "480213"
OTHER_CODE = "654321"


class RecordingSMS(bs.SMSProvider):
    """Records what would have been texted, instead of texting it."""

    name = "recording"

    def __init__(self):
        self.sent = []

    def send(self, phone, code):
        self.sent.append((phone, code))


class CapturedLog:
    """Collects the relay's log lines for the duration of a `with` block."""

    def __enter__(self):
        import logging

        records = self.records = []

        class Capture(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())

        self.handler = Capture()
        self.level = bs.log.level
        bs.log.addHandler(self.handler)
        bs.log.setLevel(logging.INFO)
        return self

    def __exit__(self, *exc):
        bs.log.removeHandler(self.handler)
        bs.log.setLevel(self.level)
        return False

    @property
    def text(self):
        return "\n".join(self.records)


class ReviewConfigTests(unittest.TestCase):
    """HOPPIN_REVIEW_PHONE / HOPPIN_REVIEW_CODE: both valid, or the feature is off."""

    def parse(self, phone, code):
        with CapturedLog() as captured:
            result = bs.parse_review_number(phone, code)
        # Whatever went wrong, the log never repeats the values themselves.
        for value in (phone, code):
            if value and value.strip():
                self.assertNotIn(value.strip(), captured.text)
        return result, captured.text

    def test_unset_is_off_and_quiet(self):
        self.assertEqual(self.parse(None, None), (None, ""))
        self.assertEqual(self.parse("", "  "), (None, ""))

    def test_valid_pair_is_on(self):
        result, _ = self.parse(" %s " % REVIEW_PHONE, " %s\n" % REVIEW_CODE)
        self.assertEqual(result, (REVIEW_PHONE, REVIEW_CODE))

    def test_half_set_or_malformed_is_off_with_an_error(self):
        cases = [
            (REVIEW_PHONE, None),
            (None, REVIEW_CODE),
            ("447700900555", REVIEW_CODE),        # no "+"
            ("+44 7700 900555", REVIEW_CODE),     # not E.164 as written
            (REVIEW_PHONE, "48021"),              # too short
            (REVIEW_PHONE, "4802131"),            # the app only takes 6 digits
            (REVIEW_PHONE, "48o213"),
            (REVIEW_PHONE, "４８０２１３"),  # fullwidth digits
        ]
        for phone, code in cases:
            with self.subTest(phone=phone, code=code):
                result, text = self.parse(phone, code)
                self.assertIsNone(result)
                self.assertIn("review number OFF", text)


class ReviewNumberTests(ServerTestCase):
    """One configured number signs in with a fixed code and never costs an SMS.

    It has to work in production, so these run with IS_DEV off. Every other
    number must behave exactly as before, and a code that never changes must
    not turn that one number into something anyone can guess their way into.
    """

    def setUp(self):
        super().setUp()
        self._was_dev = bs.IS_DEV
        bs.IS_DEV = False

    def tearDown(self):
        bs.IS_DEV = self._was_dev
        super().tearDown()

    async def start_server(self, review_phone=REVIEW_PHONE,
                           review_code=REVIEW_CODE, **kwargs):
        self.sms = RecordingSMS()
        server = bs.BootstrapServer(
            identity_key=self.identity,
            sms=self.sms,
            state_path=self.state_path,
            reports_path=self.reports_path,
            dev_fixed_code=FIXED_CODE,          # must be ignored outside dev
            review_phone=review_phone,
            review_code=review_code,
        )
        await server.start(plaintext_port=0, allow_plaintext=True, **kwargs)
        self.server = server
        return server

    @async_test
    async def test_review_number_signs_in_without_an_sms(self):
        await self.start_server()
        reviewer = self.client(REVIEW_PHONE)
        self.assertEqual(await reviewer.verify_start(), bs.OTP_RESEND_AFTER)
        cert = await reviewer.verify_confirm(REVIEW_CODE)

        self.assertEqual(cert["phone"], REVIEW_PHONE)
        self.assertEqual(self.sms.sent, [], "the SMS provider must not be called")
        self.assertEqual((await reviewer.ping())["type"], bs.T_PONG)

    @async_test
    async def test_other_numbers_are_untouched(self):
        await self.start_server()
        self.assertIsNone(self.server.dev_fixed_code)    # the dev path stays shut
        self.server._generate_code = lambda: OTHER_CODE

        alice = self.client(ALICE)
        await alice.verify_start()
        self.assertEqual(self.sms.sent, [(ALICE, OTHER_CODE)])

        for code in (REVIEW_CODE, FIXED_CODE):
            with self.assertRaises(ServerError) as ctx:
                await alice.verify_confirm(code)
            self.assertEqual(ctx.exception.code, "invalid_code")

        cert = await alice.verify_confirm(OTHER_CODE)
        self.assertEqual(cert["phone"], ALICE)

    @async_test
    async def test_changing_away_from_the_review_number_texts_the_new_one(self):
        await self.start_server()
        reviewer = self.client(REVIEW_PHONE)
        await reviewer.verify_start()
        await reviewer.verify_confirm(REVIEW_CODE)
        self.server._generate_code = lambda: OTHER_CODE

        # The number being verified is CAROL's, so she gets a real code.
        await reviewer.change_number_start(CAROL)
        self.assertEqual(self.sms.sent, [(CAROL, OTHER_CODE)])
        with self.assertRaises(ServerError) as ctx:
            await reviewer.change_number_confirm(CAROL, REVIEW_CODE)
        self.assertEqual(ctx.exception.code, "invalid_code")

        cert = await reviewer.change_number_confirm(CAROL, OTHER_CODE)
        self.assertEqual(cert["phone"], CAROL)

    @async_test
    async def test_a_reviewer_may_ask_for_a_few_more_codes(self):
        await self.start_server()
        reviewer = self.client(REVIEW_PHONE)
        # More than an ordinary number gets, since no SMS is sent...
        for _ in range(bs.REVIEW_START_PER_PHONE):
            await reviewer.verify_start()
        self.assertGreater(bs.REVIEW_START_PER_PHONE, bs.VERIFY_START_PER_PHONE)
        # ...but still a limit.
        with self.assertRaises(ServerError) as ctx:
            await reviewer.verify_start()
        self.assertEqual(ctx.exception.code, "rate_limited")
        # The code still works after all those requests.
        cert = await reviewer.verify_confirm(REVIEW_CODE)
        self.assertEqual(cert["phone"], REVIEW_PHONE)

    @async_test
    async def test_wrong_guesses_add_up_across_code_requests(self):
        """A fresh request normally means a fresh code; here it does not, so
        wrong guesses are capped per day for the number, not per request."""
        await self.start_server()
        reviewer = self.client(REVIEW_PHONE)
        wrong = "000000"
        self.assertNotEqual(wrong, REVIEW_CODE)

        left = bs.REVIEW_MAX_FAILURES - 1
        while left:
            await reviewer.verify_start()
            for _ in range(min(bs.OTP_MAX_ATTEMPTS - 1, left)):
                with self.assertRaises(ServerError) as ctx:
                    await reviewer.verify_confirm(wrong)
                self.assertEqual(ctx.exception.code, "invalid_code")
                left -= 1

        # The last allowed wrong guess locks the number...
        with self.assertRaises(ServerError) as ctx:
            await reviewer.verify_confirm(wrong)
        self.assertEqual(ctx.exception.code, "too_many_attempts")

        # ...so no new code can be requested, and the right one gets nowhere.
        with self.assertRaises(ServerError) as ctx:
            await reviewer.verify_start()
        self.assertEqual(ctx.exception.code, "rate_limited")
        with self.assertRaises(ServerError):
            await reviewer.verify_confirm(REVIEW_CODE)
        self.assertNotIn(REVIEW_PHONE, self.server.certs)

        # Nobody else is affected.
        await self.client(ALICE).verify_start()
        self.assertEqual(len(self.sms.sent), 1)

    @async_test
    async def test_a_locked_review_number_refuses_even_the_right_code(self):
        await self.start_server()
        reviewer = self.client(REVIEW_PHONE)
        await reviewer.verify_start()
        for _ in range(bs.REVIEW_MAX_FAILURES):
            self.server.review_failures.hit("review", bs.REVIEW_MAX_FAILURES)

        with self.assertRaises(ServerError) as ctx:
            await reviewer.verify_confirm(REVIEW_CODE)
        self.assertEqual(ctx.exception.code, "too_many_attempts")
        self.assertNotIn(REVIEW_PHONE, self.server.certs)

    @async_test
    async def test_invalid_config_leaves_the_relay_up_and_the_feature_off(self):
        await self.start_server(review_code="12345")
        self.assertIsNone(self.server.review_phone)

        reviewer = self.client(REVIEW_PHONE)
        await reviewer.verify_start()
        # An ordinary number now: a real SMS, and no fixed code.
        self.assertEqual([p for p, _ in self.sms.sent], [REVIEW_PHONE])

    @async_test
    async def test_sign_in_is_logged_masked_and_the_code_never(self):
        with CapturedLog() as captured:
            await self.start_server()
            reviewer = self.client(REVIEW_PHONE)
            await reviewer.verify_start()
            with self.assertRaises(ServerError):
                await reviewer.verify_confirm("000000")
            await reviewer.verify_confirm(REVIEW_CODE)

        self.assertNotIn(REVIEW_CODE, captured.text)
        self.assertNotIn(REVIEW_PHONE, captured.text)
        self.assertIn("review number signed in: %s" % bs.mask_phone(REVIEW_PHONE),
                      captured.text)


# ---------------------------------------------------------------------------
# Issue 2: enumeration / privacy
# ---------------------------------------------------------------------------

class LookupPrivacyTests(ServerTestCase):

    @async_test
    async def test_lookup_requires_authentication(self):
        await self.start_server()
        await self.registered(BOB)
        stranger = self.client(CAROL)
        msg = stranger.build(bs.T_CERT_LOOKUP, key=BOB, with_certificate=False)
        with self.assertRaises(ServerError) as ctx:
            await stranger.send(msg)
        self.assertEqual(ctx.exception.code, "cert_invalid")

    @async_test
    async def test_lookup_returns_only_the_certificate(self):
        await self.start_server()
        bob = await self.registered(BOB)
        alice = await self.registered(ALICE)

        found = await alice.cert_lookup(BOB)
        self.assertEqual(found["phone"], BOB)
        self.assertEqual(set(found.keys()),
                         {"v", "phone", "signingKey", "agreementKey",
                          "issuedAt", "expiresAt", "serial", "sig"})
        # No address information of any kind.
        blob = json.dumps(found)
        self.assertNotIn("127.0.0.1", blob)
        self.assertNotIn("ip", found)
        self.assertNotIn("port", found)

    @async_test
    async def test_lookup_of_unknown_number_returns_empty(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        self.assertIsNone(await alice.cert_lookup("+447700900999"))

    @async_test
    async def test_lookup_rate_limited(self):
        await self.start_server()
        bs.IP_BUCKET_CAPACITY = 10_000     # isolate the per-caller limit
        alice = await self.registered(ALICE)
        self.server.ip_buckets.clear()

        for _ in range(bs.CERT_LOOKUP_PER_CALLER):
            await alice.cert_lookup(BOB)
        with self.assertRaises(ServerError) as ctx:
            await alice.cert_lookup(BOB)
        self.assertEqual(ctx.exception.code, "rate_limited")

    @async_test
    async def test_server_has_no_peer_registry_api(self):
        """There must be no handler that can return a list of peers."""
        for name in ("h_find_node", "h_find_value", "h_store", "h_hole_punch",
                     "h_relay", "h_offline_notify", "h_came_online"):
            self.assertFalse(hasattr(bs.BootstrapServer, name),
                             "removed handler %s is still present" % name)


# ---------------------------------------------------------------------------
# Issue 4: store-and-forward relay
# ---------------------------------------------------------------------------

class RelayTests(ServerTestCase):

    async def _pair(self):
        alice = await self.registered(ALICE)
        bob = await self.registered(BOB)
        return alice, bob

    @async_test
    async def test_deposit_fetch_ack_round_trip(self):
        await self.start_server()
        alice, bob = await self._pair()

        payload = json.dumps({"kind": "text", "text": "hello", "sentAt": 1}).encode()
        env = alice.seal_to(bob.certificate, payload)
        env_id = await alice.deposit(env)
        self.assertEqual(env_id, env["id"])

        mail = await bob.fetch(wait=0)
        self.assertEqual(len(mail), 1)
        self.assertEqual(mail[0]["id"], env["id"])

        # Bob can actually decrypt it: the relay is transparent.
        plain = open_envelope(mail[0], bob.agreement,
                              alice.signing_key_b64, bob.signing_key_b64)
        self.assertEqual(json.loads(plain)["text"], "hello")

        await bob.ack([env["id"]])
        self.assertEqual(await bob.fetch(wait=0), [])

    @async_test
    async def test_long_poll_wakes_on_delivery(self):
        await self.start_server()
        alice, bob = await self._pair()

        started = time.monotonic()
        fetch_task = asyncio.ensure_future(bob.fetch(wait=20))
        await asyncio.sleep(0.25)          # let the fetch reach the hold

        env = alice.seal_to(bob.certificate, b'{"kind":"text","sentAt":1}')
        await alice.deposit(env)

        mail = await asyncio.wait_for(fetch_task, 10)
        elapsed = time.monotonic() - started

        self.assertEqual(len(mail), 1)
        self.assertLess(elapsed, 5.0, "long poll did not wake promptly")

    @async_test
    async def test_long_poll_times_out_empty(self):
        await self.start_server()
        bob = await self.registered(BOB)
        started = time.monotonic()
        mail = await bob.fetch(wait=1)
        self.assertEqual(mail, [])
        self.assertGreaterEqual(time.monotonic() - started, 0.9)

    @async_test
    async def test_forged_envelope_signature_rejected(self):
        await self.start_server()
        alice, bob = await self._pair()
        env = alice.seal_to(bob.certificate, b'{"kind":"text","sentAt":1}')
        env["signature"] = bs.b64e(Ed25519PrivateKey.generate().sign(b"nope"))
        with self.assertRaises(ServerError) as ctx:
            await alice.deposit(env)
        self.assertEqual(ctx.exception.code, "bad_signature")

    @async_test
    async def test_envelope_signed_by_another_key_rejected(self):
        """Mallory cannot deposit mail that claims to be from Alice."""
        await self.start_server()
        alice, bob = await self._pair()
        mallory = await self.registered(CAROL)

        env, _ = seal_envelope(
            payload=b'{"kind":"text","sentAt":1}',
            envelope_id=str(uuid.uuid4()),
            sender_phone=ALICE,                     # lies about the sender
            recipient_phone=BOB,
            timestamp=int(time.time()),
            sender_signing=mallory.signing,         # but signs with her own key
            sender_agreement=mallory.agreement,
            recipient_signing_b64=bob.signing_key_b64,
            recipient_agreement_b64=bob.certificate["agreementKey"],
            sender_certificate_json=alice.certificate_json,
        )
        msg = mallory.build(bs.T_RELAY_DEPOSIT, envelope=env, recipient_phone=BOB)
        with self.assertRaises(ServerError) as ctx:
            await mallory.send(msg)
        # senderPhone mismatch is caught before the signature check.
        self.assertIn(ctx.exception.code, ("bad_request", "bad_signature"))

    @async_test
    async def test_envelope_sender_must_match_wire_sender(self):
        await self.start_server()
        alice, bob = await self._pair()
        env = alice.seal_to(bob.certificate, b'{"kind":"text","sentAt":1}')
        env["senderPhone"] = CAROL
        with self.assertRaises(ServerError) as ctx:
            await alice.deposit(env)
        self.assertEqual(ctx.exception.code, "bad_request")

    @async_test
    async def test_envelope_recipient_must_match_wire_recipient(self):
        await self.start_server()
        alice, bob = await self._pair()
        env = alice.seal_to(bob.certificate, b'{"kind":"text","sentAt":1}')
        msg = alice.build(bs.T_RELAY_DEPOSIT, envelope=env, recipient_phone=CAROL)
        with self.assertRaises(ServerError) as ctx:
            await alice.send(msg)
        self.assertEqual(ctx.exception.code, "bad_request")

    @async_test
    async def test_deposit_to_deleted_account_is_refused(self):
        await self.start_server()
        alice, bob = await self._pair()
        env = alice.seal_to(bob.certificate, b'{"kind":"text","sentAt":1}')
        await bob.delete_account()
        with self.assertRaises(ServerError) as ctx:
            await alice.deposit(env)
        self.assertEqual(ctx.exception.code, "recipient_not_registered")
        # Nothing was queued for the dead number.
        self.assertNotIn(bob.phone, self.server.queue)

    @async_test
    async def test_unregistered_deposits_are_metered_like_lookups(self):
        await self.start_server()
        bs.IP_BUCKET_CAPACITY = 10_000     # isolate the per-caller limit
        alice, bob = await self._pair()
        env = alice.seal_to(bob.certificate, b'{"kind":"text","sentAt":1}')
        await bob.delete_account()
        self.server.ip_buckets.clear()
        for _ in range(bs.CERT_LOOKUP_PER_CALLER):
            with self.assertRaises(ServerError) as ctx:
                await alice.deposit(env)
            self.assertEqual(ctx.exception.code, "recipient_not_registered")
        with self.assertRaises(ServerError) as ctx:
            await alice.deposit(env)
        self.assertEqual(ctx.exception.code, "rate_limited")

    @async_test
    async def test_deposit_is_idempotent_by_id(self):
        await self.start_server()
        alice, bob = await self._pair()
        env = alice.seal_to(bob.certificate, b'{"kind":"text","sentAt":1}')
        await alice.deposit(env)
        await alice.deposit(dict(env))
        self.assertEqual(len(await bob.fetch(wait=0)), 1)

    @async_test
    async def test_queue_envelope_cap(self):
        await self.start_server()
        bs.QUEUE_MAX_ENVELOPES = 2
        alice, bob = await self._pair()

        for _ in range(2):
            await alice.deposit(alice.seal_to(bob.certificate,
                                              b'{"kind":"text","sentAt":1}'))
        with self.assertRaises(ServerError) as ctx:
            await alice.deposit(alice.seal_to(bob.certificate,
                                              b'{"kind":"text","sentAt":1}'))
        self.assertEqual(ctx.exception.code, "queue_full")

    @async_test
    async def test_queue_byte_cap(self):
        await self.start_server()
        # One sealed 3 KB payload is ~4.6 KB on the wire, so the cap has to sit
        # between one and two envelopes.
        bs.QUEUE_MAX_BYTES = 6000
        alice, bob = await self._pair()
        big = b"x" * 3000
        await alice.deposit(alice.seal_to(bob.certificate, big))
        with self.assertRaises(ServerError) as ctx:
            await alice.deposit(alice.seal_to(bob.certificate, big))
        self.assertEqual(ctx.exception.code, "queue_full")

    @async_test
    async def test_oversized_envelope_rejected(self):
        await self.start_server()
        bs.ENVELOPE_MAX_BYTES = 2048
        alice, bob = await self._pair()
        env = alice.seal_to(bob.certificate, b"y" * 4096)
        with self.assertRaises(ServerError) as ctx:
            await alice.deposit(env)
        self.assertEqual(ctx.exception.code, "too_large")

    @async_test
    async def test_ack_only_affects_own_mailbox(self):
        await self.start_server()
        alice, bob = await self._pair()
        env = alice.seal_to(bob.certificate, b'{"kind":"text","sentAt":1}')
        await alice.deposit(env)
        await alice.ack([env["id"]])        # Alice acking Bob's mail: no effect
        self.assertEqual(len(await bob.fetch(wait=0)), 1)

    @async_test
    async def test_fetch_respects_max(self):
        await self.start_server()
        alice, bob = await self._pair()
        for _ in range(5):
            await alice.deposit(alice.seal_to(bob.certificate,
                                              b'{"kind":"text","sentAt":1}'))
        self.assertEqual(len(await bob.fetch(wait=0, max_items=2)), 2)

    @async_test
    async def test_expired_mail_is_not_delivered(self):
        await self.start_server()
        alice, bob = await self._pair()
        env = alice.seal_to(bob.certificate, b'{"kind":"text","sentAt":1}')
        await alice.deposit(env)
        # Age the item past the 7-day TTL.
        for item in self.server.queue[BOB]:
            item["at"] = int(time.time()) - bs.QUEUE_TTL - 1
        self.assertEqual(await bob.fetch(wait=0), [])


# ---------------------------------------------------------------------------
# Account lifecycle
# ---------------------------------------------------------------------------

class AccountTests(ServerTestCase):

    @async_test
    async def test_change_number_revokes_old_certificate(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        old_cert = dict(alice.certificate)
        new_phone = "+351911111111"

        await alice.change_number_start(new_phone)
        new_cert = await alice.change_number_confirm(new_phone, FIXED_CODE)

        self.assertEqual(new_cert["phone"], new_phone)
        self.assertEqual(new_cert["signingKey"], old_cert["signingKey"])
        self.assertEqual(new_cert["agreementKey"], old_cert["agreementKey"])
        self.assertIn(old_cert["serial"], self.server.revoked)
        self.assertNotIn(ALICE, self.server.certs)
        self.assertIn(new_phone, self.server.certs)

        # The old number leaves no trace in the saved state.
        self.server.save_state()
        with open(self.state_path, "r", encoding="utf-8") as fh:
            self.assertNotIn(ALICE, fh.read())

        # The old certificate can no longer be used.
        stale = self.client(ALICE)
        stale.signing = alice.signing
        msg = stale.build(bs.T_PING,
                          certificate_json=bs.encode_certificate(old_cert))
        with self.assertRaises(ServerError) as ctx:
            await stale.send(msg)
        self.assertEqual(ctx.exception.code, "cert_invalid")

    @async_test
    async def test_change_number_carries_queued_mail(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        bob = await self.registered(BOB)
        env = bob.seal_to(alice.certificate, b'{"kind":"text","sentAt":1}')
        await bob.deposit(env)

        new_phone = "+351911111111"
        await alice.change_number_start(new_phone)
        await alice.change_number_confirm(new_phone, FIXED_CODE)

        mail = await alice.fetch(wait=0)
        self.assertEqual(len(mail), 1)

    @async_test
    async def test_change_number_wrong_code_rejected(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        new_phone = "+351911111111"
        await alice.change_number_start(new_phone)
        with self.assertRaises(ServerError) as ctx:
            await alice.change_number_confirm(new_phone, "000000")
        self.assertEqual(ctx.exception.code, "invalid_code")
        self.assertIn(ALICE, self.server.certs)

    @async_test
    async def test_delete_account_purges_everything(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        bob = await self.registered(BOB)
        await bob.deposit(bob.seal_to(alice.certificate,
                                      b'{"kind":"text","sentAt":1}'))
        serial = alice.certificate["serial"]

        await alice.delete_account()

        self.assertNotIn(ALICE, self.server.certs)
        self.assertNotIn(ALICE, self.server.queue)
        self.assertIn(serial, self.server.revoked)

        # The saved state keeps the revoked serial and nothing with her number.
        self.server.save_state()
        with open(self.state_path, "r", encoding="utf-8") as fh:
            saved = fh.read()
        self.assertNotIn(ALICE, saved)
        self.assertIn(serial, saved)

        # Alice is no longer discoverable.
        self.assertIsNone(await bob.cert_lookup(ALICE))

    @async_test
    async def test_report_is_written_with_mode_600(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        await alice.report(BOB, "spam", [{"id": "m1", "timestamp": 1, "text": "hi"}])

        self.assertTrue(os.path.exists(self.reports_path))
        mode = stat.S_IMODE(os.stat(self.reports_path).st_mode)
        self.assertEqual(mode, 0o600, "reports file must be 0600, got %o" % mode)

        with open(self.reports_path, "r", encoding="utf-8") as fh:
            lines = [json.loads(l) for l in fh if l.strip()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["reportedPhone"], BOB)
        self.assertEqual(lines[0]["reporter"], ALICE)

    @async_test
    async def test_report_evidence_is_capped(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        evidence = [{"id": str(i), "timestamp": 1, "text": "x"} for i in range(50)]
        with self.assertRaises(ServerError) as ctx:
            await alice.report(BOB, "spam", evidence)
        self.assertEqual(ctx.exception.code, "bad_request")


# ---------------------------------------------------------------------------
# Issue 9: persistence
# ---------------------------------------------------------------------------

class PersistenceTests(ServerTestCase):

    @async_test
    async def test_state_survives_restart(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        bob = await self.registered(BOB)
        env = alice.seal_to(bob.certificate, b'{"kind":"text","sentAt":1}')
        await alice.deposit(env)
        alice_serial = alice.certificate["serial"]

        await self.stop_server()

        # Same state file, fresh process state.
        await self.start_server()
        self.assertIn(ALICE, self.server.certs)
        self.assertEqual(self.server.certs[ALICE]["serial"], alice_serial)
        self.assertIn(BOB, self.server.queue)
        self.assertEqual(self.server.queue[BOB][0]["env"]["id"], env["id"])

        # And the restored mailbox is still fetchable by Bob.
        bob.port = self.server.plaintext_port
        bob.server_key_b64 = self.server.public_b64
        mail = await bob.fetch(wait=0)
        self.assertEqual(len(mail), 1)

    @async_test
    async def test_old_state_with_last_seen_loads_and_drops_it(self):
        """lastSeen was stored and never read; the relay no longer keeps it."""
        await self.start_server()
        alice = await self.registered(ALICE)
        await alice.ping()
        await alice.fetch(wait=0)
        self.server.save_state()
        await self.stop_server()

        with open(self.state_path, "r", encoding="utf-8") as fh:
            state = json.load(fh)
        self.assertNotIn("lastSeen", state)

        # A state file written by an older relay still has it.
        state["lastSeen"] = {ALICE: int(time.time())}
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(state, fh)

        await self.start_server()
        self.assertEqual(self.server.certs[ALICE]["serial"],
                         alice.certificate["serial"])
        self.server.save_state()
        with open(self.state_path, "r", encoding="utf-8") as fh:
            self.assertNotIn("lastSeen", json.load(fh))

    @async_test
    async def test_state_file_is_mode_600(self):
        await self.start_server()
        await self.registered(ALICE)
        self.server.save_state()
        mode = stat.S_IMODE(os.stat(self.state_path).st_mode)
        self.assertEqual(mode, 0o600, "state file must be 0600, got %o" % mode)

    @async_test
    async def test_state_write_is_atomic(self):
        await self.start_server()
        await self.registered(ALICE)
        self.server.save_state()
        leftovers = [f for f in os.listdir(self.tmp) if f.endswith(".tmp")]
        self.assertEqual(leftovers, [], "temp files left behind: %r" % leftovers)

    @async_test
    async def test_identity_key_file_is_600_and_reused(self):
        path = os.path.join(self.tmp, "identity.key")
        first = bs.load_or_create_identity_key(path)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode, 0o600, "identity key must be 0600, got %o" % mode)
        second = bs.load_or_create_identity_key(path)
        self.assertEqual(bs.public_key_b64(first), bs.public_key_b64(second))


# ---------------------------------------------------------------------------
# Issues 3 & 6: transport hardening
# ---------------------------------------------------------------------------

class TransportTests(ServerTestCase):

    @async_test
    async def test_tls_handshake_and_request(self):
        cert_path, key_path = make_tls_cert(self.tmp)
        await self.start_server(tls_port=0, tls_cert=cert_path, tls_key=key_path)
        self.assertIsNotNone(self.server.tls_port)

        alice = hoppinClient(ALICE, host="127.0.0.1", port=self.server.tls_port,
                              use_tls=True, cafile=cert_path,
                              server_key_b64=self.server.public_b64,
                              server_hostname="localhost")
        await alice.verify_start()
        cert = await alice.verify_confirm(FIXED_CODE)
        self.assertEqual(cert["phone"], ALICE)
        reply = await alice.ping()
        self.assertEqual(reply["type"], bs.T_PONG)

    @async_test
    async def test_plaintext_not_listening_when_not_allowed(self):
        cert_path, key_path = make_tls_cert(self.tmp)
        server = bs.BootstrapServer(identity_key=self.identity,
                                    sms=bs.ConsoleSMSProvider(),
                                    state_path=self.state_path,
                                    reports_path=self.reports_path,
                                    dev_fixed_code=FIXED_CODE)
        await server.start(tls_port=0, tls_cert=cert_path, tls_key=key_path,
                           allow_plaintext=False)
        self.server = server
        self.assertIsNone(server.plaintext_port)
        self.assertIsNotNone(server.tls_port)

    @async_test
    async def test_refuses_to_start_with_no_listener(self):
        server = bs.BootstrapServer(identity_key=self.identity,
                                    sms=bs.ConsoleSMSProvider(),
                                    state_path=self.state_path,
                                    reports_path=self.reports_path)
        with self.assertRaises(SystemExit):
            await server.start(allow_plaintext=False)

    @async_test
    async def test_oversized_frame_rejected(self):
        await self.start_server()
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", self.server.plaintext_port)
        try:
            writer.write(struct.pack(">I", bs.MAX_FRAME + 1))
            await writer.drain()
            data = await asyncio.wait_for(reader.read(4096), 5)
        finally:
            writer.close()

        if data:
            body = json.loads(data[4:].decode("utf-8"))
            self.assertEqual(body["type"], bs.T_ERROR)
            self.assertEqual(body["key"], "too_large")
        # An immediate close is also an acceptable response.

    @async_test
    async def test_zero_length_frame_rejected(self):
        await self.start_server()
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", self.server.plaintext_port)
        try:
            writer.write(struct.pack(">I", 0))
            await writer.drain()
            data = await asyncio.wait_for(reader.read(4096), 5)
        finally:
            writer.close()
        if data:
            body = json.loads(data[4:].decode("utf-8"))
            self.assertEqual(body["key"], "too_large")

    @async_test
    async def test_slow_loris_read_timeout(self):
        bs.READ_TIMEOUT = 0.4
        await self.start_server()

        reader, writer = await asyncio.open_connection(
            "127.0.0.1", self.server.plaintext_port)
        try:
            writer.write(b"\x00\x00")        # partial header, then stall
            await writer.drain()
            started = time.monotonic()
            data = await asyncio.wait_for(reader.read(4096), 5)
            elapsed = time.monotonic() - started
        finally:
            writer.close()

        self.assertEqual(data, b"", "server should drop a stalled connection")
        self.assertLess(elapsed, 3.0, "server did not time out the read")

    @async_test
    async def test_connection_cap_per_ip(self):
        bs.MAX_CONNECTIONS_PER_IP = 4
        bs.READ_TIMEOUT = 5.0
        await self.start_server()
        port = self.server.plaintext_port

        held = []
        try:
            for _ in range(bs.MAX_CONNECTIONS_PER_IP):
                held.append(await asyncio.open_connection("127.0.0.1", port))
            await asyncio.sleep(0.2)

            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            held.append((reader, writer))
            data = await asyncio.wait_for(reader.read(1), 3)
            self.assertEqual(data, b"", "connection beyond the cap should be dropped")
        finally:
            for _, writer in held:
                writer.close()

    @async_test
    async def test_ip_token_bucket(self):
        bs.IP_BUCKET_CAPACITY = 3
        await self.start_server()
        alice = await self.registered(ALICE)
        self.server.ip_buckets.clear()
        self.server.ip_buckets["127.0.0.1"] = bs.TokenBucket(3, 0.0)

        for _ in range(3):
            await alice.ping()
        with self.assertRaises(ServerError) as ctx:
            await alice.ping()
        self.assertEqual(ctx.exception.code, "rate_limited")

    @async_test
    async def test_malformed_json_rejected(self):
        await self.start_server()
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", self.server.plaintext_port)
        try:
            payload = b"{not json"
            writer.write(struct.pack(">I", len(payload)) + payload)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(4096), 5)
        finally:
            writer.close()
        body = json.loads(data[4:].decode("utf-8"))
        self.assertEqual(body["type"], bs.T_ERROR)
        self.assertEqual(body["key"], "bad_request")


# ---------------------------------------------------------------------------
# §4 envelope crypto (cross-checks the fixtures Swift consumes)
# ---------------------------------------------------------------------------

class EnvelopeCryptoTests(unittest.TestCase):

    def setUp(self):
        self.server_key = Ed25519PrivateKey.generate()
        self.alice_sign = Ed25519PrivateKey.generate()
        self.alice_agree = X25519PrivateKey.generate()
        self.bob_sign = Ed25519PrivateKey.generate()
        self.bob_agree = X25519PrivateKey.generate()
        self.alice_cert = bs.make_certificate(
            self.server_key, ALICE, bs.b64e(raw_public(self.alice_sign)),
            bs.b64e(raw_public(self.alice_agree)), int(time.time()))

    def test_seal_then_open(self):
        payload = json.dumps({"kind": "text", "text": "olá 👋",
                              "sentAt": 1}).encode("utf-8")
        env, key = seal_envelope(
            payload=payload, envelope_id=str(uuid.uuid4()),
            sender_phone=ALICE, recipient_phone=BOB, timestamp=int(time.time()),
            sender_signing=self.alice_sign, sender_agreement=self.alice_agree,
            recipient_signing_b64=bs.b64e(raw_public(self.bob_sign)),
            recipient_agreement_b64=bs.b64e(raw_public(self.bob_agree)),
            sender_certificate_json=bs.encode_certificate(self.alice_cert))

        self.assertEqual(len(key), 32)
        out = open_envelope(env, self.bob_agree,
                            bs.b64e(raw_public(self.alice_sign)),
                            bs.b64e(raw_public(self.bob_sign)))
        self.assertEqual(out, payload)

    def test_ciphertext_is_nonce_prefixed_combined_form(self):
        env, _ = seal_envelope(
            payload=b"hi", envelope_id="id", sender_phone=ALICE,
            recipient_phone=BOB, timestamp=1, sender_signing=self.alice_sign,
            sender_agreement=self.alice_agree,
            recipient_signing_b64=bs.b64e(raw_public(self.bob_sign)),
            recipient_agreement_b64=bs.b64e(raw_public(self.bob_agree)),
            sender_certificate_json="", nonce=bytes(range(12)))
        combined = base64.b64decode(env["ciphertext"])
        self.assertEqual(combined[:12], bytes(range(12)))
        self.assertEqual(len(combined), 12 + 2 + 16)     # nonce + ct + tag

    def test_tampered_header_breaks_decryption(self):
        env, _ = seal_envelope(
            payload=b"hi", envelope_id="id", sender_phone=ALICE,
            recipient_phone=BOB, timestamp=1, sender_signing=self.alice_sign,
            sender_agreement=self.alice_agree,
            recipient_signing_b64=bs.b64e(raw_public(self.bob_sign)),
            recipient_agreement_b64=bs.b64e(raw_public(self.bob_agree)),
            sender_certificate_json="")
        env["timestamp"] = 999                   # header is AEAD-authenticated
        with self.assertRaises(Exception):
            open_envelope(env, self.bob_agree,
                          bs.b64e(raw_public(self.alice_sign)),
                          bs.b64e(raw_public(self.bob_sign)))

    def test_digest_hex_is_stable_and_lowercase(self):
        env, _ = seal_envelope(
            payload=b"hi", envelope_id="id", sender_phone=ALICE,
            recipient_phone=BOB, timestamp=1, sender_signing=self.alice_sign,
            sender_agreement=self.alice_agree,
            recipient_signing_b64=bs.b64e(raw_public(self.bob_sign)),
            recipient_agreement_b64=bs.b64e(raw_public(self.bob_agree)),
            sender_certificate_json="")
        digest = bs.envelope_digest_hex(env)
        self.assertEqual(len(digest), 64)
        self.assertEqual(digest, digest.lower())
        self.assertEqual(digest, bs.envelope_digest_hex(env))


class FixtureTests(unittest.TestCase):
    """The fixtures Swift consumes must be internally consistent."""

    @classmethod
    def setUpClass(cls):
        cls.path = os.path.join(_ROOT, "docs", "fixtures", "crypto_vectors.json")
        cls.vectors = None
        if os.path.exists(cls.path):
            with open(cls.path, "r", encoding="utf-8") as fh:
                cls.vectors = json.load(fh)

    def setUp(self):
        if self.vectors is None:
            self.skipTest("run server/make_vectors.py first")

    def test_certificates_verify_against_the_fixture_server_key(self):
        server_pub = self.vectors["server"]["publicKeyBase64"]
        for name in ("alice", "bob"):
            cert = self.vectors["certificates"][name]["certificate"]
            self.assertTrue(bs.certificate_is_valid(cert, server_pub),
                            "%s certificate should verify" % name)

    def test_tampered_certificate_does_not_verify(self):
        server_pub = self.vectors["server"]["publicKeyBase64"]
        cert = self.vectors["certificates"]["tampered"]["certificate"]
        self.assertFalse(bs.certificate_is_valid(cert, server_pub))

    def test_wire_signature_verifies(self):
        wire = self.vectors["wire"]["message"]
        alice_key = self.vectors["alice"]["signingKeyBase64"]
        self.assertTrue(bs.verify_ed25519(
            alice_key, bs.canonical(bs.wire_signed_fields(wire)),
            wire["signature"]))
        self.assertEqual(bs.canonical(bs.wire_signed_fields(wire)).hex(),
                         self.vectors["wire"]["signedFieldsHex"])

    def test_envelope_opens_with_bobs_agreement_key(self):
        env = self.vectors["envelope"]["envelope"]
        bob_priv = X25519PrivateKey.from_private_bytes(
            base64.b64decode(self.vectors["bob"]["agreementPrivateBase64"]))
        plain = open_envelope(env, bob_priv,
                              self.vectors["alice"]["signingKeyBase64"],
                              self.vectors["bob"]["signingKeyBase64"])
        self.assertEqual(plain.decode("utf-8"),
                         self.vectors["envelope"]["plaintextJSON"])

    def test_envelope_digest_matches(self):
        env = self.vectors["envelope"]["envelope"]
        self.assertEqual(bs.envelope_digest_hex(env),
                         self.vectors["envelope"]["digestHex"])

    def test_safety_number_shape(self):
        expected = self.vectors["safetyNumber"]["expected"]
        self.assertEqual(len(expected), 60)
        self.assertTrue(expected.isdigit())
        halves = sorted([self.vectors["safetyNumber"]["aliceHalf"],
                         self.vectors["safetyNumber"]["bobHalf"]])
        self.assertEqual(expected, "".join(halves))

    def test_phone_vectors_match_the_implementation(self):
        for case in self.vectors["phones"]:
            self.assertEqual(
                bs.normalize_phone(case["raw"], case["region"]),
                case["expected"],
                "normalize(%r, %r)" % (case["raw"], case["region"]))

    def test_generation_is_deterministic(self):
        """Re-running the generator must not change the file."""
        import subprocess
        with open(self.path, "rb") as fh:
            before = fh.read()
        result = subprocess.run(
            [sys.executable, os.path.join(_HERE, "make_vectors.py")],
            capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        with open(self.path, "rb") as fh:
            self.assertEqual(before, fh.read(), "fixtures are not deterministic")


# ---------------------------------------------------------------------------
# Issue 8: logging hygiene
# ---------------------------------------------------------------------------

class LoggingTests(ServerTestCase):

    @async_test
    async def test_phones_are_masked_and_codes_never_logged(self):
        import logging

        records = []

        class Capture(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())

        handler = Capture()
        bs.log.addHandler(handler)
        bs.log.setLevel(logging.INFO)
        try:
            await self.start_server()
            alice = await self.registered(ALICE)
            bob = await self.registered(BOB)
            await alice.deposit(alice.seal_to(bob.certificate,
                                              b'{"kind":"text","sentAt":1}'))
            await alice.report(BOB, "spam", [])
        finally:
            bs.log.removeHandler(handler)

        blob = "\n".join(records)
        # The dev console SMS provider is the only permitted place for a code,
        # and it is the only line allowed to contain it.
        non_sms = "\n".join(r for r in records if "[dev-sms]" not in r)
        self.assertNotIn(FIXED_CODE, non_sms)
        # Full phone numbers must never appear.
        self.assertNotIn(ALICE, blob)
        self.assertNotIn(BOB, blob)
        self.assertIn(bs.mask_phone(ALICE), blob)



class BindHostsTests(unittest.TestCase):
    """Which addresses the server listens on.

    The default is IPv4 only, which silently makes the server unreachable from
    an IPv6-only mobile network — a failure that looks like a firewall and
    costs an afternoon. "*" (or an empty value) listens on both.
    """

    def test_wildcard_means_both_families(self):
        for value in ("", "   ", "*", "all"):
            self.assertEqual(bs.bind_hosts(value), ["0.0.0.0", "::"], value)

    def test_an_explicit_address_is_left_alone(self):
        self.assertEqual(bs.bind_hosts("0.0.0.0"), "0.0.0.0")
        self.assertEqual(bs.bind_hosts("::"), "::")
        self.assertEqual(bs.bind_hosts("127.0.0.1"), "127.0.0.1")
        self.assertEqual(bs.bind_hosts(" 10.0.0.5 "), "10.0.0.5")


class TwilioChannelTests(unittest.TestCase):
    """SMS or WhatsApp, chosen by the prefix on TWILIO_FROM.

    Both go through the same Messages endpoint. WhatsApp needs the prefix on
    *both* addresses, and forgetting it on "To" is a silent misdelivery.
    """

    def test_plain_from_number_is_sms(self):
        p = bs.TwilioSMSProvider("AC1", "tok", "+15551234567")
        self.assertEqual(p.channel, "sms")
        self.assertEqual(p._to_field("+351911111111"), "+351911111111")

    def test_alphanumeric_sender_is_sms(self):
        p = bs.TwilioSMSProvider("AC1", "tok", "hoppin")
        self.assertEqual(p.channel, "sms")
        self.assertEqual(p._to_field("+351911111111"), "+351911111111")

    def test_whatsapp_prefix_applies_to_both_addresses(self):
        p = bs.TwilioSMSProvider("AC1", "tok", "whatsapp:+14155238886")
        self.assertEqual(p.channel, "whatsapp")
        self.assertEqual(p._to_field("+351911111111"), "whatsapp:+351911111111")


TOKEN_A = "a1b2c3d4" * 8
TOKEN_B = "0f1e2d3c" * 8


class FakePush:
    """Records what would have gone to Apple, and can pretend a token died."""

    enabled = True
    name = "fake"

    def __init__(self, drop=False):
        self.sent = []
        self.drop = drop
        self.closed = False

    async def send(self, token, sandbox=False):
        self.sent.append((token, sandbox))
        return bsapns.PushResult(not self.drop, drop=self.drop, reason="Unregistered"
                                 if self.drop else "")

    async def close(self):
        self.closed = True


class PushTokenTests(ServerTestCase):
    """Registering a device for push, and forgetting it again.

    The token identifies one install of the app on one device, so the rules
    around its lifetime matter as much as the delivery it enables.
    """

    async def start_server(self, push=None, **kwargs):
        server = bs.BootstrapServer(
            identity_key=self.identity,
            sms=bs.ConsoleSMSProvider(),
            state_path=self.state_path,
            reports_path=self.reports_path,
            dev_fixed_code=FIXED_CODE,
            push=push if push is not None else FakePush(),
            banlist_path=self.banlist_path,
            report_alert_to="",
        )
        server.dev_fixed_code = FIXED_CODE
        await server.start(plaintext_port=0, allow_plaintext=True, **kwargs)
        self.server = server
        return server

    async def _pair(self):
        return await self.registered(ALICE), await self.registered(BOB)

    @async_test
    async def test_a_token_is_stored_and_replaced(self):
        await self.start_server()
        alice = await self.registered(ALICE)

        await alice.set_push_token(TOKEN_A)
        self.assertEqual(self.server.push_tokens[ALICE]["token"], TOKEN_A)

        # A reinstall hands out a new token; the old one must not linger, or
        # the relay keeps waking a device that no longer has the app.
        await alice.set_push_token(TOKEN_B)
        self.assertEqual(self.server.push_tokens[ALICE]["token"], TOKEN_B)

    @async_test
    async def test_an_empty_token_clears_it(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        await alice.set_push_token(TOKEN_A)
        await alice.set_push_token("")
        self.assertNotIn(ALICE, self.server.push_tokens)

    @async_test
    async def test_a_malformed_token_is_refused(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        with self.assertRaises(ServerError) as ctx:
            await alice.set_push_token("not-hex-at-all")
        self.assertEqual(ctx.exception.code, "bad_request")
        self.assertNotIn(ALICE, self.server.push_tokens)

    @async_test
    async def test_deleting_the_account_forgets_the_token(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        await alice.set_push_token(TOKEN_A)
        await alice.delete_account()
        self.assertNotIn(ALICE, self.server.push_tokens)

    @async_test
    async def test_the_token_follows_a_number_change(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        await alice.set_push_token(TOKEN_A)

        await alice.request(bs.T_CHANGE_NUMBER_START, key=CAROL)
        await alice.request(
            bs.T_CHANGE_NUMBER_CONFIRM,
            value=json.dumps({"newPhone": CAROL, "code": FIXED_CODE},
                             separators=(",", ":")))

        # Same device, new number: it must keep getting woken.
        self.assertNotIn(ALICE, self.server.push_tokens)
        self.assertEqual(self.server.push_tokens[CAROL]["token"], TOKEN_A)

    @async_test
    async def test_a_deposit_wakes_a_sleeping_device(self):
        push = FakePush()
        await self.start_server(push=push)
        alice, bob = await self._pair()
        await bob.set_push_token(TOKEN_A, sandbox=True)

        env = alice.seal_to(bob.certificate, b'{"kind":"text","sentAt":1}')
        await alice.deposit(env)
        await asyncio.sleep(0.05)          # the push is fired, not awaited

        self.assertEqual(push.sent, [(TOKEN_A, True)])

    @async_test
    async def test_no_push_for_a_device_that_is_already_listening(self):
        push = FakePush()
        await self.start_server(push=push)
        alice, bob = await self._pair()
        await bob.set_push_token(TOKEN_A)

        fetch_task = asyncio.ensure_future(bob.fetch(wait=20))
        await asyncio.sleep(0.25)          # let the long poll reach the hold

        env = alice.seal_to(bob.certificate, b'{"kind":"text","sentAt":1}')
        await alice.deposit(env)
        await asyncio.wait_for(fetch_task, 10)
        await asyncio.sleep(0.05)

        # It is awake and holding the line; waking it again is pure waste.
        self.assertEqual(push.sent, [])

    @async_test
    async def test_a_dead_token_is_dropped(self):
        push = FakePush(drop=True)
        await self.start_server(push=push)
        alice, bob = await self._pair()
        await bob.set_push_token(TOKEN_A)

        env = alice.seal_to(bob.certificate, b'{"kind":"text","sentAt":1}')
        await alice.deposit(env)
        await asyncio.sleep(0.05)

        # Apple said that install is gone, so the relay stops trying.
        self.assertNotIn(BOB, self.server.push_tokens)

    @async_test
    async def test_tokens_survive_a_restart(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        await alice.set_push_token(TOKEN_A)
        self.server.save_state()
        await self.stop_server()

        await self.start_server()
        self.assertEqual(self.server.push_tokens[ALICE]["token"], TOKEN_A)

    @async_test
    async def test_the_token_is_never_logged(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        with self.assertLogs("hoppin-bootstrap", level="INFO") as captured:
            await alice.set_push_token(TOKEN_A)
        self.assertNotIn(TOKEN_A, "\n".join(captured.output))


class APNsTests(unittest.TestCase):
    """The parts of the APNs client that do not need Apple."""

    def test_push_is_disabled_without_credentials(self):
        sender = bsapns.build_push_sender()
        self.assertFalse(sender.enabled)

    def test_token_shape(self):
        self.assertTrue(bsapns.is_valid_token("ab" * 32))
        self.assertFalse(bsapns.is_valid_token("zz" * 32))   # not hex
        self.assertFalse(bsapns.is_valid_token("abc"))       # too short
        self.assertFalse(bsapns.is_valid_token("a" * 33))    # odd length

    def test_the_payload_carries_nothing_about_the_message(self):
        flat = json.dumps(bsapns.APNsPushSender.payload())
        for leak in ("+351", "sender", "text", "envelope", "recipient"):
            self.assertNotIn(leak, flat)
        # The extension needs this, or it never gets to rewrite the placeholder.
        self.assertEqual(bsapns.APNsPushSender.payload()["aps"]["mutable-content"], 1)
        # And this is what lets the woken app go and fetch the envelope.
        self.assertEqual(bsapns.APNsPushSender.payload()["aps"]["content-available"], 1)

    def test_a_gone_device_is_distinguished_from_a_bad_configuration(self):
        self.assertTrue(bsapns.classify(410, '{"reason":"Unregistered"}').drop)
        self.assertTrue(bsapns.classify(400, '{"reason":"BadDeviceToken"}').drop)
        # Our mistake, not the device's: dropping here would silently kill push.
        self.assertFalse(bsapns.classify(403, '{"reason":"InvalidProviderToken"}').drop)
        self.assertFalse(bsapns.classify(429, '{"reason":"TooManyRequests"}').drop)
        self.assertTrue(bsapns.classify(200).ok)

    def test_the_jwt_is_signed_and_cached(self):
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())
        sender = bsapns.APNsPushSender(pem, "KEYID12345", "TEAMID6789",
                                       "com.example.hoppin")

        token = sender.bearer_token(now=1000.0)
        header, claims, signature = token.split(".")

        def unpad(part):
            return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))

        self.assertEqual(json.loads(unpad(header)),
                         {"alg": "ES256", "kid": "KEYID12345"})
        self.assertEqual(json.loads(unpad(claims)),
                         {"iss": "TEAMID6789", "iat": 1000})
        # JWS wants r||s, not DER.
        self.assertEqual(len(unpad(signature)), 64)

        # Apple throttles minting, so the same token comes back...
        self.assertEqual(sender.bearer_token(now=1000.0 + 600), token)
        # ...until it is old enough to be refused.
        self.assertNotEqual(sender.bearer_token(now=1000.0 + 3600), token)


# ---------------------------------------------------------------------------
# Moderation: suspended numbers, report alerts, the admin tool
# ---------------------------------------------------------------------------

OPERATOR = "+351935550199"


class FakeSMS(bs.SMSProvider):
    """Records codes and texts instead of sending them; can pretend to fail."""

    name = "fake"

    def __init__(self, fail=False):
        self.codes = []
        self.texts = []
        self.fail = fail

    def send(self, phone, code):
        self.codes.append((phone, code))

    def send_text(self, phone, body):
        if self.fail:
            raise bs.ProtocolError("internal", "sms send failed")
        self.texts.append((phone, body))


class FakeClock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def write_file(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


class BanListTests(unittest.TestCase):
    """The ban file: its format, and when the relay re-reads it."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hoppin-ban-")
        self.path = os.path.join(self.tmp, "banned.txt")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_format(self):
        text = ("# suspended numbers\n"
                "\n"
                "%s\n"
                "  %s   spam, 2026-09-28  \n"
                "not-a-number whatever\n"
                "# %s commented out\n" % (ALICE, BOB, CAROL))
        self.assertEqual(bs.parse_banlist(text),
                         {ALICE: "", BOB: "spam, 2026-09-28"})

    def test_a_missing_file_bans_nobody(self):
        bans = bs.BanList(self.path)
        bans.refresh(force=True)
        self.assertEqual(len(bans), 0)
        self.assertNotIn(ALICE, bans)

    def test_reloads_on_change_but_stats_at_most_every_interval(self):
        clock = FakeClock()
        bans = bs.BanList(self.path, check_interval=5, clock=clock)
        write_file(self.path, ALICE + "\n")
        bans.refresh(force=True)
        self.assertIn(ALICE, bans)

        write_file(self.path, BOB + "\n")
        clock.advance(1)
        with mock.patch.object(bs.os, "stat", wraps=os.stat) as stat_call:
            self.assertFalse(bans.refresh())      # too soon: not even a stat
            self.assertEqual(stat_call.call_count, 0)
        self.assertIn(ALICE, bans)

        clock.advance(5)
        self.assertTrue(bans.refresh())
        self.assertIn(BOB, bans)
        self.assertNotIn(ALICE, bans)

    def test_an_unchanged_file_is_not_read_again(self):
        clock = FakeClock()
        bans = bs.BanList(self.path, check_interval=5, clock=clock)
        write_file(self.path, ALICE + "\n")
        with mock.patch.object(bs, "parse_banlist", wraps=bs.parse_banlist) as parse:
            bans.refresh(force=True)
            for _ in range(5):
                clock.advance(10)
                bans.refresh()
            self.assertEqual(parse.call_count, 1)
        self.assertIn(ALICE, bans)

    def test_deleting_the_file_lifts_every_ban(self):
        bans = bs.BanList(self.path, check_interval=0)
        write_file(self.path, ALICE + "\n")
        bans.refresh()
        os.unlink(self.path)
        bans.refresh()
        self.assertNotIn(ALICE, bans)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root reads anything")
    def test_an_unreadable_file_keeps_the_last_list(self):
        bans = bs.BanList(self.path, check_interval=0)
        write_file(self.path, ALICE + "\n")
        bans.refresh()
        os.chmod(self.path, 0)
        try:
            bans.refresh()
            # Failing open would quietly unban everyone.
            self.assertIn(ALICE, bans)
        finally:
            os.chmod(self.path, 0o600)


class SuspensionTests(ServerTestCase):
    """A suspended number can't use the relay, and looks unregistered to others."""

    async def start_server(self, push=None, **kwargs):
        server = bs.BootstrapServer(
            identity_key=self.identity,
            sms=bs.ConsoleSMSProvider(),
            state_path=self.state_path,
            reports_path=self.reports_path,
            dev_fixed_code=FIXED_CODE,
            push=push if push is not None else FakePush(),
            banlist_path=self.banlist_path,
            report_alert_to="",
        )
        server.dev_fixed_code = FIXED_CODE
        await server.start(plaintext_port=0, allow_plaintext=True, **kwargs)
        # Every request re-checks the file, so a test sees its edit at once.
        server.bans.check_interval = 0
        self.server = server
        return server

    def ban(self, *phones):
        write_file(self.banlist_path, "".join(p + " test\n" for p in phones))

    async def assert_suspended(self, coro):
        with self.assertRaises(ServerError) as ctx:
            await coro
        self.assertEqual(ctx.exception.code, "suspended")

    @async_test
    async def test_cannot_start_verification(self):
        await self.start_server()
        self.ban(ALICE)
        await self.assert_suspended(self.client(ALICE).verify_start())
        self.assertNotIn(ALICE, self.server.pending)

    @async_test
    async def test_cannot_confirm_a_code_sent_before_the_ban(self):
        await self.start_server()
        alice = self.client(ALICE)
        await alice.verify_start()
        self.ban(ALICE)
        await self.assert_suspended(alice.verify_confirm(FIXED_CODE))
        self.assertNotIn(ALICE, self.server.certs)

    @async_test
    async def test_cannot_renew_deposit_or_change_number(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        bob = await self.registered(BOB)
        env = alice.seal_to(bob.certificate, b'{"kind":"text","sentAt":1}')
        self.ban(ALICE)

        await self.assert_suspended(alice.cert_renew())
        await self.assert_suspended(alice.deposit(env))
        await self.assert_suspended(alice.change_number_start(CAROL))
        await self.assert_suspended(alice.ping())
        await self.assert_suspended(alice.fetch(wait=0))
        await self.assert_suspended(alice.cert_lookup(BOB))
        await self.assert_suspended(alice.report(BOB, "spam", []))
        await self.assert_suspended(alice.set_push_token(TOKEN_A))

        self.assertNotIn(BOB, self.server.queue)
        self.assertNotIn(ALICE, self.server.pending)

    @async_test
    async def test_can_still_delete_the_account(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        self.ban(ALICE)
        await alice.delete_account()
        self.assertNotIn(ALICE, self.server.certs)

    @async_test
    async def test_cannot_change_to_a_suspended_number(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        self.ban(CAROL)
        await self.assert_suspended(alice.change_number_start(CAROL))

        # A ban landing between start and confirm is caught too.
        self.ban()
        await alice.change_number_start(CAROL)
        self.ban(CAROL)
        await self.assert_suspended(alice.change_number_confirm(CAROL, FIXED_CODE))
        self.assertIn(ALICE, self.server.certs)
        self.assertNotIn(CAROL, self.server.certs)

    @async_test
    async def test_lookup_hides_a_suspended_number_until_unbanned(self):
        await self.start_server()
        bob = await self.registered(BOB)
        alice = await self.registered(ALICE)

        self.ban(BOB)
        self.assertIsNone(await alice.cert_lookup(BOB))

        self.ban()
        found = await alice.cert_lookup(BOB)
        self.assertEqual(found["serial"], bob.certificate["serial"])

    @async_test
    async def test_deposit_to_a_suspended_number_fails_as_unregistered(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        bob = await self.registered(BOB)
        first = alice.seal_to(bob.certificate, b'{"kind":"text","sentAt":1}')
        second = alice.seal_to(bob.certificate, b'{"kind":"text","sentAt":2}')
        await alice.deposit(first)

        self.ban(BOB)
        with self.assertRaises(ServerError) as ctx:
            await alice.deposit(second)
        self.assertEqual(ctx.exception.code, "recipient_not_registered")

        # Nothing is deleted: the certificate and the mail already queued stay.
        self.assertIn(BOB, self.server.certs)
        self.assertEqual([it["env"]["id"] for it in self.server.queue[BOB]],
                         [first["id"]])

        # ...so lifting the ban restores the account as it was.
        self.ban()
        await alice.deposit(second)
        self.assertEqual(len(await bob.fetch(wait=0)), 2)

    @async_test
    async def test_the_push_token_is_dropped_once_the_ban_is_noticed(self):
        push = FakePush()
        await self.start_server(push=push)
        alice = await self.registered(ALICE)
        bob = await self.registered(BOB)
        await bob.set_push_token(TOKEN_A)
        await alice.set_push_token(TOKEN_B)

        self.ban(BOB)
        # What housekeeping does every few seconds, with no request needed.
        self.server.refresh_bans()
        self.assertNotIn(BOB, self.server.push_tokens)
        self.assertEqual(self.server.push_tokens[ALICE]["token"], TOKEN_B)
        self.assertIn(BOB, self.server.certs)

        with self.assertRaises(ServerError):
            await alice.deposit(alice.seal_to(bob.certificate,
                                              b'{"kind":"text","sentAt":1}'))
        await asyncio.sleep(0.05)
        self.assertEqual(push.sent, [])

    @async_test
    async def test_a_ban_already_in_the_file_applies_at_startup(self):
        await self.start_server()
        bob = await self.registered(BOB)
        await bob.set_push_token(TOKEN_A)
        self.server.save_state()
        await self.stop_server()

        self.ban(BOB)
        await self.start_server()
        self.assertNotIn(BOB, self.server.push_tokens)
        bob.port = self.server.plaintext_port
        await self.assert_suspended(bob.ping())

    @async_test
    async def test_edits_apply_without_a_restart(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        await alice.ping()

        hoppin_admin.ban(self.banlist_path, ALICE, "spam")
        await self.assert_suspended(alice.ping())

        hoppin_admin.unban(self.banlist_path, ALICE)
        reply = await alice.ping()
        self.assertEqual(reply["type"], bs.T_PONG)

    @async_test
    async def test_refusals_log_only_masked_numbers(self):
        await self.start_server()
        alice = await self.registered(ALICE)
        self.ban(ALICE)
        with self.assertLogs("hoppin-bootstrap", level="INFO") as captured:
            await self.assert_suspended(alice.ping())
            await self.assert_suspended(self.client(ALICE).verify_start())
        blob = "\n".join(captured.output)
        self.assertNotIn(ALICE, blob)
        self.assertIn(bs.mask_phone(ALICE), blob)


class ReportAlertTests(ServerTestCase):
    """The operator is texted when reports arrive, and told nothing else."""

    def alerter(self, sms, to=OPERATOR):
        self.clock = FakeClock()
        return bs.ReportAlerter(sms, to, window=15 * 60, clock=self.clock)

    async def drain(self, alerter):
        if alerter.tasks:
            await asyncio.wait(set(alerter.tasks), timeout=5)

    async def start_server(self, sms, **kwargs):
        server = bs.BootstrapServer(
            identity_key=self.identity,
            sms=sms,
            state_path=self.state_path,
            reports_path=self.reports_path,
            dev_fixed_code=FIXED_CODE,
            push=FakePush(),
            banlist_path=self.banlist_path,
            report_alert_to=OPERATOR,
        )
        server.dev_fixed_code = FIXED_CODE
        await server.start(plaintext_port=0, allow_plaintext=True, **kwargs)
        self.clock = FakeClock()
        server.alerts.clock = self.clock
        self.server = server
        return server

    @async_test
    async def test_the_first_report_alerts_at_once(self):
        sms = FakeSMS()
        alerts = self.alerter(sms)
        alerts.report_filed()
        await self.drain(alerts)
        self.assertEqual(sms.texts,
                         [(OPERATOR, "hoppin: 1 new report. Review it on the relay.")])

    @async_test
    async def test_reports_inside_the_window_are_coalesced(self):
        sms = FakeSMS()
        alerts = self.alerter(sms)
        alerts.report_filed()
        await self.drain(alerts)

        self.clock.advance(60)
        alerts.report_filed()
        self.clock.advance(60)
        alerts.report_filed()
        alerts.report_filed()
        alerts.tick()
        await self.drain(alerts)
        self.assertEqual(len(sms.texts), 1, "only one alert per window")

        # The window closes: one text for everything held back, even though
        # no further report arrived to trigger it.
        self.clock.advance(15 * 60 - 120)
        alerts.tick()
        await self.drain(alerts)
        self.assertEqual(len(sms.texts), 2)
        self.assertEqual(sms.texts[1][1],
                         "hoppin: 3 new reports. Review them on the relay.")

        # Nothing pending: the next tick is silent.
        self.clock.advance(15 * 60)
        alerts.tick()
        await self.drain(alerts)
        self.assertEqual(len(sms.texts), 2)

    @async_test
    async def test_alerts_are_off_without_a_recipient(self):
        sms = FakeSMS()
        with self.assertLogs("hoppin-bootstrap", level="INFO") as captured:
            alerts = self.alerter(sms, to="")
        self.assertIn("report alerts are off", "\n".join(captured.output))
        alerts.report_filed()
        self.assertEqual(alerts.tasks, set())
        self.assertEqual(sms.texts, [])

    @async_test
    async def test_a_report_texts_the_operator_without_any_detail(self):
        sms = FakeSMS()
        await self.start_server(sms)
        alice = await self.registered(ALICE)
        await alice.report(BOB, "he keeps texting 912345678 at 3am",
                           [{"id": "m1", "timestamp": 1, "text": "call +447700900123"}])
        await self.drain(self.server.alerts)

        self.assertEqual(len(sms.texts), 1)
        to, body = sms.texts[0]
        self.assertEqual(to, OPERATOR)
        for phone in (ALICE, BOB, CAROL, OPERATOR):
            digits = phone.lstrip("+")
            self.assertNotIn(digits, body)
            self.assertNotIn(digits[-4:], body)
        self.assertIsNone(re.search(r"\d{2,}", body), body)
        self.assertNotIn("+", body)
        for leak in ("texting", "3am", "call", "spam"):
            self.assertNotIn(leak, body)

    @async_test
    async def test_a_failed_alert_never_fails_the_report_and_is_retried(self):
        sms = FakeSMS(fail=True)
        await self.start_server(sms)
        alice = await self.registered(ALICE)
        await alice.report(BOB, "spam", [])       # answered ok, not internal
        self.assertTrue(os.path.exists(self.reports_path))
        await self.drain(self.server.alerts)
        self.assertEqual(sms.texts, [])
        self.assertEqual(self.server.alerts.pending, 1)

        sms.fail = False
        self.clock.advance(15 * 60)
        self.server.alerts.tick()
        await self.drain(self.server.alerts)
        self.assertEqual(sms.texts[0][1], bs.report_alert_text(1))

    @async_test
    async def test_held_back_reports_are_sent_on_shutdown(self):
        sms = FakeSMS()
        await self.start_server(sms)
        alice = await self.registered(ALICE)
        await alice.report(BOB, "spam", [])
        await alice.report(CAROL, "spam", [])
        await self.drain(self.server.alerts)
        self.assertEqual(len(sms.texts), 1)

        await self.stop_server()
        self.assertEqual([body for _, body in sms.texts],
                         [bs.report_alert_text(1), bs.report_alert_text(1)])


class AdminToolTests(unittest.TestCase):
    """hoppin_admin.py: the operator's side of reports and bans."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hoppin-admin-")
        self.banlist = os.path.join(self.tmp, "banned.txt")
        self.reports = os.path.join(self.tmp, "reports.jsonl")
        # Never consult a real systemd unit from a test.
        self._saved_env = hoppin_admin._service_env
        hoppin_admin._service_env = {}

    def tearDown(self):
        hoppin_admin._service_env = self._saved_env
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = hoppin_admin.main(["--banlist", self.banlist,
                                      "--reports", self.reports] + list(argv))
        return code, out.getvalue()

    def test_ban_unban_round_trip_preserves_the_file(self):
        original = "# suspended numbers\n%s  2026-09-01 old case\n" % CAROL
        write_file(self.banlist, original)
        os.chmod(self.banlist, 0o640)
        before = os.stat(self.banlist)

        self.assertTrue(hoppin_admin.ban(self.banlist, BOB, "spam  links",
                                         today="2026-09-28"))
        after = os.stat(self.banlist)
        self.assertEqual(stat.S_IMODE(after.st_mode), 0o640)
        self.assertEqual((after.st_uid, after.st_gid), (before.st_uid, before.st_gid))
        self.assertNotEqual(after.st_ino, before.st_ino, "expected an atomic rename")
        with open(self.banlist, encoding="utf-8") as fh:
            self.assertEqual(bs.parse_banlist(fh.read()),
                             {CAROL: "2026-09-01 old case", BOB: "2026-09-28 spam links"})

        self.assertFalse(hoppin_admin.ban(self.banlist, BOB, "again"))

        self.assertTrue(hoppin_admin.unban(self.banlist, BOB))
        self.assertFalse(hoppin_admin.unban(self.banlist, BOB))
        with open(self.banlist, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), original)
        self.assertEqual(stat.S_IMODE(os.stat(self.banlist).st_mode), 0o640)
        self.assertEqual([f for f in os.listdir(self.tmp) if f.endswith(".tmp")], [])

    def test_a_new_ban_file_is_group_readable_only(self):
        hoppin_admin.ban(self.banlist, BOB, "")
        self.assertEqual(stat.S_IMODE(os.stat(self.banlist).st_mode), 0o640)

    def test_the_relay_sees_what_the_tool_writes(self):
        bans = bs.BanList(self.banlist, check_interval=0)
        bans.refresh()
        code, _ = self.run_cli("ban", BOB, "spam")
        self.assertEqual(code, 0)
        self.assertTrue(bans.refresh())
        self.assertIn(BOB, bans)

        code, out = self.run_cli("banned")
        self.assertIn(BOB, out)

        self.run_cli("unban", BOB)
        self.assertTrue(bans.refresh())
        self.assertNotIn(BOB, bans)

    def test_numbers_must_be_e164(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                self.run_cli("ban", "912345678")
        self.assertEqual(ctx.exception.code, 2)
        self.assertFalse(os.path.exists(self.banlist))

    def test_reports_newest_first_with_since(self):
        now = int(time.time())
        lines = [
            {"at": now - 3 * 86400, "reporter": ALICE, "reportedPhone": CAROL,
             "reason": "old", "evidence": []},
            {"at": now - 60, "reporter": ALICE, "reportedPhone": BOB,
             "reason": "spam\x1b[2J", "evidence": [{"id": "1", "timestamp": now,
                                                    "text": "hi"}] * 2},
            {"at": now - 3600, "reporter": CAROL, "reportedPhone": BOB,
             "reason": "abuse", "evidence": []},
        ]
        write_file(self.reports, "".join(json.dumps(l) + "\n" for l in lines)
                   + "not json\n")
        write_file(self.banlist, BOB + "\n")

        with contextlib.redirect_stderr(io.StringIO()):
            code, out = self.run_cli("reports")
        self.assertEqual(code, 0)
        self.assertLess(out.index("spam"), out.index("abuse"))
        self.assertLess(out.index("abuse"), out.index("old"))
        self.assertIn("evidence  2 message(s)", out)
        self.assertIn("(suspended)", out)
        # Reporter-written text can't drive the operator's terminal.
        self.assertNotIn("\x1b", out)

        with contextlib.redirect_stderr(io.StringIO()):
            code, out = self.run_cli("reports", "--since", "24h")
        self.assertIn("2 report(s)", out)
        self.assertNotIn("old", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
