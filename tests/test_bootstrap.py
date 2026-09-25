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
import datetime
import json
import os
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

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for path in (_ROOT, _HERE):
    if path not in sys.path:
        sys.path.insert(0, path)

# The server reads HOPPIN_ENV at import time.
os.environ.setdefault("HOPPIN_ENV", "dev")

import bootstrap as bs  # noqa: E402
from client import (  # noqa: E402
    hoppinClient,
    ServerError,
    open_envelope,
    raw_public,
    seal_envelope,
)

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
        self.assertNotIn(ALICE, self.server.last_seen)

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
        self.assertNotIn(ALICE, self.server.last_seen)
        self.assertIn(serial, self.server.revoked)

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
