#!/usr/bin/env python3
"""
Minimal async hoppin client.

Used by server/test_bootstrap.py, and usable by hand for smoke testing a
deployment. It implements the client half of §1-§4 of the design contract:
canonical encoding, certificate handling, wire signing, and envelope sealing.

Manual smoke test (server running in dev with HOPPIN_ALLOW_PLAINTEXT=1):

    ./venv/bin/python -m server.client --host 127.0.0.1 --port 4001 \
        --phone +351912345678 --code 123456
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import ssl
import struct
import sys
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import bootstrap as bs  # noqa: E402


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def raw_public(key) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def raw_private(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


# ---------------------------------------------------------------------------
# §4 Envelope sealing / opening
# ---------------------------------------------------------------------------

def derive_envelope_key(dh1: bytes, dh2: bytes, sender_signing_b64: str,
                        recipient_signing_b64: str, header: List[str]) -> bytes:
    info = bs.canonical(["hoppin-seal-v2", sender_signing_b64,
                         recipient_signing_b64] + header)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"hoppin-E2E-v2",
        info=info,
    ).derive(dh1 + dh2)


def seal_envelope(payload: bytes,
                  envelope_id: str,
                  sender_phone: str,
                  recipient_phone: str,
                  timestamp: int,
                  sender_signing: Ed25519PrivateKey,
                  sender_agreement: X25519PrivateKey,
                  recipient_signing_b64: str,
                  recipient_agreement_b64: str,
                  sender_certificate_json: str,
                  ephemeral: Optional[X25519PrivateKey] = None,
                  nonce: Optional[bytes] = None) -> Tuple[Dict[str, Any], bytes]:
    """
    Seal a payload per §4. Returns (envelope dict, derived AES key).

    `ephemeral` and `nonce` may be fixed to produce deterministic fixtures.
    """
    if ephemeral is None:
        ephemeral = X25519PrivateKey.generate()
    if nonce is None:
        nonce = os.urandom(12)

    recipient_agreement_pub = X25519PublicKey.from_public_bytes(
        base64.b64decode(recipient_agreement_b64))

    header = [
        "hoppin-env-v2",
        envelope_id,
        sender_phone,
        recipient_phone,
        bs.cint(timestamp),
        bs.b64e(raw_public(sender_agreement)),
        recipient_agreement_b64,
        bs.b64e(raw_public(ephemeral)),
    ]

    dh1 = ephemeral.exchange(recipient_agreement_pub)
    dh2 = sender_agreement.exchange(recipient_agreement_pub)
    key = derive_envelope_key(dh1, dh2, bs.b64e(raw_public(sender_signing)),
                              recipient_signing_b64, header)

    combined = nonce + AESGCM(key).encrypt(nonce, payload, bs.canonical(header))
    ciphertext = bs.b64e(combined)

    signature = bs.b64e(sender_signing.sign(bs.canonical(header + [ciphertext])))

    env = {
        "id": envelope_id,
        "senderPhone": sender_phone,
        "recipientPhone": recipient_phone,
        "timestamp": int(timestamp),
        "senderAgreementKey": header[5],
        "recipientAgreementKey": recipient_agreement_b64,
        "ephemeralKey": header[7],
        "ciphertext": ciphertext,
        "senderCertificate": sender_certificate_json,
        "signature": signature,
    }
    return env, key


def open_envelope(env: Dict[str, Any],
                  recipient_agreement: X25519PrivateKey,
                  sender_signing_b64: str,
                  recipient_signing_b64: str) -> bytes:
    """Inverse of seal_envelope. Verifies the signature, then decrypts."""
    header = bs.envelope_header(env)
    if not bs.verify_ed25519(sender_signing_b64,
                             bs.canonical(bs.envelope_signed_fields(env)),
                             env["signature"]):
        raise ValueError("envelope signature does not verify")

    eph_pub = X25519PublicKey.from_public_bytes(base64.b64decode(env["ephemeralKey"]))
    sender_pub = X25519PublicKey.from_public_bytes(
        base64.b64decode(env["senderAgreementKey"]))

    dh1 = recipient_agreement.exchange(eph_pub)
    dh2 = recipient_agreement.exchange(sender_pub)
    key = derive_envelope_key(dh1, dh2, sender_signing_b64,
                              recipient_signing_b64, header)

    combined = base64.b64decode(env["ciphertext"])
    nonce, body = combined[:12], combined[12:]
    return AESGCM(key).decrypt(nonce, body, bs.canonical(header))


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class ServerError(Exception):
    def __init__(self, code: str, message: str = ""):
        super().__init__("%s: %s" % (code, message))
        self.code = code
        self.message = message


class hoppinClient:
    def __init__(self, phone: str, host: str = "127.0.0.1", port: int = 4001,
                 use_tls: bool = False, cafile: Optional[str] = None,
                 server_key_b64: Optional[str] = None,
                 signing_seed: Optional[bytes] = None,
                 agreement_seed: Optional[bytes] = None,
                 server_hostname: str = "localhost"):
        self.phone = phone
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.cafile = cafile
        self.server_key_b64 = server_key_b64
        self.server_hostname = server_hostname

        self.signing = (Ed25519PrivateKey.from_private_bytes(signing_seed)
                        if signing_seed else Ed25519PrivateKey.generate())
        self.agreement = (X25519PrivateKey.from_private_bytes(agreement_seed)
                          if agreement_seed else X25519PrivateKey.generate())
        self.certificate: Optional[Dict[str, Any]] = None

    # -- keys ------------------------------------------------------------- #

    @property
    def signing_key_b64(self) -> str:
        return bs.b64e(raw_public(self.signing))

    @property
    def agreement_key_b64(self) -> str:
        return bs.b64e(raw_public(self.agreement))

    @property
    def certificate_json(self) -> str:
        if self.certificate is None:
            return ""
        return bs.encode_certificate(self.certificate)

    # -- transport --------------------------------------------------------- #

    def _ssl_context(self) -> Optional[ssl.SSLContext]:
        if not self.use_tls:
            return None
        ctx = ssl.create_default_context(cafile=self.cafile)
        if self.cafile is None:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def build(self, msg_type: int, *, key: Optional[str] = None,
              value: Optional[str] = None,
              recipient_phone: Optional[str] = None,
              envelope: Optional[Dict[str, Any]] = None,
              with_certificate: bool = True,
              signing: Optional[Ed25519PrivateKey] = None,
              timestamp: Optional[int] = None,
              tx_id: Optional[str] = None,
              sender_phone: Optional[str] = None,
              sender_port: int = 0,
              certificate_json: Optional[str] = None) -> Dict[str, Any]:
        """Build and sign a wire message. Overridable for negative tests."""
        msg: Dict[str, Any] = {
            "v": bs.WIRE_VERSION,
            "type": msg_type,
            "txID": tx_id or str(uuid.uuid4()),
            "senderPhone": sender_phone if sender_phone is not None else self.phone,
            "senderPort": sender_port,
            "timestamp": int(timestamp if timestamp is not None else time.time()),
        }
        if recipient_phone is not None:
            msg["recipientPhone"] = recipient_phone
        if key is not None:
            msg["key"] = key
        if value is not None:
            msg["value"] = value
        if envelope is not None:
            msg["envelope"] = envelope
        if certificate_json is not None:
            msg["certificate"] = certificate_json
        elif with_certificate and self.certificate is not None:
            msg["certificate"] = self.certificate_json

        signer = signing or self.signing
        msg["signature"] = bs.b64e(signer.sign(bs.canonical(bs.wire_signed_fields(msg))))
        return msg

    async def send(self, msg: Dict[str, Any], timeout: float = 30.0) -> Dict[str, Any]:
        """Send one frame, read one reply, verify the server signature."""
        reader, writer = await asyncio.open_connection(
            self.host, self.port, ssl=self._ssl_context(),
            server_hostname=self.server_hostname if self.use_tls else None)
        try:
            writer.write(bs.make_frame(msg))
            await writer.drain()
            header = await asyncio.wait_for(reader.readexactly(4), timeout)
            (length,) = struct.unpack(">I", header)
            body = await asyncio.wait_for(reader.readexactly(length), timeout)
        finally:
            writer.close()

        reply = json.loads(body.decode("utf-8"))

        if self.server_key_b64:
            if not bs.verify_ed25519(self.server_key_b64,
                                     bs.canonical(bs.wire_signed_fields(reply)),
                                     reply.get("signature", "")):
                raise ServerError("bad_server_signature", "server reply not authentic")

        if reply.get("type") == bs.T_ERROR:
            raise ServerError(reply.get("key", "error"), reply.get("value", ""))
        return reply

    async def request(self, msg_type: int, **kwargs: Any) -> Dict[str, Any]:
        timeout = kwargs.pop("timeout", 30.0)
        return await self.send(self.build(msg_type, **kwargs), timeout=timeout)

    # -- protocol operations ------------------------------------------------ #

    async def ping(self) -> Dict[str, Any]:
        return await self.request(bs.T_PING)

    async def verify_start(self, phone: Optional[str] = None) -> int:
        reply = await self.request(bs.T_VERIFY_START, key=phone or self.phone,
                                   with_certificate=False)
        return int(reply.get("value") or 0)

    async def verify_confirm(self, code: str,
                             phone: Optional[str] = None) -> Dict[str, Any]:
        body = json.dumps({
            "code": code,
            "signingKey": self.signing_key_b64,
            "agreementKey": self.agreement_key_b64,
        }, separators=(",", ":"))
        reply = await self.request(bs.T_VERIFY_CONFIRM, key=phone or self.phone,
                                   value=body, with_certificate=False)
        self.certificate = json.loads(reply["value"])
        return self.certificate

    async def cert_renew(self, agreement_key: Optional[str] = None) -> Dict[str, Any]:
        body = json.dumps({"agreementKey": agreement_key or self.agreement_key_b64},
                          separators=(",", ":"))
        reply = await self.request(bs.T_CERT_RENEW, value=body)
        self.certificate = json.loads(reply["value"])
        return self.certificate

    async def cert_lookup(self, phone: str) -> Optional[Dict[str, Any]]:
        reply = await self.request(bs.T_CERT_LOOKUP, key=phone)
        value = reply.get("value") or ""
        return json.loads(value) if value else None

    async def deposit(self, envelope: Dict[str, Any]) -> str:
        reply = await self.request(bs.T_RELAY_DEPOSIT, envelope=envelope,
                                   recipient_phone=envelope["recipientPhone"])
        return reply.get("key", "")

    async def fetch(self, wait: int = 0, max_items: int = 100,
                    timeout: float = 40.0) -> List[Dict[str, Any]]:
        body = json.dumps({"wait": wait, "max": max_items}, separators=(",", ":"))
        reply = await self.request(bs.T_RELAY_FETCH, value=body, timeout=timeout)
        return json.loads(reply.get("value") or "[]")

    async def ack(self, ids: List[str]) -> None:
        await self.request(bs.T_RELAY_ACK,
                           value=json.dumps(ids, separators=(",", ":")))

    async def report(self, reported_phone: str, reason: str,
                     evidence: Optional[List[Dict[str, Any]]] = None) -> None:
        body = json.dumps({
            "reportedPhone": reported_phone,
            "reason": reason,
            "evidence": evidence or [],
        }, separators=(",", ":"))
        await self.request(bs.T_REPORT, value=body)

    async def set_push_token(self, token: str, sandbox: bool = False) -> None:
        """Register the device's APNs token, or clear it with an empty string."""
        value = json.dumps({"sandbox": bool(sandbox)}, separators=(",", ":"))
        await self.request(bs.T_PUSH_TOKEN, key=token, value=value)

    async def delete_account(self) -> None:
        await self.request(bs.T_DELETE_ACCOUNT)

    async def change_number_start(self, new_phone: str) -> int:
        reply = await self.request(bs.T_CHANGE_NUMBER_START, key=new_phone)
        return int(reply.get("value") or 0)

    async def change_number_confirm(self, new_phone: str, code: str) -> Dict[str, Any]:
        body = json.dumps({"newPhone": new_phone, "code": code},
                          separators=(",", ":"))
        reply = await self.request(bs.T_CHANGE_NUMBER_CONFIRM, value=body)
        self.certificate = json.loads(reply["value"])
        self.phone = new_phone
        return self.certificate

    # -- convenience --------------------------------------------------------- #

    def seal_to(self, peer_cert: Dict[str, Any], payload: bytes,
                envelope_id: Optional[str] = None,
                timestamp: Optional[int] = None) -> Dict[str, Any]:
        env, _ = seal_envelope(
            payload=payload,
            envelope_id=envelope_id or str(uuid.uuid4()),
            sender_phone=self.phone,
            recipient_phone=peer_cert["phone"],
            timestamp=int(timestamp if timestamp is not None else time.time()),
            sender_signing=self.signing,
            sender_agreement=self.agreement,
            recipient_signing_b64=peer_cert["signingKey"],
            recipient_agreement_b64=peer_cert["agreementKey"],
            sender_certificate_json=self.certificate_json,
        )
        return env


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------

async def _smoke(args: argparse.Namespace) -> None:
    client = hoppinClient(args.phone, host=args.host, port=args.port,
                           use_tls=args.tls, cafile=args.cafile,
                           server_key_b64=args.server_key)
    retry = await client.verify_start()
    print("verifyStart ok, retryAfter =", retry)
    code = args.code or input("code: ").strip()
    cert = await client.verify_confirm(code)
    print("certificate issued, serial =", cert["serial"],
          "expires =", cert["expiresAt"])
    await client.ping()
    print("ping ok")
    mail = await client.fetch(wait=0)
    print("mailbox has %d envelope(s)" % len(mail))


def main() -> None:
    parser = argparse.ArgumentParser(description="hoppin bootstrap smoke client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4001)
    parser.add_argument("--phone", required=True)
    parser.add_argument("--code", default=None)
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--cafile", default=None)
    parser.add_argument("--server-key", default=None,
                        help="base64 server Ed25519 public key to pin")
    asyncio.get_event_loop().run_until_complete(_smoke(parser.parse_args()))


if __name__ == "__main__":
    main()
