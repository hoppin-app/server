#!/usr/bin/env python3
"""
HopChat bootstrap server (v2).

Implements docs/DESIGN_CONTRACT.md sections 1-5:

  * §1 canonical length-prefixed signing encoding
  * §2 identity certificates signed by the server Ed25519 key
  * §3 wire messages (4-byte BE length + UTF-8 JSON, one request/one response)
  * §4 envelopes (opaque to the server; only signatures are checked)
  * §5 server policy: TLS, SMS OTP, rate limits, relay queue caps, persistence

The server is a *store-and-forward relay plus certificate authority*. It never
decrypts message content, never returns peer lists, never maps phone -> IP, and
never mutates state on an unauthenticated request.

Python 3.9+ / stdlib + `cryptography`.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import signal
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ENV = os.environ.get("HOPCHAT_ENV", "prod").strip().lower()
IS_DEV = ENV == "dev"

PLAINTEXT_PORT = int(os.environ.get("HOPCHAT_PORT", "4001"))
TLS_PORT = int(os.environ.get("HOPCHAT_TLS_PORT", "4443"))
TLS_CERT = os.environ.get("HOPCHAT_TLS_CERT", "").strip()
TLS_KEY = os.environ.get("HOPCHAT_TLS_KEY", "").strip()
ALLOW_PLAINTEXT = os.environ.get("HOPCHAT_ALLOW_PLAINTEXT", "") == "1"

IDENTITY_KEY_PATH = os.environ.get("HOPCHAT_IDENTITY_KEY", "./bootstrap_identity.key")
STATE_PATH = os.environ.get("HOPCHAT_STATE", "./bootstrap_state.json")
REPORTS_PATH = os.environ.get("HOPCHAT_REPORTS", "./reports.jsonl")

BIND_HOST = os.environ.get("HOPCHAT_BIND", "0.0.0.0")

# --- protocol constants (§3) ---------------------------------------------- #

WIRE_VERSION = 2
MAX_FRAME = 1_048_576                # 1 MiB hard frame limit
FRESHNESS_WINDOW = 300               # |now - timestamp| <= 300 s
TXID_TTL = 600                       # replay cache retention

# --- certificate constants (§2) ------------------------------------------- #

CERT_VERSION = 1
CERT_VALIDITY = 30 * 86400           # 30 days
CERT_CLOCK_SKEW = 300                # issuedAt - 300 <= now
REVOKED_TTL = 31 * 86400

# --- limits (§5) ----------------------------------------------------------- #

IP_BUCKET_CAPACITY = 60              # 60 req / min per IP
IP_BUCKET_REFILL = 60.0 / 60.0       # tokens per second
MAX_CONNECTIONS_PER_IP = 64
READ_TIMEOUT = 15.0                  # seconds (not applied to the relayFetch hold)

VERIFY_START_PER_PHONE = 3           # per hour
VERIFY_START_PER_IP = 10             # per hour
CERT_LOOKUP_PER_CALLER = 30          # per hour
RATE_WINDOW = 3600

OTP_TTL = 600                        # 10 minutes
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_AFTER = 60                # retryAfter hint returned to the client

QUEUE_MAX_ENVELOPES = 500            # per recipient
QUEUE_MAX_BYTES = 20 * 1024 * 1024   # per recipient
ENVELOPE_MAX_BYTES = 900 * 1024
QUEUE_TTL = 7 * 86400
GLOBAL_QUEUE_MAX_BYTES = int(os.environ.get("HOPCHAT_QUEUE_MAX_BYTES", str(512 * 1024 * 1024)))
RELAY_BATCH_BUDGET = 880 * 1024      # keep the response frame under 900 KB
RELAY_WAIT_MAX = 25
RELAY_MAX_MAX = 100

STATE_FLUSH_INTERVAL = 10.0
REPORT_MAX_EVIDENCE = 20

# --- message types (§3) ----------------------------------------------------- #

T_PING = 0x01
T_PONG = 0x02
T_DIRECT_ENVELOPE = 0x0B
T_DIRECT_ACK = 0x0C
T_VERIFY_START = 0x20
T_VERIFY_STARTED = 0x21
T_VERIFY_CONFIRM = 0x22
T_CERTIFICATE_ISSUED = 0x23
T_CERT_RENEW = 0x24
T_CERT_LOOKUP = 0x25
T_CERT_RESULT = 0x26
T_ERROR = 0x2F
T_RELAY_DEPOSIT = 0x30
T_RELAY_ACCEPTED = 0x31
T_RELAY_FETCH = 0x32
T_RELAY_BATCH = 0x33
T_RELAY_ACK = 0x34
T_OK = 0x35
T_REPORT = 0x36
T_DELETE_ACCOUNT = 0x37
T_CHANGE_NUMBER_START = 0x38
T_CHANGE_NUMBER_CONFIRM = 0x39
T_HELLO = 0x40

# Types the server accepts. Everything else is a bad_request.
SERVER_TYPES = {
    T_PING,
    T_VERIFY_START,
    T_VERIFY_CONFIRM,
    T_CERT_RENEW,
    T_CERT_LOOKUP,
    T_RELAY_DEPOSIT,
    T_RELAY_FETCH,
    T_RELAY_ACK,
    T_REPORT,
    T_DELETE_ACCOUNT,
    T_CHANGE_NUMBER_START,
    T_CHANGE_NUMBER_CONFIRM,
}

# Types that do not carry a certificate (§3).
UNAUTHENTICATED_TYPES = {T_VERIFY_START, T_VERIFY_CONFIRM}

log = logging.getLogger("hopchat-bootstrap")


# ---------------------------------------------------------------------------
# §1 Canonical encoding
# ---------------------------------------------------------------------------

def canonical(fields: List[str]) -> bytes:
    """Canonical(fields) = concat of ASCII(len(utf8(f))) + ":" + utf8(f)."""
    out = bytearray()
    for f in fields:
        b = f.encode("utf-8")
        out += str(len(b)).encode("ascii")
        out += b":"
        out += b
    return bytes(out)


def cint(value: int) -> str:
    """Base-10, no leading zeros."""
    return str(int(value))


def cbool(value: bool) -> str:
    return "1" if value else "0"


def copt(value: Optional[str]) -> str:
    return value if value else ""


# ---------------------------------------------------------------------------
# Base64 / key helpers
# ---------------------------------------------------------------------------

def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(s: str) -> Optional[bytes]:
    """Strict standard base64 with padding. Returns None on anything invalid."""
    if not isinstance(s, str):
        return None
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def b64d_key32(s: str) -> Optional[bytes]:
    raw = b64d(s)
    if raw is None or len(raw) != 32:
        return None
    return raw


def verify_ed25519(public_key_b64: str, message: bytes, signature_b64: str) -> bool:
    """Constant-time signature check via the library. Never raises."""
    raw_key = b64d_key32(public_key_b64)
    if raw_key is None:
        return False
    sig = b64d(signature_b64)
    if sig is None or len(sig) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(raw_key).verify(sig, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# §2 Phone numbers
# ---------------------------------------------------------------------------

E164_RE = re.compile(r"^\+[1-9][0-9]{7,14}$")

# Region -> calling code. Must stay in sync with Swift PhoneNumber.normalize.
CALLING_CODES = {
    "AT": "43", "AU": "61", "BE": "32", "BR": "55", "CA": "1", "CH": "41",
    "CN": "86", "CZ": "420", "DE": "49", "DK": "45", "ES": "34", "FI": "358",
    "FR": "33", "GB": "44", "GR": "30", "HU": "36", "IE": "353", "IN": "91",
    "IT": "39", "JP": "81", "KR": "82", "LU": "352", "MX": "52", "NL": "31",
    "NO": "47", "NZ": "64", "PL": "48", "PT": "351", "RO": "40", "RU": "7",
    "SE": "46", "TR": "90", "UA": "380", "US": "1", "ZA": "27",
}

_STRIP_CHARS = " \t -()./‐‑‒–—"


def is_valid_e164(s: str) -> bool:
    return isinstance(s, str) and bool(E164_RE.match(s))


def normalize_phone(raw: str, default_region: Optional[str] = None) -> Optional[str]:
    """
    Mirror of the client-side normalizer (§2), shared so that the cross-language
    fixtures agree. The server itself only ever *validates* E.164.
    """
    if not isinstance(raw, str):
        return None
    s = "".join(ch for ch in raw if ch not in _STRIP_CHARS)
    if not s:
        return None

    if s.startswith("00"):
        s = "+" + s[2:]

    if s.startswith("+"):
        digits = s[1:]
        if not digits.isdigit():
            return None
        candidate = "+" + digits
    else:
        if not s.isdigit():
            return None
        region = (default_region or "").upper()
        code = CALLING_CODES.get(region)
        if not code:
            return None
        national = s
        # Drop a single national trunk '0'.
        if national.startswith("0"):
            national = national[1:]
        candidate = "+" + code + national

    return candidate if is_valid_e164(candidate) else None


def mask_phone(phone: str) -> str:
    """'+351912345678' -> '+35191*****78'. Never log a full number."""
    if not isinstance(phone, str) or len(phone) < 6:
        return "<phone>"
    return phone[:6] + "*" * max(0, len(phone) - 8) + phone[-2:]


# ---------------------------------------------------------------------------
# §2 Identity certificates
# ---------------------------------------------------------------------------

def cert_signed_fields(phone: str, signing_key: str, agreement_key: str,
                       issued_at: int, expires_at: int, serial: str) -> List[str]:
    return [
        "hopchat-cert-v1",
        phone,
        signing_key,
        agreement_key,
        cint(issued_at),
        cint(expires_at),
        serial,
    ]


def make_certificate(server_key: Ed25519PrivateKey, phone: str, signing_key: str,
                     agreement_key: str, issued_at: int,
                     expires_at: Optional[int] = None,
                     serial: Optional[str] = None) -> Dict[str, Any]:
    if expires_at is None:
        expires_at = issued_at + CERT_VALIDITY
    if serial is None:
        serial = str(uuid.uuid4())
    fields = cert_signed_fields(phone, signing_key, agreement_key,
                                issued_at, expires_at, serial)
    sig = server_key.sign(canonical(fields))
    return {
        "v": CERT_VERSION,
        "phone": phone,
        "signingKey": signing_key,
        "agreementKey": agreement_key,
        "issuedAt": int(issued_at),
        "expiresAt": int(expires_at),
        "serial": serial,
        "sig": b64e(sig),
    }


def parse_certificate(cert_json: str) -> Optional[Dict[str, Any]]:
    if not isinstance(cert_json, str) or not cert_json:
        return None
    try:
        cert = json.loads(cert_json)
    except (ValueError, TypeError):
        return None
    if not isinstance(cert, dict):
        return None
    required = ("v", "phone", "signingKey", "agreementKey",
                "issuedAt", "expiresAt", "serial", "sig")
    if any(k not in cert for k in required):
        return None
    if not isinstance(cert["v"], int) or cert["v"] != CERT_VERSION:
        return None
    if not isinstance(cert["issuedAt"], int) or not isinstance(cert["expiresAt"], int):
        return None
    for k in ("phone", "signingKey", "agreementKey", "serial", "sig"):
        if not isinstance(cert[k], str):
            return None
    return cert


def certificate_is_valid(cert: Dict[str, Any], server_public_b64: str,
                         now: Optional[int] = None) -> bool:
    """§2: v == 1, sig verifies, issuedAt - 300 <= now < expiresAt, phone E.164."""
    if now is None:
        now = int(time.time())
    if cert.get("v") != CERT_VERSION:
        return False
    if not is_valid_e164(cert.get("phone", "")):
        return False
    if b64d_key32(cert.get("signingKey", "")) is None:
        return False
    if b64d_key32(cert.get("agreementKey", "")) is None:
        return False
    issued_at = cert.get("issuedAt")
    expires_at = cert.get("expiresAt")
    if not isinstance(issued_at, int) or not isinstance(expires_at, int):
        return False
    if not (issued_at - CERT_CLOCK_SKEW <= now < expires_at):
        return False
    fields = cert_signed_fields(cert["phone"], cert["signingKey"],
                               cert["agreementKey"], issued_at, expires_at,
                               cert["serial"])
    return verify_ed25519(server_public_b64, canonical(fields), cert["sig"])


def encode_certificate(cert: Dict[str, Any]) -> str:
    return json.dumps(cert, separators=(",", ":"), sort_keys=True)


# ---------------------------------------------------------------------------
# §4 Envelope helpers (the server never decrypts; it only checks signatures)
# ---------------------------------------------------------------------------

ENVELOPE_FIELDS = ("id", "senderPhone", "recipientPhone", "timestamp",
                   "senderAgreementKey", "recipientAgreementKey", "ephemeralKey",
                   "ciphertext", "senderCertificate", "signature")


def envelope_header(env: Dict[str, Any]) -> List[str]:
    return [
        "hopchat-env-v2",
        env["id"],
        env["senderPhone"],
        env["recipientPhone"],
        cint(env["timestamp"]),
        env["senderAgreementKey"],
        env["recipientAgreementKey"],
        env["ephemeralKey"],
    ]


def envelope_signed_fields(env: Dict[str, Any]) -> List[str]:
    return envelope_header(env) + [env["ciphertext"]]


def envelope_digest_hex(env: Dict[str, Any]) -> str:
    fields = envelope_header(env) + [env["ciphertext"], env["signature"]]
    return hashlib.sha256(canonical(fields)).hexdigest()


def validate_envelope_shape(env: Any) -> bool:
    if not isinstance(env, dict):
        return False
    for k in ENVELOPE_FIELDS:
        if k not in env:
            return False
    if not isinstance(env["timestamp"], int):
        return False
    for k in ENVELOPE_FIELDS:
        if k != "timestamp" and not isinstance(env[k], str):
            return False
    return True


# ---------------------------------------------------------------------------
# §3 Wire messages
# ---------------------------------------------------------------------------

def wire_signed_fields(msg: Dict[str, Any]) -> List[str]:
    env = msg.get("envelope")
    digest = envelope_digest_hex(env) if isinstance(env, dict) and validate_envelope_shape(env) else ""
    return [
        "hopchat-wire-v2",
        cint(msg["type"]),
        msg["txID"],
        msg["senderPhone"],
        cint(msg.get("senderPort") or 0),
        cint(msg["timestamp"]),
        copt(msg.get("recipientPhone")),
        copt(msg.get("key")),
        copt(msg.get("value")),
        digest,
    ]


class ProtocolError(Exception):
    """Maps to a 0x2F error reply."""

    def __init__(self, code: str, message: str = ""):
        super().__init__(code)
        self.code = code
        self.message = message or code


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------

async def read_frame(reader: asyncio.StreamReader, timeout: float) -> bytes:
    """
    Read one length-prefixed frame under a wall-clock timeout (slow-loris
    defence). Raises ProtocolError('too_large') for oversized frames and
    ConnectionError on EOF/timeout.
    """
    try:
        header = await asyncio.wait_for(reader.readexactly(4), timeout)
    except asyncio.TimeoutError:
        raise ConnectionError("read timeout")
    except (asyncio.IncompleteReadError, ConnectionResetError, OSError):
        raise ConnectionError("eof")

    (length,) = struct.unpack(">I", header)
    if length == 0 or length > MAX_FRAME:
        raise ProtocolError("too_large", "frame length out of range")

    try:
        return await asyncio.wait_for(reader.readexactly(length), timeout)
    except asyncio.TimeoutError:
        raise ConnectionError("read timeout")
    except (asyncio.IncompleteReadError, ConnectionResetError, OSError):
        raise ConnectionError("eof")


def make_frame(msg: Dict[str, Any]) -> bytes:
    payload = json.dumps(msg, separators=(",", ":")).encode("utf-8")
    return struct.pack(">I", len(payload)) + payload


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

class TokenBucket:
    __slots__ = ("tokens", "capacity", "refill", "updated")

    def __init__(self, capacity: int, refill_per_sec: float):
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.refill = refill_per_sec
        self.updated = time.monotonic()

    def take(self, amount: float = 1.0) -> bool:
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.refill)
        self.updated = now
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False


class SlidingCounter:
    """Fixed-window counters with a TTL, for the per-hour limits in §5."""

    def __init__(self, window: int = RATE_WINDOW):
        self.window = window
        self._hits: Dict[str, List[float]] = {}

    def hit(self, key: str, limit: int) -> bool:
        now = time.monotonic()
        hits = [t for t in self._hits.get(key, []) if now - t < self.window]
        if len(hits) >= limit:
            self._hits[key] = hits
            return False
        hits.append(now)
        self._hits[key] = hits
        return True

    def purge(self) -> None:
        now = time.monotonic()
        for key in list(self._hits):
            hits = [t for t in self._hits[key] if now - t < self.window]
            if hits:
                self._hits[key] = hits
            else:
                del self._hits[key]


# ---------------------------------------------------------------------------
# SMS providers (§5)
# ---------------------------------------------------------------------------

class SMSProvider:
    name = "none"

    def send(self, phone: str, code: str) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class ConsoleSMSProvider(SMSProvider):
    """Dev only. This is the ONLY place an OTP code may be logged."""

    name = "console"

    def send(self, phone: str, code: str) -> None:
        log.info("[dev-sms] %s -> code %s", mask_phone(phone), code)


class TwilioSMSProvider(SMSProvider):
    name = "twilio"

    def __init__(self, account_sid: str, auth_token: str, from_number: str):
        self.account_sid = account_sid
        self.auth_token = auth_token
        self.from_number = from_number

    def send(self, phone: str, code: str) -> None:
        url = "https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json" % (
            urllib.parse.quote(self.account_sid)
        )
        body = urllib.parse.urlencode({
            "To": phone,
            "From": self.from_number,
            "Body": "Your HopChat verification code is %s. It expires in 10 minutes." % code,
        }).encode("ascii")
        auth = base64.b64encode(
            ("%s:%s" % (self.account_sid, self.auth_token)).encode("utf-8")
        ).decode("ascii")
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Authorization", "Basic " + auth)
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status >= 300:
                    raise ProtocolError("internal", "sms send failed")
        except urllib.error.HTTPError as exc:
            # Never log the code or the full number.
            log.error("twilio send failed for %s: HTTP %s", mask_phone(phone), exc.code)
            raise ProtocolError("internal", "sms send failed")
        except (urllib.error.URLError, OSError) as exc:
            log.error("twilio send failed for %s: %s", mask_phone(phone), exc.__class__.__name__)
            raise ProtocolError("internal", "sms send failed")


def build_sms_provider() -> SMSProvider:
    sid = os.environ.get("TWILIO_ACCOUNT_SID", "").strip()
    token = os.environ.get("TWILIO_AUTH_TOKEN", "").strip()
    from_number = os.environ.get("TWILIO_FROM", "").strip()
    if sid and token and from_number:
        return TwilioSMSProvider(sid, token, from_number)
    if IS_DEV:
        return ConsoleSMSProvider()
    raise SystemExit(
        "refusing to start: no SMS provider configured. Set TWILIO_ACCOUNT_SID, "
        "TWILIO_AUTH_TOKEN and TWILIO_FROM, or run with HOPCHAT_ENV=dev."
    )


# ---------------------------------------------------------------------------
# Server identity key (§2)
# ---------------------------------------------------------------------------

def load_or_create_identity_key(path: str) -> Ed25519PrivateKey:
    """Raw 32-byte Ed25519 seed, base64, mode 600. Created on first run."""
    if os.path.exists(path):
        with open(path, "r", encoding="ascii") as fh:
            seed = b64d(fh.read().strip())
        if seed is None or len(seed) != 32:
            raise SystemExit("identity key at %s is not a base64 32-byte seed" % path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return Ed25519PrivateKey.from_private_bytes(seed)

    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(b64e(seed) + "\n")
    log.info("generated a new server identity key at %s", path)
    return key


def public_key_b64(key: Ed25519PrivateKey) -> str:
    return b64e(key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ))


# ---------------------------------------------------------------------------
# Atomic, 0600 file writes
# ---------------------------------------------------------------------------

def atomic_write(path: str, data: str) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    if not os.path.isdir(directory):
        os.makedirs(directory, mode=0o700, exist_ok=True)
    tmp = os.path.join(directory, ".%s.%s.tmp" % (os.path.basename(path), os.getpid()))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def append_jsonl(path: str, record: Dict[str, Any]) -> None:
    exists = os.path.exists(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n")
    if not exists:
        os.chmod(path, 0o600)


# ---------------------------------------------------------------------------
# The server
# ---------------------------------------------------------------------------

class PendingVerification:
    __slots__ = ("salt", "digest", "expires_at", "attempts", "new_phone")

    def __init__(self, salt: bytes, digest: bytes, expires_at: float,
                 new_phone: Optional[str] = None):
        self.salt = salt
        self.digest = digest
        self.expires_at = expires_at
        self.attempts = 0
        self.new_phone = new_phone


class BootstrapServer:
    def __init__(self,
                 identity_key: Optional[Ed25519PrivateKey] = None,
                 sms: Optional[SMSProvider] = None,
                 state_path: str = STATE_PATH,
                 reports_path: str = REPORTS_PATH,
                 dev_fixed_code: Optional[str] = None):
        self.key = identity_key or load_or_create_identity_key(IDENTITY_KEY_PATH)
        self.public_b64 = public_key_b64(self.key)
        self.sms = sms or build_sms_provider()
        self.state_path = state_path
        self.reports_path = reports_path
        self.dev_fixed_code = dev_fixed_code if IS_DEV else None

        # Persisted state.
        self.certs: Dict[str, Dict[str, Any]] = {}
        self.revoked: Dict[str, int] = {}
        self.queue: Dict[str, List[Dict[str, Any]]] = {}
        self.last_seen: Dict[str, int] = {}

        # Volatile state.
        self.pending: Dict[str, PendingVerification] = {}
        self.txids: Dict[str, float] = {}
        self.mail_events: Dict[str, asyncio.Event] = {}
        self.ip_buckets: Dict[str, TokenBucket] = {}
        self.ip_connections: Dict[str, int] = {}
        self.verify_phone_counter = SlidingCounter()
        self.verify_ip_counter = SlidingCounter()
        self.lookup_counter = SlidingCounter()

        self._dirty = False
        self._servers: List[asyncio.AbstractServer] = []
        self._tasks: List[asyncio.Task] = []
        self._stopping = asyncio.Event()

        self.plaintext_port: Optional[int] = None
        self.tls_port: Optional[int] = None

    # -- state persistence (§5) -------------------------------------------- #

    def load_state(self) -> None:
        if not os.path.exists(self.state_path):
            return
        try:
            with open(self.state_path, "r", encoding="utf-8") as fh:
                state = json.load(fh)
        except (ValueError, OSError) as exc:
            log.error("could not read state file %s: %s", self.state_path, exc)
            return
        if not isinstance(state, dict):
            return
        self.certs = {k: v for k, v in (state.get("certs") or {}).items()
                      if isinstance(v, dict)}
        self.revoked = {k: int(v) for k, v in (state.get("revoked") or {}).items()}
        self.last_seen = {k: int(v) for k, v in (state.get("lastSeen") or {}).items()}
        queue = state.get("queue") or {}
        self.queue = {}
        for phone, items in queue.items():
            if not isinstance(items, list):
                continue
            clean = [it for it in items
                     if isinstance(it, dict) and validate_envelope_shape(it.get("env"))]
            if clean:
                self.queue[phone] = clean
        self.expire_state()
        log.info("loaded state: %d certs, %d mailboxes, %d queued envelopes",
                 len(self.certs), len(self.queue),
                 sum(len(v) for v in self.queue.values()))

    def save_state(self) -> None:
        state = {
            "v": 1,
            "certs": self.certs,
            "revoked": self.revoked,
            "queue": self.queue,
            "lastSeen": self.last_seen,
        }
        try:
            atomic_write(self.state_path, json.dumps(state, separators=(",", ":")))
            self._dirty = False
        except OSError as exc:
            log.error("could not write state file %s: %s", self.state_path, exc)

    def touch(self) -> None:
        self._dirty = True

    # -- housekeeping ------------------------------------------------------- #

    def expire_state(self) -> None:
        now = int(time.time())

        for serial in [s for s, exp in self.revoked.items() if exp <= now]:
            del self.revoked[serial]

        for phone in list(self.queue):
            items = [it for it in self.queue[phone]
                     if now - int(it.get("at", 0)) < QUEUE_TTL]
            if items:
                self.queue[phone] = items
            else:
                del self.queue[phone]

        mono = time.monotonic()
        for tx in [t for t, seen in self.txids.items() if mono - seen > TXID_TTL]:
            del self.txids[tx]

        for phone in [p for p, pv in self.pending.items() if pv.expires_at <= mono]:
            del self.pending[phone]

        self.verify_phone_counter.purge()
        self.verify_ip_counter.purge()
        self.lookup_counter.purge()
        self.enforce_global_cap()

    def queue_bytes(self) -> int:
        return sum(int(it.get("size", 0)) for items in self.queue.values() for it in items)

    def enforce_global_cap(self) -> None:
        """Evict expired first (done in expire_state), then oldest-first."""
        total = self.queue_bytes()
        if total <= GLOBAL_QUEUE_MAX_BYTES:
            return
        entries = []
        for phone, items in self.queue.items():
            for it in items:
                entries.append((int(it.get("at", 0)), phone, it))
        entries.sort(key=lambda e: e[0])
        for _, phone, it in entries:
            if total <= GLOBAL_QUEUE_MAX_BYTES:
                break
            items = self.queue.get(phone)
            if not items:
                continue
            try:
                items.remove(it)
            except ValueError:
                continue
            total -= int(it.get("size", 0))
            if not items:
                self.queue.pop(phone, None)
        self.touch()
        log.warning("global queue cap exceeded; evicted oldest envelopes")

    def mail_event(self, phone: str) -> asyncio.Event:
        ev = self.mail_events.get(phone)
        if ev is None:
            ev = asyncio.Event()
            self.mail_events[phone] = ev
        return ev

    # -- response construction ---------------------------------------------- #

    def sign_response(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        msg.setdefault("v", WIRE_VERSION)
        msg.setdefault("senderPhone", "server")
        msg.setdefault("senderPort", 0)
        msg.setdefault("timestamp", int(time.time()))
        sig = self.key.sign(canonical(wire_signed_fields(msg)))
        msg["signature"] = b64e(sig)
        return msg

    def response(self, tx_id: str, msg_type: int, **fields: Any) -> Dict[str, Any]:
        msg = {"v": WIRE_VERSION, "type": msg_type, "txID": tx_id,
               "senderPhone": "server", "senderPort": 0,
               "timestamp": int(time.time())}
        for k, v in fields.items():
            if v is not None:
                msg[k] = v
        return self.sign_response(msg)

    def error(self, tx_id: str, code: str, message: str = "") -> Dict[str, Any]:
        return self.response(tx_id, T_ERROR, key=code, value=message or code)

    # -- OTP ---------------------------------------------------------------- #

    def _generate_code(self) -> str:
        if self.dev_fixed_code:
            return self.dev_fixed_code
        return "".join(secrets.choice("0123456789") for _ in range(6))

    @staticmethod
    def _hash_code(salt: bytes, code: str) -> bytes:
        return hashlib.sha256(salt + code.encode("ascii")).digest()

    def start_verification(self, phone: str, ip: str,
                           new_phone: Optional[str] = None) -> int:
        """Create/replace a pending OTP and send it. Returns retryAfter seconds."""
        if not self.verify_phone_counter.hit("p:" + phone, VERIFY_START_PER_PHONE):
            raise ProtocolError("rate_limited", "too many codes requested for this number")
        if not self.verify_ip_counter.hit("i:" + ip, VERIFY_START_PER_IP):
            raise ProtocolError("rate_limited", "too many codes requested from this address")

        code = self._generate_code()
        salt = secrets.token_bytes(16)
        target = new_phone or phone
        self.pending[phone] = PendingVerification(
            salt=salt,
            digest=self._hash_code(salt, code),
            expires_at=time.monotonic() + OTP_TTL,
            new_phone=new_phone,
        )
        self.sms.send(target, code)
        log.info("verification code sent to %s", mask_phone(target))
        return OTP_RESEND_AFTER

    def check_code(self, phone: str, code: str,
                   expect_new_phone: Optional[str] = None) -> None:
        pv = self.pending.get(phone)
        if pv is None:
            raise ProtocolError("invalid_code", "no verification in progress")
        if pv.expires_at <= time.monotonic():
            del self.pending[phone]
            raise ProtocolError("code_expired", "verification code expired")
        if pv.attempts >= OTP_MAX_ATTEMPTS:
            del self.pending[phone]
            raise ProtocolError("too_many_attempts", "too many attempts")
        if expect_new_phone is not None and pv.new_phone != expect_new_phone:
            pv.attempts += 1
            raise ProtocolError("invalid_code", "verification code is not valid")
        if not isinstance(code, str) or not code:
            pv.attempts += 1
            raise ProtocolError("invalid_code", "verification code is not valid")
        if not hmac.compare_digest(pv.digest, self._hash_code(pv.salt, code)):
            pv.attempts += 1
            if pv.attempts >= OTP_MAX_ATTEMPTS:
                del self.pending[phone]
                raise ProtocolError("too_many_attempts", "too many attempts")
            raise ProtocolError("invalid_code", "verification code is not valid")
        del self.pending[phone]

    # -- certificate issuance ----------------------------------------------- #

    def issue_certificate(self, phone: str, signing_key: str,
                          agreement_key: str) -> Dict[str, Any]:
        now = int(time.time())
        previous = self.certs.get(phone)
        if previous and isinstance(previous.get("serial"), str):
            self.revoked[previous["serial"]] = now + REVOKED_TTL
        cert = make_certificate(self.key, phone, signing_key, agreement_key, now)
        self.certs[phone] = cert
        self.last_seen[phone] = now
        self.touch()
        log.info("issued certificate for %s", mask_phone(phone))
        return cert

    def purge_account(self, phone: str) -> None:
        cert = self.certs.pop(phone, None)
        if cert and isinstance(cert.get("serial"), str):
            self.revoked[cert["serial"]] = int(time.time()) + REVOKED_TTL
        self.queue.pop(phone, None)
        self.last_seen.pop(phone, None)
        self.pending.pop(phone, None)
        self.mail_events.pop(phone, None)
        self.touch()

    # -- request handling ---------------------------------------------------- #

    async def handle_request(self, raw: bytes, ip: str) -> Optional[Dict[str, Any]]:
        try:
            msg = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ProtocolError("bad_request", "malformed JSON")
        if not isinstance(msg, dict):
            raise ProtocolError("bad_request", "malformed JSON")

        tx_id = msg.get("txID")
        if not isinstance(tx_id, str) or not tx_id or len(tx_id) > 128:
            raise ProtocolError("bad_request", "missing txID")

        if msg.get("v") != WIRE_VERSION:
            raise ProtocolError("bad_request", "unsupported protocol version")
        msg_type = msg.get("type")
        if not isinstance(msg_type, int) or msg_type not in SERVER_TYPES:
            raise ProtocolError("bad_request", "unsupported message type")
        timestamp = msg.get("timestamp")
        if not isinstance(timestamp, int):
            raise ProtocolError("bad_request", "missing timestamp")
        sender = msg.get("senderPhone")
        if not isinstance(sender, str) or not sender:
            raise ProtocolError("bad_request", "missing senderPhone")
        signature = msg.get("signature")
        if not isinstance(signature, str) or not signature:
            raise ProtocolError("bad_signature", "missing signature")

        # §3 freshness, then replay.
        now = int(time.time())
        if abs(now - timestamp) > FRESHNESS_WINDOW:
            raise ProtocolError("stale", "timestamp outside the freshness window")
        if tx_id in self.txids:
            raise ProtocolError("replay", "txID already seen")
        self.txids[tx_id] = time.monotonic()

        # Authentication.
        cert: Optional[Dict[str, Any]] = None
        if msg_type not in UNAUTHENTICATED_TYPES:
            cert = self.authenticate(msg)

        handler = self.HANDLERS[msg_type]
        return await handler(self, msg, cert, ip)

    def authenticate(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        """Certificate + wire signature + sender binding. Raises ProtocolError."""
        cert_json = msg.get("certificate")
        cert = parse_certificate(cert_json) if isinstance(cert_json, str) else None
        if cert is None:
            raise ProtocolError("cert_invalid", "missing or malformed certificate")
        if not certificate_is_valid(cert, self.public_b64):
            raise ProtocolError("cert_invalid", "certificate is not valid")
        if cert["phone"] != msg.get("senderPhone"):
            raise ProtocolError("cert_invalid", "certificate does not match senderPhone")
        if cert["serial"] in self.revoked:
            raise ProtocolError("cert_invalid", "certificate has been revoked")

        # The certificate on the wire must be the current one for that phone:
        # a superseded certificate must not be able to act on the account.
        current = self.certs.get(cert["phone"])
        if current is not None and current.get("serial") != cert["serial"]:
            raise ProtocolError("cert_invalid", "certificate has been superseded")

        if not verify_ed25519(cert["signingKey"],
                              canonical(wire_signed_fields(msg)),
                              msg["signature"]):
            raise ProtocolError("bad_signature", "wire signature does not verify")
        return cert

    # -- handlers ------------------------------------------------------------ #

    async def h_ping(self, msg, cert, ip):
        self.last_seen[cert["phone"]] = int(time.time())
        self.touch()
        return self.response(msg["txID"], T_PONG)

    async def h_verify_start(self, msg, cert, ip):
        phone = msg.get("key")
        if not isinstance(phone, str) or not is_valid_e164(phone):
            raise ProtocolError("invalid_phone", "phone must be E.164")
        # NOTE: §3 says verifyStart is signed with the prospective signing key,
        # but that key is not on the wire yet, so it cannot be verified here.
        # verifyConfirm carries the key and binds it to the code, which is where
        # the actual authentication happens. verifyStart is rate limited only.
        retry_after = self.start_verification(phone, ip)
        return self.response(msg["txID"], T_VERIFY_STARTED, value=str(retry_after))

    async def h_verify_confirm(self, msg, cert, ip):
        phone = msg.get("key")
        if not isinstance(phone, str) or not is_valid_e164(phone):
            raise ProtocolError("invalid_phone", "phone must be E.164")
        try:
            body = json.loads(msg.get("value") or "")
        except (ValueError, TypeError):
            raise ProtocolError("bad_request", "malformed value")
        if not isinstance(body, dict):
            raise ProtocolError("bad_request", "malformed value")

        code = body.get("code")
        signing_key = body.get("signingKey")
        agreement_key = body.get("agreementKey")
        if b64d_key32(signing_key or "") is None or b64d_key32(agreement_key or "") is None:
            raise ProtocolError("bad_request", "malformed keys")
        if msg.get("senderPhone") != phone:
            raise ProtocolError("bad_request", "senderPhone must equal key")

        # The message must be signed by the key being registered.
        if not verify_ed25519(signing_key, canonical(wire_signed_fields(msg)),
                              msg["signature"]):
            raise ProtocolError("bad_signature", "wire signature does not verify")

        self.check_code(phone, code if isinstance(code, str) else "")
        cert_out = self.issue_certificate(phone, signing_key, agreement_key)
        return self.response(msg["txID"], T_CERTIFICATE_ISSUED,
                             value=encode_certificate(cert_out))

    async def h_cert_renew(self, msg, cert, ip):
        try:
            body = json.loads(msg.get("value") or "")
        except (ValueError, TypeError):
            raise ProtocolError("bad_request", "malformed value")
        if not isinstance(body, dict):
            raise ProtocolError("bad_request", "malformed value")
        agreement_key = body.get("agreementKey")
        if b64d_key32(agreement_key or "") is None:
            raise ProtocolError("bad_request", "malformed agreementKey")
        # Same signing key, possibly rotated agreement key.
        cert_out = self.issue_certificate(cert["phone"], cert["signingKey"], agreement_key)
        return self.response(msg["txID"], T_CERTIFICATE_ISSUED,
                             value=encode_certificate(cert_out))

    async def h_cert_lookup(self, msg, cert, ip):
        target = msg.get("key")
        if not isinstance(target, str) or not is_valid_e164(target):
            raise ProtocolError("invalid_phone", "phone must be E.164")
        if not self.lookup_counter.hit("l:" + cert["phone"], CERT_LOOKUP_PER_CALLER):
            raise ProtocolError("rate_limited", "too many lookups")
        found = self.certs.get(target)
        value = encode_certificate(found) if found else ""
        return self.response(msg["txID"], T_CERT_RESULT, value=value)

    async def h_relay_deposit(self, msg, cert, ip):
        env = msg.get("envelope")
        if not validate_envelope_shape(env):
            raise ProtocolError("bad_request", "malformed envelope")

        size = len(json.dumps(env, separators=(",", ":")).encode("utf-8"))
        if size > ENVELOPE_MAX_BYTES:
            raise ProtocolError("too_large", "envelope exceeds the size limit")

        if env["senderPhone"] != msg.get("senderPhone"):
            raise ProtocolError("bad_request", "envelope sender does not match")
        recipient = msg.get("recipientPhone")
        if not isinstance(recipient, str) or not is_valid_e164(recipient):
            raise ProtocolError("invalid_phone", "recipientPhone must be E.164")
        if env["recipientPhone"] != recipient:
            raise ProtocolError("bad_request", "envelope recipient does not match")

        # The envelope must be signed by the sender's own signing key.
        if not verify_ed25519(cert["signingKey"],
                              canonical(envelope_signed_fields(env)),
                              env["signature"]):
            raise ProtocolError("bad_signature", "envelope signature does not verify")

        # Mail for a number with no current certificate (never registered, or
        # deleted) could never be fetched — refuse it rather than let anyone
        # fill a dead mailbox. The answer reveals registration status, so it
        # is metered exactly like certLookup to stop cheap enumeration.
        if recipient not in self.certs:
            if not self.lookup_counter.hit("l:" + cert["phone"], CERT_LOOKUP_PER_CALLER):
                raise ProtocolError("rate_limited", "too many lookups")
            raise ProtocolError("recipient_not_registered",
                                "recipient is not registered")

        now = int(time.time())
        mailbox = self.queue.setdefault(recipient, [])

        if any(it["env"]["id"] == env["id"] for it in mailbox):
            # Idempotent deposit.
            return self.response(msg["txID"], T_RELAY_ACCEPTED, key=env["id"])

        if len(mailbox) >= QUEUE_MAX_ENVELOPES:
            raise ProtocolError("queue_full", "recipient mailbox is full")
        if sum(int(it.get("size", 0)) for it in mailbox) + size > QUEUE_MAX_BYTES:
            raise ProtocolError("queue_full", "recipient mailbox is full")

        mailbox.append({"env": env, "at": now, "size": size})
        self.touch()
        self.enforce_global_cap()

        ev = self.mail_events.get(recipient)
        if ev is not None:
            ev.set()

        log.info("relay deposit %s -> %s (%d bytes)",
                 mask_phone(env["senderPhone"]), mask_phone(recipient), size)
        return self.response(msg["txID"], T_RELAY_ACCEPTED, key=env["id"])

    async def h_relay_fetch(self, msg, cert, ip):
        wait = 0
        max_items = 100
        if msg.get("value"):
            try:
                body = json.loads(msg["value"])
            except (ValueError, TypeError):
                raise ProtocolError("bad_request", "malformed value")
            if not isinstance(body, dict):
                raise ProtocolError("bad_request", "malformed value")
            if isinstance(body.get("wait"), int):
                wait = body["wait"]
            if isinstance(body.get("max"), int):
                max_items = body["max"]
        wait = max(0, min(RELAY_WAIT_MAX, wait))
        max_items = max(1, min(RELAY_MAX_MAX, max_items))

        phone = cert["phone"]
        self.last_seen[phone] = int(time.time())

        # Long poll: hold the connection until mail arrives or `wait` elapses.
        if wait > 0 and not self.queue.get(phone):
            ev = self.mail_event(phone)
            ev.clear()
            try:
                await asyncio.wait_for(ev.wait(), wait)
            except asyncio.TimeoutError:
                pass

        now = int(time.time())
        mailbox = self.queue.get(phone, [])
        batch: List[Dict[str, Any]] = []
        used = 0
        for item in mailbox:
            if now - int(item.get("at", 0)) >= QUEUE_TTL:
                continue
            size = int(item.get("size", 0))
            if batch and used + size > RELAY_BATCH_BUDGET:
                break
            batch.append(item["env"])
            used += size
            if len(batch) >= max_items:
                break

        value = json.dumps(batch, separators=(",", ":"))
        return self.response(msg["txID"], T_RELAY_BATCH, value=value)

    async def h_relay_ack(self, msg, cert, ip):
        try:
            ids = json.loads(msg.get("value") or "[]")
        except (ValueError, TypeError):
            raise ProtocolError("bad_request", "malformed value")
        if not isinstance(ids, list) or any(not isinstance(i, str) for i in ids):
            raise ProtocolError("bad_request", "value must be an array of ids")

        phone = cert["phone"]
        mailbox = self.queue.get(phone)
        if mailbox:
            wanted = set(ids)
            remaining = [it for it in mailbox if it["env"]["id"] not in wanted]
            if remaining:
                self.queue[phone] = remaining
            else:
                del self.queue[phone]
            self.touch()
        return self.response(msg["txID"], T_OK)

    async def h_report(self, msg, cert, ip):
        try:
            body = json.loads(msg.get("value") or "")
        except (ValueError, TypeError):
            raise ProtocolError("bad_request", "malformed value")
        if not isinstance(body, dict):
            raise ProtocolError("bad_request", "malformed value")
        reported = body.get("reportedPhone")
        reason = body.get("reason")
        evidence = body.get("evidence") or []
        if not isinstance(reported, str) or not is_valid_e164(reported):
            raise ProtocolError("invalid_phone", "reportedPhone must be E.164")
        if not isinstance(reason, str) or len(reason) > 500:
            raise ProtocolError("bad_request", "malformed reason")
        if not isinstance(evidence, list) or len(evidence) > REPORT_MAX_EVIDENCE:
            raise ProtocolError("bad_request", "too much evidence")

        record = {
            "at": int(time.time()),
            "reporter": cert["phone"],
            "reportedPhone": reported,
            "reason": reason,
            "evidence": evidence,
        }
        try:
            append_jsonl(self.reports_path, record)
        except OSError as exc:
            log.error("could not append report: %s", exc)
            raise ProtocolError("internal", "could not store report")
        log.info("report filed by %s against %s",
                 mask_phone(cert["phone"]), mask_phone(reported))
        return self.response(msg["txID"], T_OK)

    async def h_delete_account(self, msg, cert, ip):
        phone = cert["phone"]
        self.purge_account(phone)
        log.info("account deleted: %s", mask_phone(phone))
        return self.response(msg["txID"], T_OK)

    async def h_change_number_start(self, msg, cert, ip):
        new_phone = msg.get("key")
        if not isinstance(new_phone, str) or not is_valid_e164(new_phone):
            raise ProtocolError("invalid_phone", "phone must be E.164")
        if new_phone == cert["phone"]:
            raise ProtocolError("bad_request", "new number equals current number")
        if new_phone in self.certs:
            raise ProtocolError("bad_request", "number already registered")
        retry_after = self.start_verification(cert["phone"], ip, new_phone=new_phone)
        return self.response(msg["txID"], T_VERIFY_STARTED, value=str(retry_after))

    async def h_change_number_confirm(self, msg, cert, ip):
        try:
            body = json.loads(msg.get("value") or "")
        except (ValueError, TypeError):
            raise ProtocolError("bad_request", "malformed value")
        if not isinstance(body, dict):
            raise ProtocolError("bad_request", "malformed value")
        new_phone = body.get("newPhone")
        code = body.get("code")
        if not isinstance(new_phone, str) or not is_valid_e164(new_phone):
            raise ProtocolError("invalid_phone", "phone must be E.164")
        if new_phone in self.certs:
            raise ProtocolError("bad_request", "number already registered")

        old_phone = cert["phone"]
        self.check_code(old_phone, code if isinstance(code, str) else "",
                        expect_new_phone=new_phone)

        # Same keys, new phone. The old certificate is revoked and the old
        # mailbox moves across so queued mail is not lost.
        old_cert = self.certs.pop(old_phone, None)
        if old_cert and isinstance(old_cert.get("serial"), str):
            self.revoked[old_cert["serial"]] = int(time.time()) + REVOKED_TTL
        mailbox = self.queue.pop(old_phone, None)
        if mailbox:
            self.queue[new_phone] = mailbox
        self.last_seen.pop(old_phone, None)

        cert_out = self.issue_certificate(new_phone, cert["signingKey"],
                                          cert["agreementKey"])
        log.info("number change %s -> %s", mask_phone(old_phone), mask_phone(new_phone))
        return self.response(msg["txID"], T_CERTIFICATE_ISSUED,
                             value=encode_certificate(cert_out))

    HANDLERS = {
        T_PING: h_ping,
        T_VERIFY_START: h_verify_start,
        T_VERIFY_CONFIRM: h_verify_confirm,
        T_CERT_RENEW: h_cert_renew,
        T_CERT_LOOKUP: h_cert_lookup,
        T_RELAY_DEPOSIT: h_relay_deposit,
        T_RELAY_FETCH: h_relay_fetch,
        T_RELAY_ACK: h_relay_ack,
        T_REPORT: h_report,
        T_DELETE_ACCOUNT: h_delete_account,
        T_CHANGE_NUMBER_START: h_change_number_start,
        T_CHANGE_NUMBER_CONFIRM: h_change_number_confirm,
    }

    # -- connection handling -------------------------------------------------- #

    async def handle_connection(self, reader: asyncio.StreamReader,
                                writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else "?"

        count = self.ip_connections.get(ip, 0)
        if count >= MAX_CONNECTIONS_PER_IP:
            log.warning("connection cap reached for an address; dropping")
            try:
                writer.close()
            except OSError:
                pass
            return
        self.ip_connections[ip] = count + 1

        tx_id = ""
        try:
            bucket = self.ip_buckets.get(ip)
            if bucket is None:
                bucket = TokenBucket(IP_BUCKET_CAPACITY, IP_BUCKET_REFILL)
                self.ip_buckets[ip] = bucket

            raw = await read_frame(reader, READ_TIMEOUT)

            if not bucket.take():
                # Parse just far enough to echo the txID back.
                try:
                    tx_id = json.loads(raw.decode("utf-8")).get("txID") or ""
                except Exception:
                    tx_id = ""
                reply = self.error(tx_id, "rate_limited", "too many requests")
            else:
                try:
                    tx_id = json.loads(raw.decode("utf-8")).get("txID") or ""
                except Exception:
                    tx_id = ""
                try:
                    reply = await self.handle_request(raw, ip)
                except ProtocolError as exc:
                    reply = self.error(tx_id, exc.code, exc.message)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    log.exception("unhandled error while processing a request")
                    reply = self.error(tx_id, "internal", "internal error")

            if reply is not None:
                writer.write(make_frame(reply))
                await writer.drain()
        except ProtocolError as exc:
            # Framing-level failure (oversized frame): reply if we still can.
            try:
                writer.write(make_frame(self.error(tx_id, exc.code, exc.message)))
                await writer.drain()
            except (OSError, ConnectionError):
                pass
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("connection handler failed")
        finally:
            remaining = self.ip_connections.get(ip, 1) - 1
            if remaining > 0:
                self.ip_connections[ip] = remaining
            else:
                self.ip_connections.pop(ip, None)
            try:
                writer.close()
            except OSError:
                pass

    # -- lifecycle ------------------------------------------------------------ #

    async def start(self, plaintext_port: Optional[int] = None,
                    tls_port: Optional[int] = None,
                    tls_cert: str = "", tls_key: str = "",
                    allow_plaintext: Optional[bool] = None) -> None:
        self.load_state()

        if allow_plaintext is None:
            allow_plaintext = ALLOW_PLAINTEXT

        started_any = False

        if tls_cert and tls_key:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(tls_cert, tls_key)
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            except (AttributeError, ValueError):
                pass
            port = TLS_PORT if tls_port is None else tls_port
            srv = await asyncio.start_server(self.handle_connection, BIND_HOST, port, ssl=ctx)
            self._servers.append(srv)
            self.tls_port = srv.sockets[0].getsockname()[1]
            log.info("TLS listener on %s:%d", BIND_HOST, self.tls_port)
            started_any = True

        if allow_plaintext:
            port = PLAINTEXT_PORT if plaintext_port is None else plaintext_port
            srv = await asyncio.start_server(self.handle_connection, BIND_HOST, port)
            self._servers.append(srv)
            self.plaintext_port = srv.sockets[0].getsockname()[1]
            log.warning("PLAINTEXT listener on %s:%d - development only",
                        BIND_HOST, self.plaintext_port)
            started_any = True

        if not started_any:
            raise SystemExit(
                "no listener configured: set HOPCHAT_TLS_CERT and HOPCHAT_TLS_KEY, "
                "or HOPCHAT_ALLOW_PLAINTEXT=1 for development."
            )

        self._tasks.append(asyncio.ensure_future(self._housekeeping()))
        log.info("server public key (pin this in AppConfig.serverSigningKeyBase64): %s",
                 self.public_b64)

    async def _housekeeping(self) -> None:
        try:
            while not self._stopping.is_set():
                try:
                    await asyncio.wait_for(self._stopping.wait(), STATE_FLUSH_INTERVAL)
                except asyncio.TimeoutError:
                    pass
                self.expire_state()
                if self._dirty:
                    self.save_state()
        except asyncio.CancelledError:
            pass

    async def stop(self) -> None:
        self._stopping.set()
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        self._tasks = []
        for srv in self._servers:
            srv.close()
            try:
                await srv.wait_closed()
            except Exception:
                pass
        self._servers = []
        self.save_state()
        log.info("server stopped; state flushed")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def _amain() -> None:
    server = BootstrapServer(
        dev_fixed_code=os.environ.get("HOPCHAT_DEV_FIXED_CODE") or None,
    )
    await server.start(tls_cert=TLS_CERT, tls_key=TLS_KEY)

    stopped = asyncio.Event()
    loop = asyncio.get_event_loop()

    def _signal_handler() -> None:
        log.info("shutdown signal received")
        stopped.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except (NotImplementedError, RuntimeError):  # pragma: no cover
            pass

    await stopped.wait()
    await server.stop()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    try:
        import uvloop  # type: ignore
    except ImportError:
        pass
    else:
        try:
            uvloop.install()
            log.info("using uvloop")
        except Exception:  # pragma: no cover
            pass

    try:
        asyncio.run(_amain())
    except KeyboardInterrupt:  # pragma: no cover
        pass


if __name__ == "__main__":
    main()
