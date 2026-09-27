#!/usr/bin/env python3
"""
apns.py — Apple Push Notification service client for the hoppin relay.

Push exists for one reason: iOS will not run the app on its own often enough
to deliver mail promptly, and will not run it at all once the user force-quits.
A push wakes the app so it can fetch from the relay.

**Nothing about the message is sent to Apple.** The payload carries no sender,
no recipient, no text and no envelope id — only `mutable-content`, which lets a
Notification Service Extension on the device fetch the sealed envelope, decrypt
it locally, and replace the placeholder text. Apple therefore learns that
hoppin pushed to a device and when, which is the unavoidable cost of push, and
nothing else.

APNs speaks HTTP/2 only, which the standard library cannot do, so this module
needs `httpx[http2]`. It is imported lazily and the relay runs without it —
`build_push_sender()` returns a disabled sender that logs once, exactly like
the console SMS provider in development.

Authentication is a token, not a certificate: an ES256 JWT signed with a `.p8`
key downloaded from the Apple Developer portal. Apple rejects tokens older than
one hour and refuses more than one new token per 20 minutes, so it is cached
and refreshed on a 40-minute cadence.

Environment:
    APNS_KEY_PATH   path to AuthKey_XXXXXXXXXX.p8   (mode 600, never committed)
    APNS_KEY_ID     the 10-character key id
    APNS_TEAM_ID    the 10-character Apple team id
    APNS_TOPIC      the app's bundle identifier
    APNS_ENV        "production" (default) or "sandbox" for development builds
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

log = logging.getLogger("hoppin-bootstrap")

PRODUCTION_HOST = "https://api.push.apple.com"
SANDBOX_HOST = "https://api.sandbox.push.apple.com"

# Apple rejects a JWT older than 60 minutes and throttles minting to one per
# 20; 40 sits safely between the two.
TOKEN_LIFETIME = 40 * 60

# How long APNs should keep trying. Mail waits in the mailbox regardless, so a
# push that cannot be delivered within ten minutes has been overtaken by the
# next fetch anyway.
EXPIRATION = 10 * 60

REQUEST_TIMEOUT = 10.0


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class PushResult:
    """What the caller must do about a token, not what HTTP said.

    `drop` means Apple considers the token dead and it must be forgotten —
    keeping it would mean pushing to a device that uninstalled the app forever.
    """

    __slots__ = ("ok", "drop", "reason")

    def __init__(self, ok: bool, drop: bool = False, reason: str = ""):
        self.ok = ok
        self.drop = drop
        self.reason = reason

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "PushResult(ok=%r, drop=%r, reason=%r)" % (self.ok, self.drop, self.reason)


class PushSender:
    """Interface. `build_push_sender()` returns one of the two implementations."""

    enabled = False
    name = "none"

    async def send(self, token: str, sandbox: bool = False) -> PushResult:
        raise NotImplementedError  # pragma: no cover - interface

    async def close(self) -> None:
        return None


class DisabledPushSender(PushSender):
    """No credentials, or no HTTP/2 client. Says so once, then stays quiet."""

    enabled = False
    name = "disabled"

    def __init__(self, why: str):
        self.why = why
        self._warned = False

    async def send(self, token: str, sandbox: bool = False) -> PushResult:
        if not self._warned:
            self._warned = True
            log.warning("push disabled (%s); devices rely on background refresh", self.why)
        return PushResult(False, reason="disabled")


class APNsPushSender(PushSender):
    """Token-authenticated APNs client over HTTP/2."""

    enabled = True
    name = "apns"

    def __init__(self, key_pem: bytes, key_id: str, team_id: str,
                 topic: str, production: bool = True, client: Any = None):
        self.key = serialization.load_pem_private_key(key_pem, password=None)
        if not isinstance(self.key, ec.EllipticCurvePrivateKey):
            raise ValueError("APNs key must be an EC private key")
        self.key_id = key_id
        self.team_id = team_id
        self.topic = topic
        self.production = production
        self._client = client
        self._token: Optional[str] = None
        self._token_at = 0.0

    # -- JWT ---------------------------------------------------------------- #

    def _sign_es256(self, message: bytes) -> bytes:
        """JWS wants r||s fixed-width; `cryptography` hands back DER."""
        der = self.key.sign(message, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def bearer_token(self, now: Optional[float] = None) -> str:
        now = time.time() if now is None else now
        if self._token is not None and now - self._token_at < TOKEN_LIFETIME:
            return self._token

        header = {"alg": "ES256", "kid": self.key_id}
        claims = {"iss": self.team_id, "iat": int(now)}
        signing_input = "%s.%s" % (
            b64url(json.dumps(header, separators=(",", ":")).encode("utf-8")),
            b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8")),
        )
        signature = self._sign_es256(signing_input.encode("ascii"))
        self._token = "%s.%s" % (signing_input, b64url(signature))
        self._token_at = now
        return self._token

    # -- payload ------------------------------------------------------------ #

    @staticmethod
    def payload() -> Dict[str, Any]:
        """Deliberately contentless.

        `mutable-content` is what makes this work: the device's Notification
        Service Extension gets to replace the placeholder with the real sender
        and text after decrypting locally. Putting anything real here would
        hand Apple the metadata the rest of the design goes out of its way to
        withhold.
        """
        return {
            "aps": {
                "alert": {"loc-key": "NOTIFICATION_NEW_MESSAGE"},
                "sound": "default",
                "mutable-content": 1,
                # Also ask iOS to wake the app, so the mailbox is drained and
                # the receipt is on its way before the user taps anything. iOS
                # may decline; the banner is shown either way.
                "content-available": 1,
            }
        }

    def headers(self, now: Optional[float] = None) -> Dict[str, str]:
        expiry = int((time.time() if now is None else now) + EXPIRATION)
        return {
            "authorization": "bearer " + self.bearer_token(now),
            "apns-topic": self.topic,
            "apns-push-type": "alert",
            "apns-priority": "10",
            "apns-expiration": str(expiry),
        }

    # -- sending ------------------------------------------------------------ #

    def _host(self, sandbox: bool) -> str:
        return SANDBOX_HOST if (sandbox or not self.production) else PRODUCTION_HOST

    async def client(self) -> Any:
        if self._client is None:
            import httpx  # imported here so the relay starts without it

            self._client = httpx.AsyncClient(http2=True, timeout=REQUEST_TIMEOUT)
        return self._client

    async def send(self, token: str, sandbox: bool = False) -> PushResult:
        if not is_valid_token(token):
            return PushResult(False, drop=True, reason="malformed token")
        url = "%s/3/device/%s" % (self._host(sandbox), token)
        try:
            client = await self.client()
            resp = await client.post(url, headers=self.headers(),
                                     content=json.dumps(self.payload()).encode("utf-8"))
        except Exception as exc:  # network, TLS, HTTP/2 — never fatal
            log.warning("push failed: %s", exc.__class__.__name__)
            return PushResult(False, reason="transport")

        return classify(resp.status_code, resp.text)

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


def classify(status: int, body: str = "") -> PushResult:
    """Map an APNs reply onto what to do with the token.

    410 is Apple saying the app is gone from that device. 400 covers a batch of
    permanent mistakes, only some of which are about the token — the reason
    string separates them, because dropping a good token over a configuration
    error would silently stop push for that account.
    """
    if status == 200:
        return PushResult(True)

    reason = ""
    try:
        parsed = json.loads(body) if body else {}
        if isinstance(parsed, dict):
            reason = str(parsed.get("reason") or "")
    except ValueError:
        pass

    if status == 410 or reason in ("Unregistered", "BadDeviceToken", "DeviceTokenNotForTopic"):
        return PushResult(False, drop=True, reason=reason or "unregistered")
    return PushResult(False, reason=reason or ("http %d" % status))


def is_valid_token(token: str) -> bool:
    """APNs tokens are hex. Anything else never reaches Apple."""
    if not isinstance(token, str) or not 32 <= len(token) <= 200:
        return False
    if len(token) % 2:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in token)


def build_push_sender() -> PushSender:
    """Reads the environment. Missing credentials disable push, never crash.

    Unlike SMS — where starting without a provider in production would let the
    server hand out certificates nobody verified — push is a delivery
    optimisation. Refusing to boot over it would take the relay down for a
    feature that only makes messages arrive sooner.
    """
    key_path = os.environ.get("APNS_KEY_PATH", "").strip()
    key_id = os.environ.get("APNS_KEY_ID", "").strip()
    team_id = os.environ.get("APNS_TEAM_ID", "").strip()
    topic = os.environ.get("APNS_TOPIC", "").strip()
    if not (key_path and key_id and team_id and topic):
        return DisabledPushSender("APNS_* environment variables are not set")

    try:
        import httpx  # noqa: F401
    except ImportError:
        return DisabledPushSender("httpx[http2] is not installed")

    try:
        with open(key_path, "rb") as fh:
            key_pem = fh.read()
    except OSError as exc:
        return DisabledPushSender("cannot read %s: %s" % (key_path, exc.__class__.__name__))

    production = os.environ.get("APNS_ENV", "production").strip().lower() != "sandbox"
    try:
        sender = APNsPushSender(key_pem, key_id, team_id, topic, production=production)
    except (ValueError, TypeError) as exc:
        return DisabledPushSender("bad APNs key: %s" % exc.__class__.__name__)

    log.info("push enabled via APNs (%s, topic %s)",
             "production" if production else "sandbox", topic)
    return sender
