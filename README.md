# HopChat bootstrap server

`bootstrap.py` is the only server component. It does two jobs:

1. **Certificate authority** — verifies phone numbers by SMS OTP and issues
   Ed25519-signed identity certificates binding `phone -> signingKey + agreementKey`.
2. **Encrypted store-and-forward relay** — accepts sealed envelopes it cannot
   read, holds them per recipient, and hands them over on an authenticated
   long-poll fetch.

It implements §1–§5 of [`docs/DESIGN_CONTRACT.md`](../docs/DESIGN_CONTRACT.md).

**What it deliberately does not do:** no peer lists, no phone→IP lookup, no DHT
`store`/`findValue`, no hole punching, no unauthenticated state changes, and no
access to message plaintext. Every state-changing request needs a valid
certificate, a valid wire signature, a fresh timestamp and an unseen `txID`.

---

## Requirements

* Python 3.9+
* [`cryptography`](https://pypi.org/project/cryptography/) (the only hard dependency)
* `uvloop` is used automatically if it happens to be importable

```sh
./venv/bin/pip install -r requirements.txt
```

---

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `HOPCHAT_ENV` | `prod` | `dev` unlocks `ConsoleSMSProvider` and `HOPCHAT_DEV_FIXED_CODE` |
| `HOPCHAT_TLS_PORT` | `4443` | TLS listener port |
| `HOPCHAT_TLS_CERT` | – | PEM certificate chain; TLS starts only when cert **and** key are set |
| `HOPCHAT_TLS_KEY` | – | PEM private key |
| `HOPCHAT_PORT` | `4001` | Plaintext listener port |
| `HOPCHAT_ALLOW_PLAINTEXT` | – | `1` enables the plaintext listener (**development only**) |
| `HOPCHAT_BIND` | `0.0.0.0` | Bind address |
| `HOPCHAT_IDENTITY_KEY` | `./bootstrap_identity.key` | Server Ed25519 seed; created on first run, mode 600 |
| `HOPCHAT_STATE` | `./bootstrap_state.json` | Certificates + revoked serials + queued mail, mode 600 |
| `HOPCHAT_REPORTS` | `./reports.jsonl` | Abuse reports, one JSON object per line, mode 600 |
| `HOPCHAT_QUEUE_MAX_BYTES` | `536870912` | Global relay memory cap before oldest-first eviction |
| `HOPCHAT_DEV_FIXED_CODE` | – | Fixed OTP; **ignored unless `HOPCHAT_ENV=dev`** |
| `TWILIO_ACCOUNT_SID` / `TWILIO_AUTH_TOKEN` / `TWILIO_FROM` | – | Enables `TwilioSMSProvider` |

The server **refuses to start** if no listener is configured, and in `prod`
it refuses to start without Twilio credentials rather than silently falling
back to logging codes to the console.

---

## Running

### Development

```sh
export HOPCHAT_ENV=dev
export HOPCHAT_ALLOW_PLAINTEXT=1
export HOPCHAT_DEV_FIXED_CODE=123456
./venv/bin/python bootstrap.py
```

On startup it prints the line you need for the app:

```
server public key (pin this in AppConfig.serverSigningKeyBase64): <base64>
```

Smoke test it with the bundled client:

```sh
./venv/bin/python server/client.py --host 127.0.0.1 --port 4001 \
    --phone +351912345678 --code 123456
```

### Production

TLS only — never set `HOPCHAT_ALLOW_PLAINTEXT` on a public host.

```sh
export HOPCHAT_ENV=prod
export HOPCHAT_TLS_CERT=/etc/hopchat/tls/cert.pem
export HOPCHAT_TLS_KEY=/etc/hopchat/tls/key.pem
export TWILIO_ACCOUNT_SID=AC... TWILIO_AUTH_TOKEN=... TWILIO_FROM='+1...'
./venv/bin/python bootstrap.py
```

---

## TLS and the SPKI pin

```sh
./server/gen_tls_cert.sh hopchat.example.com ./tls 825
```

This writes `cert.pem` + `key.pem` (mode 600) and prints the pin. To extract the
pin from an existing certificate at any time:

```sh
openssl x509 -in cert.pem -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary \
  | openssl base64
```

The pin covers the **SubjectPublicKeyInfo**, not the certificate, so renewing
with the same key keeps the pin stable. Generate a **backup keypair** now, pin
both, and you can rotate without an app update.

---

## Twilio setup

1. Buy an SMS-capable number in the Twilio console.
2. Copy the Account SID and Auth Token from the project dashboard.
3. Put them in `/etc/hopchat/bootstrap.env` (mode 600, owned by root):

   ```
   TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   TWILIO_AUTH_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   TWILIO_FROM=+15551234567
   ```

The provider uses stdlib `urllib` only. On failure it logs the masked number and
an HTTP status — never the code, never the full number.

---

## Deploying

See [`hopchat-bootstrap.service`](hopchat-bootstrap.service) for a hardened
systemd unit; its header comments contain the full install sequence. Key points:

* Run as a dedicated unprivileged user with state in `/var/lib/hopchat` (mode 700).
* Stop with `SIGTERM` — the server flushes its state file before exiting, so
  queued mail survives a restart. State is also flushed every 10 s.
* Back up `bootstrap_identity.key`. **If you lose it, every installed app that
  pinned the old public key stops trusting the server** and all users must
  re-verify.

---

## Wiring the app

In `HopChat-1/App/AppConfig.swift`:

```swift
enum AppConfig {
    static let serverHost = "hopchat.example.com"
    static let serverTLSPort: UInt16 = 4443

    // The line bootstrap.py prints at startup.
    static let serverSigningKeyBase64 = "<server public key>"

    // The output of gen_tls_cert.sh (current + backup).
    static let serverSPKISHA256Base64: [String] = ["<pin>", "<backup pin>"]
}
```

---

## Tests and fixtures

```sh
./venv/bin/python -m unittest discover -s server -v
./venv/bin/python -m py_compile bootstrap.py
```

The suite starts a real server in-process on ephemeral ports (plaintext and TLS)
and drives it over real sockets via `server/client.py`.

`server/make_vectors.py` regenerates `docs/fixtures/crypto_vectors.json`, the
cross-language test vectors the Swift target consumes. It is fully
deterministic — every key derives from SHA-256 of a fixed ASCII label — so
re-running it must leave the file byte-identical, and a test asserts exactly
that. Regenerate it whenever the canonical encoding, certificate format,
envelope sealing or safety-number algorithm changes, and tell the app side.

---

## Operational notes

* **Logging**: phone numbers are masked (`+35191*****78`). OTP codes are logged
  only by `ConsoleSMSProvider` in dev. Envelope contents are never logged.
* **Limits**: 60 req/min per IP, 64 concurrent connections per IP, 15 s read
  timeout (the relay long-poll hold is exempt), 1 MiB max frame, 3 verify starts
  per phone per hour and 10 per IP, 30 certificate lookups per caller per hour.
* **Relay queue**: ≤ 500 envelopes and ≤ 20 MB per recipient, ≤ 900 KB per
  envelope, 7-day TTL, deduplicated by envelope id.
* **Abuse reports** land in `HOPCHAT_REPORTS` as JSON lines and contain
  user-consented plaintext evidence — treat that file as sensitive.
