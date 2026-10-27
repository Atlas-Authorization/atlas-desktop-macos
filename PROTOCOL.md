# Atlas workstation agent protocol (version 1)

What the Windows credential provider and the macOS authorization plugin implement.
The reference vectors in `shared/protocol-vectors.json` are produced by the Atlas
server code; both agents' unit tests must reproduce them.

All calls are `POST` with JSON bodies to `<instance URL>/v1/client/desktop_mfa/...`
with the header `X-Publishable-Key: <publishable key>`. Responses are JSON; errors are
`{ "errors": [ { "code", "message", "meta"? } ] }`.

## Keys and encodings

- The device key is an ECDSA P-256 key pair created on the workstation, ideally
  non-exportable in hardware (Windows: TPM through CNG "Microsoft Platform Crypto
  Provider"; macOS: Secure Enclave). It must support signing (ES256) and ECDH key
  agreement. The public half is sent as a JWK `{ "kty":"EC","crv":"P-256","x","y" }`.
- Hardware that cannot use one key for both signing and key agreement (typical for TPM keys) creates a
  **second P-256 key (ECDH)** and sends its public JWK as `seal_public_key` at enrolment. Offline bundles are
  then sealed to that key instead of the signing key; opening them is identical (ECDH with the seal private key).
  Without `seal_public_key` bundles are sealed to the signing key.
- Signatures: ECDSA over SHA-256 of the UTF-8 message, **IEEE P1363** (raw `r || s`,
  64 bytes), base64url without padding.
- Every base64url value is unpadded.

## Signed message

```
atlas-desktop:v1:<purpose>:<instance id>:<key id>:<nonce>[:<extra>]
```

`instance id` is returned by enrolment (`device.instance_id` is not exposed; the agent
config carries it as `instance_id`, see `config` below). `key id` is the JWK `x` value for
`enroll` and the **device id** (`ddv_...`) for everything else.

| call | purpose | nonce | extra |
|---|---|---|---|
| `enroll` | `enroll` | the enrolment code | none |
| `nonce` | unsigned: body `{ "device_id" }` -> `{ "nonce" }` | | |
| `sync` | `sync` | from `nonce` | held bundle id, or `-` when none |
| `pin` | `pin` | from `nonce` | base64url SHA-256 of the PIN string |
| `challenges` (start) | `challenge` | from `nonce` | the factor name |
| `challenges/:id/verify` | `verify` | the challenge id | none |
| `report` | `report` | from `nonce` | base64url SHA-256 of the `payload` string as sent |
| `passkeys/options` | `passkey_options` | from `nonce` | the proof challenge id |
| `passkeys/:id/enrol` | `passkey_enrol` | the registration id | none |

A nonce is single use and lives five minutes.

## Calls

### `enroll`
Body: `{ code, public_key, seal_public_key?, signature, hostname, platform ("windows"|"macos"), agent_version, pin }`.
`pin` is 6-12 digits (required when the policy requires an offline PIN).
Response 201: `{ device: { id, ... }, bundle_mac_key, offline_otp_uri }`.
Persist `device.id` and `bundle_mac_key` (protect it: DPAPI/Keychain; it authenticates
offline bundles). Show `offline_otp_uri` to the user once if they want it in an
authenticator app.

### `sync` (run at start-up, at each network change, and about hourly)
Body: `{ device_id, nonce, signature, held_bundle_id? }`.
Response: `{ status, required, allowed_factors, offline: { enabled, grace_hours, pin_required, pin_set, keep_cache, bundle_valid, bundle }, server_time }`.
- 403 with `meta.device_status = "revoked"`: wipe the offline cache and refuse the factor flow
  (fail closed for that user's MFA: the policy owner decides, the agent must not fall back to password-only for a user that was required).
- `keep_cache = false`: delete any cached bundle.
- `bundle` present: verify `mac` (below), store it, replace the old one.
- Cache the last good `required` and `allowed_factors` so a workstation that is offline knows whether
  the user needed MFA. If the user was required and there is no valid offline bundle, offline login is refused.

### Starting a step-up (`challenges`)
Body: `{ device_id, nonce, signature, factor }`, factor in `allowed_factors`.
Response 201: `{ id, factor, expires_at, number_match?, passkey_options? }`.
- push: display `number_match` big on the login screen. The user picks it on their phone. Poll `verify`
  (no body besides device_id + signature) every 2 s until `status` is `verified` or `failed`.
- totp: send `code` (6 digits) to `verify`.
- passkey: run a WebAuthn assertion with `passkey_options` and send
  `assertion: { challenge, credential_id, authenticator_data, client_data_json, signature }` (base64url).

### `challenges/:id/verify`
Body: `{ device_id, signature, code?, assertion? }`. Response `{ status: "pending"|"verified"|"failed" }`.
422 = wrong code (retry; five wrong answers end the challenge with 429). Only `verified` lets the login continue.
A challenge verifies once.

### `pin` / `report`
`pin`: `{ device_id, nonce, signature, pin }`. `report`: `{ device_id, nonce, signature, payload }` where
`payload` is a JSON string of up to 200 events `{ at (epoch ms), outcome ("success"|"failure"), bundle_id?, reason? }`.
Upload queued offline events on the next successful sync.

## Passkeys (security keys)

The `passkey` factor needs the policy's `passkey_rp_id` / `passkey_scope` / `passkey_require_uv` (see `sync` -> `passkey`:
`{ rp_id, origin, scope, user_verification, device_passkeys }`). The origin is always `https://<rp_id>`.

- **Assertion at sign-in.** `challenges` with factor `passkey` returns `passkey_options`:
  `{ challenge, rpId, origin, allowCredentials: [{type, id, transports}], userVerification, timeout }`. The agent builds
  `clientDataJSON` = `{"type":"webauthn.get","challenge":<challenge>,"origin":<origin>,"crossOrigin":false}` (or lets the platform build
  it, then checks it says exactly that), has the authenticator sign `authenticatorData || SHA-256(clientDataJSON)` and posts
  `assertion: { challenge, credential_id, authenticator_data, client_data_json, signature }` (base64url) to `verify`.
  The agent refuses options whose `origin` is not `https://` + `rpId` or whose challenge is under 16 bytes.
- **Registering a key through this workstation.** First pass any other factor (push or code) on this device: that verified challenge is
  the *proof*. Within 5 minutes call `passkeys/options` `{ device_id, nonce, signature, proof_challenge_id }` (signed with `extra` = the proof id)
  -> `201 { registration_id, passkey_options }` (WebAuthn creation options plus `origin`). Create the credential, then
  `POST passkeys/:registration_id/enrol` `{ device_id, signature, credential: { challenge, attestation_object, client_data_json }, name?, transports? }`
  (the signature covers the registration id, which is single use) -> `201 { id, ... }`. One proof registers one key; a device holds at most 10.
  A key registered this way answers only this factor and never a web sign-in.

## Offline bundle

`bundle = { bundle_id, generation, issued_at, expires_at, sealed, mac }`.

1. Check `mac = base64url(HMAC-SHA256(bundle_mac_key, "atlas-desktop-bundle:v1:" + device_id + ":" + bundle_id + ":" + generation + ":" + expires_at + ":" + sealed))`
   in constant time. Reject the bundle if it does not match.
2. Store `sealed` as received (it only opens with the device key). Opening it:
   `raw = base64url_decode(sealed)`; `raw[0] = 0x01`; `eph = raw[1..66]` (uncompressed P-256 point, `0x04 || X || Y`);
   `iv = raw[66..78]`; `ct = raw[78..len-16]`; `tag = raw[len-16..]`.
   `secret = ECDH(device private key, eph)` (32 bytes, the X coordinate);
   `key = HKDF-SHA256(ikm = secret, salt = eph (the 65 bytes), info = "atlas-desktop-offline-bundle-v1", 32)`;
   plaintext = AES-256-GCM-decrypt(key, iv, ct, tag, no AAD).
3. Plaintext is JSON:
   `{ v:1, bundle_id, device_id, user_id, generation, issued_at, expires_at, pin_required, pin, totp:{ secret (base32), digits:6, period:30, algorithm:"SHA1" } }`
   with `pin = { alg:"scrypt", N, r, p, salt (b64url), hash (b64url, 32 bytes) } | null`.

## Offline unlock

Allowed only while `now < expires_at` **and** the system clock has not moved backwards past `issued_at`
(keep a monotonic high-water mark of the last time seen; refuse when `now` is earlier than it by more than 5 minutes).
1. If `pin_required`, the user enters the PIN: `scrypt(pin, salt, N, r, p, 32)` must equal `hash` (constant time).
2. The user enters the 6-digit TOTP from their authenticator app (the seed is also in the `offline_otp_uri`
   from enrolment). Accept the current step +/- 1; remember the last accepted step and refuse any step <= it (replay).
3. After five wrong attempts lock offline unlock for 15 minutes (persist the counter).
Every attempt is appended to a local queue and sent with `report` on the next successful sync.

## Agent configuration (file, written by the installer)

```json
{ "instance_url": "https://auth.example.com", "publishable_key": "pk_live_...", "instance_id": "ins_...",
  "device_id": "ddv_...", "device_key_id": "<store label>", "enrolled": true }
```
`device_id` is empty until enrolment. The bundle MAC key and the offline bundle live in the platform secret
store (DPAPI machine scope / Keychain), never in this file.

## Fail-closed rules

- A user whose cached `required` is true never logs in without a factor, online or offline.
- If `required` is unknown for the user (never synced), allow the underlying password login only if the install
  was configured with `"fail_open_when_never_synced": true` (default false).
- Never log a code, PIN, number match, bundle or key.
