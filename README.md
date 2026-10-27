# Atlas desktop sign-in MFA for macOS

A macOS authorization plugin (`AtlasMFA.bundle`) that asks for a second factor at the login window,
after the password was verified. Factors: push approval with number match, TOTP code, passkey
(only when a WebAuthn callback is wired in; otherwise reported as unsupported) and an offline
PIN + authenticator code for when the Atlas server is unreachable. The wire protocol is in
[PROTOCOL.md](PROTOCOL.md).

The default is to **fail closed**: a user who needs MFA never gets in without a factor.

## Layout

| path | what |
|---|---|
| `Sources/AtlasDesktopCore` | all logic: protocol client, signed messages, offline bundle (HMAC + ECIES), scrypt, TOTP, offline-unlock state machine, `LoginGate` orchestrator, device key (Secure Enclave or Keychain fallback), Keychain store |
| `Sources/atlas-enroll`, `atlas-sync` | CLI: enrol this Mac; hourly sync (run by a LaunchDaemon) |
| `Plugin/` | thin Objective-C shim (`AuthorizationPluginCreate`, one mechanism `check`) + Swift panel UI. Compiled together with the core by `scripts/build-plugin.sh` |
| `launchd/` | `net.atlasauth.desktop.sync.plist` (at load, hourly, and on network-interface changes) |
| `scripts/` | build, install, uninstall, pkg, notarize |
| `Tests/` | XCTest suite that reproduces the reference vectors in `protocol-vectors.json` |

Files on disk: `/Library/Application Support/Atlas/config.json` (no secrets), the device-bound bundle MAC key,
offline bundle and unlock state in the System keychain, the device key in the Secure Enclave
(software P-256 key in the Keychain only when there is no Secure Enclave).

## Build and test

```sh
swift build
swift test            # 36 tests; scrypt N=16384 needs optimisation, Package.swift keeps -O in debug
bash scripts/build-plugin.sh    # -> build/AtlasMFA.bundle (arm64 + x86_64) and build/bin/atlas-{sync,enroll}
bash scripts/build-pkg.sh       # -> dist/AtlasDesktopMFA-<version>-unsigned.pkg
```

Signing happens only when you set the identities; nothing is ever faked:

```sh
ATLAS_CODESIGN_IDENTITY="Developer ID Application: ..." bash scripts/build-plugin.sh
ATLAS_INSTALLER_IDENTITY="Developer ID Installer: ..."  bash scripts/build-pkg.sh --sign
ATLAS_NOTARY_KEY_ID=... ATLAS_NOTARY_ISSUER=... ATLAS_NOTARY_KEY_PATH=AuthKey.p8 bash scripts/notarize.sh dist/AtlasDesktopMFA-<version>.pkg
```
(`ATLAS_NOTARY_PROFILE` for a stored notarytool keychain profile also works.)
`OUT`, `DIST`, `SCRATCH` environment variables move the output directories.

## Install

1. Enrol first: `sudo atlas-enroll --instance-url https://auth.example.com --publishable-key pk_live_... --instance-id ins_... --code <enrolment code> --user <local account>`
   (PIN is prompted, or `ATLAS_ENROLL_PIN`; the code can come from `ATLAS_ENROLL_CODE`). It prints the offline authenticator URI once.
2. `sudo scripts/install.sh --dry-run` shows the rule edit without writing anything, then `sudo scripts/install.sh`.
   It backs up the original rule to `/Library/Application Support/Atlas/backup/`, inserts `AtlasMFA:check` after the
   last `builtin:authenticate*` in `system.login.console`, verifies the edited plist with `plutil`, and is safe to re-run.
   `--with-unlock-rule` additionally edits the shared `authenticate` rule (admin prompts and unlock): opt-in, wider blast radius.
3. Or use the pkg; its postinstall does step 2 only when the Mac is already enrolled.

Test on a spare machine or VM with SSH enabled and a second admin account before rolling out.

## Break-glass account

Before rolling out, create a dedicated local admin (for example `atlas-breakglass`), give it a long random password,
and vault that password offline. Put the account name in `config.json`:

```json
"break_glass_accounts": ["atlas-breakglass"]
```

For listed accounts only, the plugin skips Atlas (no push, no code). Their password is still verified first, every use
is written to the unified log (`log show --predicate 'subsystem == "net.atlasauth.desktop"'`, "break-glass login") and a
`break_glass:<account>` event is queued and reported on the next sync. The list is empty by default. Treat any use as an incident.

## Wrong passwords never reach Atlas

The mechanism sits after `builtin:authenticate` but does not trust that: the password from the authorization context is
re-verified against OpenDirectory (`ODRecord verifyPassword`) before any Atlas call. If the password is absent (for example
smart-card or auto-login) or wrong, the login is denied and no network request is made (`LoginGate.begin(passwordVerified:)`,
covered by a test). C buffers holding the password are wiped; the brief Swift `String` copy cannot be.

## Installer safety

`install.sh` refuses unless the rule has the expected shape: `loginwindow:login` < `builtin:login-begin` < `builtin:authenticate*` <
`AtlasMFA:check`, which must come before `builtin:login-success`, `loginwindow:success`, HomeDir/MCX/CryptoTokenKit mechanisms and
`loginwindow:done`, with no credential mechanism after it. The same check runs on the edited plist before writing and on the rule read back
after writing; if the read-back fails the saved original is written back. Nothing in the login rule other than `builtin:auto-login` /
`forward-login` (which precede authentication and are denied by the password re-check) can start a session without passing the mechanism.
Not covered: sessions that do not use the login window rule (SSH, `su`, Screen Sharing/Remote Management login, FileVault pre-boot unlock).

## Offline behaviour

Not-enrolled accounts pass through. For an enrolled account the gate fails closed: if there is neither a cached `required` state
nor, when `required` is true, a valid unexpired offline bundle, login is refused. A Mac that has never synced is refused for enrolled
accounts unless `fail_open_when_never_synced` is set. Plan for this with the break-glass account and a long offline grace period.

## Recovery

We have **not** verified what macOS does when the rule lists a mechanism whose bundle is missing; assume it fails closed
(you stay at the login window). So removing the bundle alone is not a guaranteed fix; restore the rule too.

1. SSH (enable Remote Login beforehand) or another admin session, or the break-glass account at the console:

   ```sh
   sudo scripts/uninstall.sh      # restores the saved original rules, removes bundle, helpers, LaunchDaemon
   # by hand:
   sudo security authorizationdb write system.login.console < "/Library/Application Support/Atlas/backup/system.login.console.original.plist"
   sudo rm -rf /Library/Security/SecurityAgentPlugins/AtlasMFA.bundle
   sudo security authorizationdb remove system.login.console   # last resort: OS default rule
   ```

2. Recovery mode (Apple silicon: hold the power button, Options; Intel: Cmd-R), then Terminal. Unlock and mount the Data volume
   and run `uninstall.sh --data-volume "/Volumes/Macintosh HD - Data"`. This only removes files (bundle, LaunchDaemon, helpers);
   it cannot edit the authorization database, so if the login window still fails, restore the rule over SSH after boot.
   Replacing `/var/db/auth.db` on the Data volume with a pre-install copy is a possible, unverified alternative.
3. Apple silicon has no single-user mode. On Intel, target disk mode from another Mac gives file-level access like (2).

## Behaviour and security notes

- The device key signs every request (ES256, P1363) and opens the offline bundle (ECDH + HKDF + AES-256-GCM); the private key never leaves the Secure Enclave.
- Bundle MAC is checked in constant time on receipt and again before use; an unverifiable bundle is ignored.
- Offline unlock: bundle unexpired, clock not moved back more than 5 minutes past the high-water mark or the issue time, PIN (scrypt) and TOTP (+/-1 step, replay refused), 5 failures lock for 15 minutes, state persisted before an allow is returned.
- Revoked device: cache wiped, login refused. Never-synced users are refused unless `"fail_open_when_never_synced": true` is set in `config.json`.
- `enrolled_users` (optional, set by `--user`) limits MFA to those local accounts; others pass through. Without it, every account is gated.
- Codes, PINs, number matches, bundles and keys are never logged. Transport is https only.
- The Keychain items are created with an access list that lets any local process read them, because the login-window agent is not the process that created them; the protection is that they sit in the System keychain behind root-only writes and the device key is hardware bound.

## Not verified

- Behaviour inside a real loginwindow / SecurityAgent (UI placement, key and System-keychain access from that context, focus, FileVault pre-boot interplay).
- Secure Enclave key creation and ECDH on real hardware (tests use the software key; the SE path is compiled, not exercised).
- Code signing, hardened-runtime loading, notarisation and the signed pkg path.
- Passkey (WebAuthn) at the login window: only the callback hook exists.
- The `authenticate`-rule opt-in on every macOS version.
