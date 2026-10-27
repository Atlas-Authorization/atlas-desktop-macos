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
| `scripts/` | build, install, uninstall, pkg, notarize; `pam-install.sh` / `pam-uninstall.sh`, `filevault-mitigation.sh`, `build-passkey-helper.sh` |
| `pam/` | `pam_atlas.so` (C), its tests and the conversation core |
| `Sources/atlas-pam-helper`, `Sources/atlas-passkey` | the agent side of the PAM module; security-key registration CLI / helper app |
| `Tests/` | XCTest suite that reproduces the reference vectors in `protocol-vectors.json` |

Files on disk: `/Library/Application Support/Atlas/config.json` (no secrets), the device-bound bundle MAC key,
offline bundle and unlock state in the System keychain, the device key in the Secure Enclave
(software P-256 key in the Keychain only when there is no Secure Enclave).

## Build and test

```sh
swift build
swift test            # core, PAM helper protocol, passkey and CTAP2 tests; scrypt N=16384 needs optimisation, Package.swift keeps -O in debug
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
Other doors: SSH, `su`, `sudo` and Screen Sharing are covered by the PAM module below; the FileVault pre-boot unlock cannot be covered by anything third-party (see FileVault).

## PAM: sshd, su, sudo and screen sharing

`pam/` builds `pam_atlas.so`, the same Atlas step for the services that never touch the login window. It uses the same agent: the module starts
`atlas-pam-helper`, which runs the same `LoginGate` (same `config.json`, same offline bundle in the System keychain, same `break_glass_accounts` and
`enrolled_users` rules). Factors: push with number match, authenticator code, offline PIN + code. Passkeys are not offered in a terminal.

```sh
make -C pam                       # pam/build/pam_atlas.so (universal)
make -C pam test                  # unit tests of the conversation logic
sudo make -C pam itest            # real PAM stack, test build of the module, fake helper
bash pam/tests/install_test.sh    # install and uninstall scripts against a staged filesystem
sudo scripts/pam-install.sh --dry-run
sudo scripts/pam-install.sh
```

Behaviour: the module goes after the password module. It re-checks the password that module collected against OpenDirectory, so a wrong password never starts a push; no
password (a smart card, say) means refusal. Every failure refuses: helper missing or not root-owned, a garbled or late reply, a closed pipe, a timeout.
Break-glass: `pam-install.sh` refuses unless `config.json` lists a break-glass account (`--allow-no-break-glass` to override); that account skips Atlas in every service,
and the kill switch file `/Library/Application Support/Atlas/pam-disabled` (root-owned, not group/world-writable) turns the module into a pass-through without editing `/etc/pam.d`.

`pam-install.sh` edits `/etc/pam.d/{sshd,sudo,su,screensharing}` safely: each file must have the expected layout (an `auth ... pam_opendirectory.so` line to follow; the only `sufficient`
auth modules allowed ahead of it are `pam_smartcard.so` and `pam_rootok.so`), every file is checked before any is written, writes are atomic and read back, the first original is kept in
`/Library/Application Support/Atlas/pam-backup`, and if anything fails every file already changed is put back. `pam-uninstall.sh [--purge]` restores the original byte for byte (or removes only our
line if the OS has rewritten the file since). macOS updates may replace files in `/etc/pam.d`: re-run `pam-install.sh` (idempotent).
SSH: the PAM auth stack runs for password and keyboard-interactive logins; for key-only logins add `AuthenticationMethods publickey,keyboard-interactive` to `sshd_config`.

## FileVault

**Third-party code cannot gate the FileVault unlock.** With FileVault on, the Mac boots into a pre-boot environment that loads no third-party code (Apple, developer forums
thread 758542: "it boots to pre-boot environment that will not load any third-party code ... This affects authorisation plug-ins as well"). Neither this plugin nor `pam_atlas.so` can run there, and no
setting changes that. What is supported is to require Atlas at the **first login after the unlock**: by default macOS completes that login with the credentials typed into FileVault and
shows no login window (Apple: "the mechanics of that are not documented"). `DisableFDEAutoLogin` makes the login window appear after the unlock, so the person types the password again and the
login rule (`system.login.console`, which contains `AtlasMFA:check`) runs. `sudo scripts/filevault-mitigation.sh --enable` sets it (`com.apple.loginwindow`), verifies it and warns if the login rule does not contain
the Atlas mechanism; `--disable` and `--status` do the rest. Via MDM: a `com.apple.loginwindow` payload with `DisableFDEAutoLogin` true. The disk password still unlocks the disk by itself.

## Security keys (passkeys)

What works where, and why:

| Where | Works | Why / how |
|---|---|---|
| Login window, **security key over USB** | yes, `CTAP2Authenticator` | CTAP2 over USB HID, written against FIDO CTAP 2.1: no entitlement, no app identity needed. The panel asks the key's PIN. Unverified on real hardware (software key in the tests). |
| Login window, AuthenticationServices (`ASAuthorizationSecurityKeyPublicKeyCredentialProvider`, `ASAuthorizationPlatformPublicKeyCredentialProvider`) | **impossible** | AuthenticationServices needs a signed app with the `com.apple.developer.associated-domains` entitlement for the relying-party domain and the domain's apple-app-site-association file naming that app (Apple staff: "The application identifier (and entitlements in general) are part of your application's code signature", developer forums thread 737810). An authorization plugin is a bundle loaded into Apple's SecurityAgent/loginwindow process; entitlements belong to the main executable, so a plugin has no identity of its own to present. |
| Login window, Touch ID / iCloud Keychain **platform** passkeys | **impossible** | They live in the person's keychain, which is locked until the password has been used to log in: at the login window there is nothing to read. |
| User session, security key through AuthenticationServices | yes, with a signed helper | `scripts/build-passkey-helper.sh --domain <passkey domain> --team <TEAMID>` builds and signs `AtlasPasskey.app` (needs your Developer ID and a provisioning profile with Associated Domains); list `<TEAMID>.net.atlasauth.desktop.passkey` in the instance's native apps and Atlas serves it in the association file. Unsigned, macOS refuses its requests. |
| Registering a key | `atlas-passkey enrol` | `--via ctap` (default, no signing) or `--via authservices` (the signed app). You pass a code or push first. |

The closest alternative to a platform passkey at the login window is therefore a **security key** driven over CTAP2, with Touch ID or iCloud passkeys still usable after login in the user session.

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
- Security keys over CTAP2 against real keys (the tests use a software key); the PIN panel in the login window; the PAM module on a real sshd/sudo/screensharing stack beyond the CI test service; `pam-install.sh` against a real macOS `/etc/pam.d` after an OS update.
- The signed passkey helper app (needs your Developer ID, profile and association file).
- The `authenticate`-rule opt-in on every macOS version.
