# Threat Model

Status: current local CLI MVP baseline

Last reviewed: 2026-09-13

## Scope and method

This model covers the privileged-access path from a local PAM login through a
brokered SSH shell and lifecycle audit. It separates controls the MVP actually
implements from residual risks and product features that remain out of scope.
It does not assume that a local administrator, root, or a compromised PAM
process can be contained by application-level cryptography.

The original Phase 1 threat-model source is not present in the tracked
repository. Accepted ADRs refer to `T01` through `T09` and deferred risks
`D01` and `D02`, but do not reproduce every original definition. The table
below is therefore a constrained reconstruction from those ADR references,
the implementation, tests, and live runbooks. `T10` and `T11` are explicit
current additions. Review against any recovered Phase 1 source before treating
the reconstructed wording as historical text.

## Protected assets

- PAM users' login passwords and stored password hashes.
- Target privileged-account credentials and Vault key material.
- Audit integrity key and the authenticity/order of audit records.
- The authenticated identity and authorization decision.
- Pinned target identity and the SSH connection.
- Interactive terminal content and session resources.
- Target, account, policy, and duration configuration.

## Actors and attacker capabilities

- A local CLI caller may control command arguments and enter an arbitrary PAM
  password, but does not initially control the PAM OS account or process.
- A network attacker may observe, interrupt, redirect, or impersonate the path
  between the PAM host and target.
- A party obtaining one database file may inspect or modify it without also
  possessing its separately stored key.
- A local file attacker may try to replace paths, relax permissions, or supply
  malformed persisted rows.
- An authorized session user can see everything their target shell displays;
  this MVP does not constrain commands after the shell opens.

## Trust boundaries

| Boundary | What crosses it | Current trust statement |
| --- | --- | --- |
| A. PAM CLI user | Username, PAM password, target ID, terminal bytes | Arguments are untrusted; password uses non-echoing `getpass`; identity comes from authentication, not a CLI `user_id`. |
| B. PAM process / OS account | Plaintext passwords and decrypted target credential in memory | The process must be trusted. Host, account, process, debugger, and root compromise are outside application protection. |
| C. Local runtime filesystem | Keys and SQLite files | Provisioned directory is `0700`; artifacts are `0600`. The same OS account can read all of them. |
| D. Vault DB | Nonce and AES-GCM ciphertext | `vault.db` alone does not disclose the credential without the Vault key. |
| E. Vault key | 32-byte AES key | Separate file and canonical path from the Vault DB/audit key; not stored in a DB. It shares the lab runtime directory. |
| F. Audit DB | Structured records and HMAC chain | Local, append-only through the application port, tamper-evident when the audit key remains trusted. |
| G. Audit key | HMAC key | Separate path and bytes from the Vault key; shares the protected runtime directory. |
| H. PAM-to-target network | SSH handshake, authentication, PTY traffic | SSH protects the channel; a configured ED25519 SHA256 fingerprint is checked before password authentication. |
| I. Target SSH server | Host key, authentication, PTY/shell | Trusted only after pin verification and successful authentication. |
| J. Privileged target account | Shell authority on the target | It is intentionally privileged; command authorization and recording are outside this MVP. |

The lab co-locates `vault.key`, `audit.key`, and all databases under one
owner-only runtime directory for reproducibility. Encryption therefore
protects against **database-only theft or accidental DB disclosure**, not
copying the whole runtime directory. It is not a defense against PAM-host or
root compromise.

## Assumptions

- The PAM host, running Python process, OS account, installed dependencies,
  and root are trusted during a session.
- The operator obtains the target fingerprint through an independent trusted
  channel, such as the target console.
- The provisioned key files remain confidential and their owner-only
  permissions are meaningful on the underlying POSIX filesystem.
- The target SSH daemon and its host private key are administered correctly.
- The deployment is one local application instance; distributed concurrency
  and Byzantine storage are not assumed.
- The user runs the CLI on a real POSIX terminal when requesting an
  interactive shell.

## Threats and controls

| ID | Threat | MVP disposition and controls | Residual risk |
| --- | --- | --- | --- |
| T01 | A caller spoofs another PAM identity or learns whether a username, password, or disabled state caused login failure. | `AuthenticationService` returns an `AuthenticatedPrincipal`; CLI supplies no `user_id`; `AccessService` rejects principal/request mismatch before dependencies. Authentication uses a dummy hash and one generic public failure. | Python/runtime timing is not claimed perfectly indistinguishable. Host compromise can bypass the boundary. |
| T02 | The target credential is disclosed through CLI input, output, configuration, object representation, audit, or ordinary persistence. | Access never prompts for it. Config holds only `CredentialRef`; Vault returns a redacted `BrokerCredential`; no transcript is recorded; marker-based tests inspect outputs and raw DB files. | Credential necessarily exists briefly in process/library memory and reaches the verified SSH authentication call. |
| T03 | Theft or modification of Vault storage reveals or substitutes a target credential. | AES-256-GCM with a fresh 96-bit nonce; key stored outside the DB; authentication failure/tamper/wrong key fail closed; files are owner-only. | Co-located key and DB fall together if the runtime directory or OS account is compromised. No rotation/KMS/HSM. |
| T04 | A network attacker or wrong host receives the target password. | Exact pinned ED25519 SHA256 fingerprint is compared before `auth_password`; no TOFU/AutoAddPolicy path. | Incorrect initial fingerprint acquisition or compromise of the pinned target host is not solved. |
| T05 | Secrets leak through logs, errors, audit, representations, or terminal capture. | Generic CLI errors, redacted credential/hash representations, secret-free audit schema, no recording, and no password CLI flags. | Authorized users see their live terminal. Process memory and dependency internals remain trusted. |
| T06 | SSH, PTY, relay, timeout, or cleanup failure leaves resources/session state/terminal mode unsafe. | Strict state machine, owned-resource cleanup, raw-terminal context restoration, controlled failure results, and monotonic total-duration enforcement. | Cleanup is best effort when the OS or process is fatally compromised; detailed operator diagnosis is limited. |
| T07 | Persisted audit fields are modified or forged. | Deterministic HMAC-SHA256 chain authenticates all persisted fields; verification uses constant-time comparison; dedicated audit key. | Audit-key compromise permits recomputation. Local storage is neither WORM nor remotely witnessed. |
| T08 | Audit events are deleted, reordered, or truncated. | Sequence/link verification detects interior deletion and reordering. Direct copied-DB tampering was detected live. | Valid suffix truncation is not detectable without an external trusted chain-head anchor. |
| T09 | Missing, conflicting, failed, or approval-required policy accidentally grants access. | Missing and repository failure deny; explicit `DENY` overrides `ALLOW`; `REQUIRES_APPROVAL` cannot open because no approval engine exists. | Direct user policy is intentionally limited and does not express enterprise roles/attributes. |
| T10 | PAM login passwords are stolen at rest or guessed online. | Argon2id salted hashes, generic failures, and dummy-hash verification reduce at-rest and enumeration risk. | No rate limiting, lockout, MFA, remote identity provider, or protection after host/process compromise. |
| T11 | Disabled, missing, ambiguous, or malformed target/account configuration reaches Vault or SSH. | Domain validation and strict repository decoding fail closed; enabled target and exactly one enabled account are required before Vault/Broker use. | Local administrators with access to every runtime artifact remain trusted. |

## Addressed threats versus residual and out-of-scope risk

The controls above address the expected untrusted CLI caller, database-only
disclosure/tampering, network host impersonation, invalid configuration, and
ordinary adapter/session failure cases. Automated tests establish internal
ordering; the live record establishes behavior in one Fedora/libvirt/Debian
environment.

The following remain accepted residual risk:

- Complete PAM-host, PAM OS account, root, or running-process compromise
  (`D01` in the accepted ADRs).
- Sensitive live terminal content and target-side activity outside the
  broker's lifecycle metadata (`D02` in ADR-004).
- Plaintext secrets briefly resident in Python and SSH-library memory.
- Audit tail truncation and recomputation after audit-key compromise.
- Online password guessing without rate limiting or MFA.

The following are product-scope exclusions rather than claimed controls:
session recording/replay, command filtering, RBAC/ABAC, JIT/approvals, remote
identity, SSH certificates, key/credential rotation, remote/WORM audit,
external anchoring, HA, and distributed deployment. See
[Known Limitations](KNOWN_LIMITATIONS.md).

## Security evidence boundaries

Tests and code review support specific properties; they do not prove the
absence of every vulnerability. Live denial after a bad host pin demonstrates
the integrated result, while the automated connector test establishes the
stronger internal fact that password authentication receives zero calls after
a mismatch. Likewise, local HMAC verification demonstrates tamper evidence,
not tamper-proof storage.
