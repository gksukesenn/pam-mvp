# Product Requirements Document

Status: current MVP baseline after Phase 9

Last reviewed: 2026-09-13

## Document roles

This PRD defines what the MVP must do and why. The
[Threat Model](THREAT_MODEL.md) defines the attacks and residual risks. The
[ADRs](adr/ADR-002-vault-key-strategy.md) explain major technical choices. The
[Domain Model](DOMAIN_MODEL.md) defines business concepts and invariants.

The original Phase 1 PRD was not present in the tracked repository when this
reviewable baseline was created. Requirements below are reconstructed only
from accepted ADRs, shipped code, tests, runbooks, and completed live
validation. They describe the product that exists; they do not invent an
enterprise scope.

## Problem statement

An operator needs temporary interactive access to a privileged account on a
managed Linux server without entering or learning that account's password at
access time. The broker must authenticate the PAM user, authorize the exact
identity/target/action tuple, protect the reusable target credential at rest,
verify the SSH server identity before sending that credential, bound the
session duration, and produce secret-free lifecycle evidence.

## Goals

- Demonstrate one complete, inspectable privileged SSH access path.
- Bind access decisions to an authenticated local identity.
- Fail closed on absent/denying policy, disabled/malformed configuration,
  unavailable secrets, and host-key mismatch.
- Keep target credentials out of CLI arguments, configuration storage, audit
  records, and terminal transcripts.
- Encrypt target credentials in local persistent storage.
- Broker a real interactive PTY session and restore the local terminal safely.
- Persist structured, tamper-evident access/session lifecycle audit.
- Provide a reproducible Debian/libvirt lab and isolated negative scenarios.
- Keep domain/application code independent of SQLite, Paramiko, Argon2,
  AES-GCM, terminal file descriptors, and virtualization.

## Non-goals

The MVP does not provide RBAC/ABAC, JIT access, approvals, MFA, external
identity federation, brute-force controls, credential/key rotation, SSH
certificates, recording/replay, command filtering, remote/WORM audit, external
chain anchoring, a web interface, high availability, or distributed storage.
These omissions are classified in [Known Limitations](KNOWN_LIMITATIONS.md).

## Actors and personas

| Actor | Need / responsibility |
| --- | --- |
| PAM user | Authenticate locally and request an allowed target session without receiving the target password. |
| Lab/operator administrator | Build the target, verify its fingerprint out of band, provision local data/keys, and run audit verification. |
| PAM process | Enforce authentication, authorization, secret retrieval, SSH ordering, lifecycle, and audit. |
| Managed SSH target | Present the pinned host key, authenticate the configured privileged account, and host the PTY shell. |
| Security reviewer | Trace controls from threats and requirements to code, automated tests, and environment-specific live evidence. |

## MVP scope

- One local Linux CLI application instance.
- Local PAM users stored in `auth.db`.
- Direct user-target-action policies and non-secret target/account
  configuration stored in `config.db`.
- One unambiguous privileged account per target, referenced by `CredentialRef`.
- Target password encrypted in `vault.db`; Vault key held in a separate file.
- Separate HMAC key and `audit.db` for audit integrity.
- Password-authenticated SSH to a pinned Linux target through Paramiko.
- Interactive POSIX terminal relay with a maximum total duration.
- One-shot local provisioning, isolated negative-lab preparation, and audit
  verification tools.

## Functional requirements

Priority meanings: **Must** is required for the supported MVP flow; **Should**
is valuable hardening or reproducibility that does not redefine the product.

| ID | Priority | Requirement | Threats | Status / evidence |
| --- | --- | --- | --- | --- |
| FR-001 | Must | Provision a fresh lab runtime without accepting either password as a command-line argument. | T02, T03, T05 | Implemented by `src.tools.provision_lab`; interactive and one-shot tests. |
| FR-002 | Must | Authenticate an active local PAM user with a password and return a non-secret principal; invalid, unknown, inactive, or repository-failure cases use the same public failure. | T01, T10 | `AuthenticationService`; authentication and CLI tests. |
| FR-003 | Must | Create privileged access only for the authenticated principal; caller-controlled identity must not authorize access. | T01 | CLI principal binding plus `AccessService` mismatch guard; automated spoofing tests. |
| FR-004 | Must | Evaluate direct user/target/action policy with default DENY, explicit-DENY precedence, and unsupported approval failing closed. | T09 | `PolicyEvaluator`; precedence and repository-failure tests; DENY live validation. |
| FR-005 | Must | Resolve a persisted enabled target and exactly one enabled privileged-account reference before secret retrieval. | T11 | SQLite config repositories and `AccessService`; missing/disabled/ambiguous/corrupt tests; disabled live validation. |
| FR-006 | Must | Store the target credential encrypted and resolve it only through the Vault after ALLOW and configuration checks. | T02, T03, T05 | AES-GCM/SQLite Vault and access ordering tests; successful live session. |
| FR-007 | Must | Verify the configured SSH host-key fingerprint before password authentication and reject mismatches without authentication. | T04 | Paramiko connector ordering test proves zero auth calls; bad-pin live validation. |
| FR-008 | Must | Open a PTY/shell only after verified SSH authentication, relay bytes without recording, close owned resources, and restore local terminal mode. | T05, T06, D02 | Channel/broker/relay/terminal tests; successful and failure live validation. |
| FR-009 | Must | Enforce a positive maximum total session duration using monotonic elapsed time; timeout is a controlled close. | T06 | Relay/access/CLI tests; five-second live validation. |
| FR-010 | Must | Persist secret-free access/session lifecycle events through an append-only application port and verify an HMAC chain with a dedicated key. | T05, T07, T08 | SQLite audit and integrity tests; baseline/tampered live verification. Current event scope is defined below. |
| FR-011 | Must | Provide a secret-free CLI with deterministic results for success, authentication failure, denial, session failure, and startup failure. | T01, T02, T05 | `src.main`; CLI tests and live matrix. |
| FR-012 | Should | Create isolated negative-scenario copies without mutating the working baseline. | T04, T09, T11 | `prepare_negative_lab`; copy/permission/baseline tests and manual runbook. |
| FR-013 | Should | Let another Linux engineer build and validate the lab without access to private credentials or conversation history. | T06 | `LAB_SETUP.md` and runbooks; operator execution remains manual. |

## Non-functional and security requirements

| ID | Priority | Requirement | Threats | Status / evidence |
| --- | --- | --- | --- | --- |
| NFR-SEC-001 | Must | Persist PAM passwords only as Argon2id hashes with library-generated salts. | T01, T10 | Real hasher/repository tests and raw-file checks. |
| NFR-SEC-002 | Must | Use AES-256-GCM with a fresh 96-bit secure-random nonce for every target-secret encryption. | T02, T03 | Cipher tests cover size, freshness, tamper, and wrong key. |
| NFR-SEC-003 | Must | Keep Vault/audit key paths and key bytes distinct; persist neither key in any database. | T03, T07 | Composition/provisioning checks and raw-file tests. |
| NFR-SEC-004 | Must | Do not print, log, audit, or persist plaintext passwords, key bytes, target credential objects, or terminal content; redact password/hash/credential representations. | T02, T05, D02 | Marker-based CLI/DB/audit/repr tests cover the supported paths and secret-bearing public types. |
| NFR-SEC-005 | Must | Fail closed on dependency/storage errors and never reinterpret corrupt or unavailable policy/config/Vault data as ALLOW. | T03, T09, T11 | Repository/evaluator/access negative tests. |
| NFR-SEC-006 | Must | Compare the pinned host key before target authentication; do not use TOFU. | T04 | Connector behavior and source guard tests. |
| NFR-SEC-007 | Must | Authenticate all persisted audit fields in a deterministic HMAC-SHA256 chain and compare MACs safely. | T07, T08 | Canonicalization, sequence, tamper, wrong-key, and `compare_digest` tests. |
| NFR-SEC-008 | Must | Create provisioned runtime directories as `0700` and runtime DB/key artifacts as `0600`; reject or tighten unsafe files according to adapter policy. | T03, T05, T07 | Provisioning/scenario/database-permission tests and lab metadata inspection. |
| NFR-SEC-009 | Must | Restore terminal attributes after normal completion, denial, timeout, I/O failure, SSH failure, or exception. | T06 | Terminal context and CLI exception tests. |
| NFR-SEC-010 | Must | Keep expected user-facing failures generic and secret-free. | T01, T02, T05 | Auth and CLI failure-output tests. Cause-specific protected operator observability is deferred hardening. |
| NFR-SEC-011 | Should | Make even encrypted-secret container representations safe for incidental debugging and never intentionally print ciphertext. | T05 | No production logging path exists, but `EncryptedSecret` representation hardening remains S-005 in the final gap audit. |
| NFR-ARCH-001 | Must | Domain and application code must not depend on infrastructure frameworks or CLI/virtualization details. | All | Import inspection and composition tests. |
| NFR-TEST-001 | Must | Automated tests must not require or contact the real target. | T06 | Network boundary is replaced with fakes/monkeypatching. |
| NFR-PORT-001 | Must | Supported local terminal platform is Linux/POSIX. | D02 | `termios`, file-descriptor, and `select` adapters; explicitly limited. |

## Current audit contract

Production currently emits exactly these event types:

- `ACCESS_ALLOWED`
- `ACCESS_DENIED`
- `SESSION_OPENING`
- `SESSION_ACTIVE`
- `SESSION_CLOSED`
- `SESSION_FAILED`

The current MVP does **not** emit pre-authentication `AUTH_SUCCESS` or
`AUTH_FAILURE`, a separate `ACCESS_REQUESTED`, or cause-specific
`HOST_KEY_MISMATCH`, Vault, or target-unavailable event types. Broker-open
failures use the generic `SESSION_FAILED` reason `broker_open_failed`.
User-facing errors are deliberately generic. Broader protected operator
observability is Phase 10 hardening, not a current claim. See the revised
[ADR-004](adr/ADR-004-audit-integrity.md).

## Acceptance criteria

The MVP is accepted when:

1. A provisioned active PAM user can authenticate and an explicitly allowed
   request can open the configured target shell without prompting for the
   target password.
2. `whoami` and `hostname` on the tested target confirm the configured account
   and server; logout returns safely and restores the terminal.
3. Wrong PAM password, policy DENY, disabled target/account, bad host pin, and
   wrong target password open no shell and return the documented safe result.
4. A short total-duration limit closes an active session with a controlled
   success result and terminal restoration.
5. Audit verification succeeds for the baseline, fails for an isolated
   directly modified copy, and still succeeds for the untouched baseline.
6. Automated tests validate the security ordering without live network use.
7. No password, key, transcript, or plaintext credential is added to tracked
   documentation or runtime-independent source configuration.

The environment-specific completion record is in
[LIVE_VALIDATION.md](LIVE_VALIDATION.md).

## Critical-control traceability

Threat mappings T01-T09 are reconstructions constrained by the accepted ADRs;
their original Phase 1 wording was unavailable. See the mapping notice in the
[Threat Model](THREAT_MODEL.md).

| Control | Threat | Requirement | ADR | Implementation | Automated evidence | Live evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Authenticated identity binding | T01 | FR-002, FR-003 | ADR-003 | `AuthenticationService`, `AuthenticatedPrincipal`, `AccessService.handle` | Authentication, authenticated-flow, mismatch, and CLI tests | Wrong PAM password; successful login. |
| Fail-closed DENY | T09 | FR-004, NFR-SEC-005 | ADR-003 | `PolicyEvaluator`, access denial path | Default/explicit/conflict/repository-failure tests | Policy-DENY scenario. |
| Disabled target/account | T11 | FR-005, NFR-SEC-005 | ADR-003 context; current implementation | `AccessService`, SQLite config repositories | Ordering, malformed, ambiguous, and scenario-copy tests | Disabled-target and disabled-account scenarios. |
| Encrypted Vault | T02, T03 | FR-006, NFR-SEC-002 | ADR-002 | `AesGcmSecretCipher`, `SQLiteVault` | Nonce/tamper/wrong-key/raw-file tests | Successful session; wrong-target-password failure. |
| Vault/audit key separation | T03, T07 | NFR-SEC-003 | ADR-002, ADR-004 | `RuntimeSettings`, composition, `FileKeyProvider` | Same-path/same-bytes and DB-absence tests | Runtime metadata only; no key contents inspected. |
| Host key before authentication | T04 | FR-007, NFR-SEC-006 | ADR-005 | `ParamikoSshConnector`, `verify_pinned_host_key` | Host mismatch produces zero `auth_password` calls | Bad-host-key scenario proves denial, not call ordering. |
| Credential hiding/injection | T02, T05 | FR-006, FR-011, NFR-SEC-004 | ADR-002 | Vault -> `BrokerCredential` -> connector | Parser/getpass/repr/raw-DB/output tests | Shell opens without target-password prompt. |
| Session lifecycle | T06 | FR-008, NFR-SEC-009 | ADR-004, ADR-005 | `Session`, broker/channel/relay, terminal context | Transition, cleanup, relay, terminal, and CLI tests | Normal logout and failure scenarios. |
| Maximum duration | T06 | FR-009 | ADR-004 lifecycle intent | monotonic terminal relay and close reason | Timeout/activity/no-wall-clock tests | Five-second controlled close. |
| Audit tamper evidence | T07, T08 | FR-010, NFR-SEC-007 | ADR-004 | `SQLiteAuditRepository`, canonical HMAC chain | Field/delete/reorder/forge/wrong-key tests | Baseline OK; copied tamper FAILED; baseline OK. |
| Runtime permissions | T03, T05, T07 | NFR-SEC-008 | ADR-002, ADR-004 | provisioning plus shared SQLite permission helper | permissive-umask, tightening, provisioning/scenario tests | Metadata inspection of tested runtime. |

Automated evidence establishes call ordering that cannot be inferred from a
user-visible live result. Live evidence establishes integration with one real
environment and is not treated as an automated regression suite.
