# Final Gap Audit

Audit date: 2026-09-13

Scope: Phase 10A, repository and local runtime metadata only

Commit reviewed: `cc12965` (`master`)

Network/live-VM activity: none

> Point-in-time record: Phase 10B-1 subsequently addressed B-001 and B-002
> with the tracked [README](../README.md), [PRD](PRD.md),
> [Threat Model](THREAT_MODEL.md), [Domain Model](DOMAIN_MODEL.md),
> [Known Limitations](KNOWN_LIMITATIONS.md), [Lab Setup](LAB_SETUP.md),
> Markdown ADRs, and [Live Validation](LIVE_VALIDATION.md). The finding table
> below is preserved as the evidence and prioritization recorded at audit
> time; it is not a claim that those two publication blockers remain open.

> Phase 10B-2 resolution: S-003 through S-007 were subsequently resolved by
> clamped terminal lifecycle timestamps under backward wall-clock movement,
> an explicit Paramiko legacy-algorithm deny policy, redacted
> `EncryptedSecret` representation, versioned/exact Vault schema and row
> validation with compatible legacy metadata upgrade, and descriptor-based
> no-follow regular-file key loading plus strict lab runtime-directory checks.
> The original findings below remain unchanged as point-in-time audit evidence.

# Executive Summary

The core functional MVP is complete and its supported access path is credible. The implementation authenticates a local PAM user, binds authorization to the authenticated principal, evaluates policy fail-closed, resolves an encrypted target credential only after authorization and configuration checks, verifies the pinned SSH host key before password authentication, brokers an interactive PTY under a monotonic duration limit, restores terminal state, and appends HMAC-chained audit events. The supplied record of successful and negative live validation is consistent with the code and automated tests.

No authentication bypass, authorization bypass, plaintext credential persistence, host-key-ordering defect, or default-allow path was identified. Clean Architecture dependency direction is sound. `AccessService` is a focused use-case orchestrator rather than a God Service, and no production refactor is required merely for symmetry.

The project is not yet ready for public portfolio publication. Two release BLOCKERs exist in the repository as delivered:

1. The PRD, Threat Model, domain model, and consolidated known-limitations document referenced by the ADRs are not tracked. This makes the security boundary and requirement traceability impossible for an independent reviewer to verify.
2. A fresh-clone engineer cannot reproduce the live Debian/libvirt demonstration from the tracked instructions. The runbooks begin with an already-running, machine-specific VM and already-provisioned runtime.

These are evidence/reproducibility blockers, not evidence that the working access path is insecure. There are 13 SHOULD FIX findings, mostly security hardening, failure observability, packaging, and automated quality gates. Intentional MVP exclusions are classified separately and are not inflated into blockers.

Verification results:

- Literal `pytest -q`: could not run because the virtual environment was not active and `pytest` was not on `PATH` (exit 127).
- Existing environment: `.venv/bin/pytest -q` -> **356 passed in 1.97s**.
- `python -m compileall -q src tests` -> success.
- `.venv/bin/python -m pip check` -> no broken requirements.
- Pre-report `git diff --check` -> success; pre-report worktree -> clean.
- Runtime metadata inspection only: `runtime/lab` and scenario leaf directories are `0700`; all six baseline artifacts and copied scenario artifacts are `0600`.

Finding totals: **2 BLOCKER, 13 SHOULD FIX, 10 KNOWN LIMITATION, 9 FUTURE**.

# Findings

| ID | Severity | Area | Finding | Evidence | Recommendation |
| --- | --- | --- | --- | --- | --- |
| B-001 | BLOCKER | Security documentation | The repository has no tracked README, PRD, Threat Model, domain-model document, or consolidated limitations document, although every ADR refers to a Phase 1 Threat Model and IDs such as T01-T09, D01, and D02. Independent threat/control/requirement traceability is therefore not possible. | `git ls-files`; four files under `ADRS- PRD/`; ADR-002 through ADR-005 “Related Threats” sections. | Restore or author source-controlled Markdown PRD, threat model, domain model, trust boundaries, supported claims, and limitations. Mark superseded decisions explicitly. |
| B-002 | BLOCKER | Demo reproducibility | The live lab cannot be recreated from a fresh clone. The runbooks assume a running VM at one fixed address and an already-provisioned runtime, with no Fedora/libvirt/QEMU setup, Debian install, OpenSSH setup, `pamadmin`/sudo procedure, network reservation, fingerprint acquisition, or snapshot/rebuild steps. | `docs/LAB_E2E.md:3-7`; `docs/LAB_NEGATIVE_E2E.md:1-8`; ADR-005 permits manual provisioning but gives no executable procedure. | Add a secret-free, end-to-end lab build and reset guide plus a top-level README. Treat the current IP, hostname, account, and fingerprint as a tested example and document how another engineer obtains their own values. |
| S-001 | SHOULD FIX | Key deployment / ADR consistency | ADR-002 explicitly rejects storing the key in the same location as `vault.db`, but the provisioning/runtime layout places `vault.key`, `audit.key`, and every DB in one runtime directory. File modes mitigate other-user reads, but copying or backing up that directory captures keys and encrypted data together. | ADR-002 “Evaluated Key Strategies”; `src/tools/provision_lab.py:83-102`; `src/main.py:180-197`. | Reconcile the ADR with the intended local-lab threat model. Before publication, either use separately protected key paths or state clearly that only database-only theft, not runtime-directory or PAM-user compromise, is protected. |
| S-002 | SHOULD FIX | Audit contract / observability | Accepted ADR-004 requires authentication, `ACCESS_REQUESTED`, and specific host-key/Vault/target failure events; ADR-005 names `HOST_KEY_MISMATCH`. The model implements only allow/deny and session lifecycle events, and all broker-open causes collapse to `broker_open_failed`. `reason` also mixes policy IDs and reason codes. | ADR-004 “Required Event Coverage” and final bullet; ADR-005 negative test section; `src/domain/audit.py:6-12`; `src/application/authentication_service.py:9-12`; `src/application/access_service.py:112-140`. | Decide the actual MVP audit contract, update ADRs, and add only the minimum schema/events needed for honest authentication and failure attribution. Preserve secret-free CLI errors while providing protected operator diagnosis. |
| S-003 | SHOULD FIX | Session integrity | The duration enforcement correctly uses monotonic time, but session terminal transitions use wall-clock UTC and reject an `ended_at` earlier than `started_at`. A backward system-clock step during a live session can close the broker yet leave the audit trail at `SESSION_ACTIVE` because `mark_closed`/`mark_failed` raises before a terminal event is appended. | `src/infrastructure/ssh/terminal_relay.py:22-37`; `src/infrastructure/runtime.py:7-11`; `src/domain/session.py:64-91`; `src/application/access_service.py:170-197`. No access-service clock-rollback test exists. | Define wall-clock rollback semantics that preserve a valid terminal state/audit record while retaining monotonic duration enforcement; add a regression test. |
| S-004 | SHOULD FIX | SSH cryptographic policy | The connector relies on Paramiko's complete default negotiation set rather than an explicit modern algorithm policy. Local inspection of installed Paramiko 5.0.0 shows legacy CBC/3DES and SHA-1/MD5 MAC options remain available after stronger preferences. The live negotiated suite was not captured, so this is a hardening gap, not proof the successful session used a weak suite. | `src/infrastructure/ssh/paramiko_connection.py:80-83`; no `disabled_algorithms` or `SecurityOptions` configuration; local read-only inspection of `Transport._preferred_*`. | Define and test a conservative algorithm policy compatible with Debian 13, and fail closed when no approved KEX/cipher/MAC is shared. Record the negotiated suite as non-secret operator diagnostics if useful. |
| S-005 | SHOULD FIX | Secret representation | `EncryptedSecret` uses the generated dataclass representation, which includes its nonce and ciphertext byte values. Current code does not log it, but this contradicts the stated “never print ciphertext” invariant and creates an accidental exception/debug disclosure path. | `src/ports/security.py:5-15`; read-only construction confirmed `repr()` contains both byte fields. `BrokerCredential` and `StoredUserAuthentication` already use redacted representations. | Make the representation redacted (`repr=False` plus safe `__repr__`) and add a regression test covering ciphertext and nonce markers. |
| S-006 | SHOULD FIX | Vault data integrity | `SQLiteVault` creates its table with `IF NOT EXISTS` but does not validate an exact schema or schema version. `resolve()` uses `fetchone()` without detecting ambiguous rows if an incompatible/corrupt pre-existing table lacks the intended primary key. Other security repositories perform explicit schema validation. | `src/infrastructure/vault/sqlite_vault.py:60-105`; compare `src/infrastructure/auth/sqlite_user_auth_repository.py:133-212` and audit schema validation. Vault tests cover field tamper/wrong key, not malformed schema. | Add explicit Vault schema/version validation and fail-closed row-shape/uniqueness checks without changing the port. |
| S-007 | SHOULD FIX | Filesystem hardening | SQLite paths are opened with `O_NOFOLLOW` and verified as regular files, but `FileKeyProvider` follows symlinks and does not verify a regular file. Provisioning also accepts a symlinked runtime directory, while access does not enforce the provisioner's `0700` directory invariant. | `src/infrastructure/sqlite_security.py:15-39`; `src/infrastructure/security/file_key_provider.py:15-32`; `src/tools/provision_lab.py:335-354`; `src/main.py:199-214`. | Apply descriptor-based no-follow/regular-file checks to key loading and explicitly validate the runtime directory/ancestor policy. Keep the local-host-compromise boundary documented. |
| S-008 | SHOULD FIX | Packaging / reproducibility | Runtime top-level packages are exactly pinned, but there is no declared Python version, `pyproject.toml`, dev/test dependency set, installable package metadata, or transitive lock/constraints file. The code requires Python 3.11+ (`StrEnum`), while plain `pytest -q` failed in the unaactivated shell. | `requirements.txt:1-3`; `src/domain/access.py:3`; absent packaging files; verification output. | Declare supported Python versions and Linux requirement, separate runtime/dev dependencies, and provide one documented fresh-environment install/test path. Add a reproducible lock or constraints strategy appropriate for the portfolio. |
| S-009 | SHOULD FIX | Automated quality gates | No CI, linter, type checker, coverage measurement, or dependency-advisory gate is tracked. The current pins match the installed environment and `pip check` succeeds, but that is not a repeatable security advisory assessment. | No `.github/workflows`, Ruff, mypy/pyright, coverage, or audit configuration in `git ls-files`. Official package records: [cryptography](https://pypi.org/project/cryptography/), [Paramiko](https://pypi.org/project/paramiko/), [argon2-cffi](https://pypi.org/project/argon2-cffi/). | Add a small GitHub Actions matrix with tests, compile/lint/type checks, coverage reporting, and a dependency audit. Do not claim the dependency set is vulnerability-free without a reproducible scan. |
| S-010 | SHOULD FIX | Test design / missing boundaries | The 356-test suite is security-focused, fast, and network-isolated, but all 34 test modules are under `tests/unit`, real-adapter/composition tests often assert private attributes, and several invariants rely on source-string searches. There is no simultaneous-audit-writer test, clock-rollback test, Vault-schema-corruption test, or audit failure test at `SESSION_CLOSED`/`SESSION_FAILED`. | 8,120 test lines; `tests/unit/test_application_composition.py:112-180`; `tests/unit/test_paramiko_connection.py:350-378`; audit failure tests stop at opening/active in `tests/unit/test_access_service.py:618-666`. | Split unit/integration/security-contract layers and add the missing high-value boundary tests. Keep behavioral assertions primary; use source inspection only as defense in depth. |
| S-011 | SHOULD FIX | Error handling / diagnosis | The access command safely redacts expected errors, but the `validate` subcommand lets configuration exceptions escape as tracebacks. Conversely, access has no protected diagnostic channel: auth DB outage is intentionally shown as authentication failure, while config/Vault/SSH/PTY failures are collapsed to generic output and sometimes generic audit causes. | `src/main.py:81-94` versus guarded access path at `src/main.py:97-169`; `src/application/authentication_service.py:49-66`; `src/application/access_service.py:133-140`. | Catch validation failures consistently and add minimal secret-free operator diagnostics distinct from user-facing output. Avoid a large exception framework. |
| S-012 | SHOULD FIX | Interactive terminal quality | The remote PTY is always requested as `xterm`, 80x24, and local resize events are not propagated. This does not break the demonstrated shell, but common full-screen tools and resized terminals can render incorrectly. | `src/infrastructure/ssh/interactive_channel.py:15-46`; no `TIOCGWINSZ`, `resize_pty`, or `SIGWINCH` handling. | Read the initial local terminal type/size safely and propagate resize events; preserve the existing relay and restoration boundaries. |
| S-013 | SHOULD FIX | Public repository quality | There is no license, and the accepted ADRs are binary DOCX files with blank date fields, making review/diff/linking harder. The repository also lacks a sanitized, dated record of the completed live test matrix; current runbooks state expected outcomes only. | `git ls-files`; extracted ADR metadata; `docs/LAB_E2E.md` and `docs/LAB_NEGATIVE_E2E.md`. | Add a license chosen by the owner, convert/copy ADRs to reviewable Markdown, and record non-secret live validation results (date, environment, pass/fail, no transcripts/passwords). |
| K-001 | KNOWN LIMITATION | Trust boundary | Compromise of the PAM host, its OS account, or root can read process memory and locally stored keys; locally adjacent file keys do not protect against that actor. | ADR-002 and ADR-005 explicitly defer D01; `src/application/authentication_service.py:3-5`. | State this prominently in the threat model and README; do not describe the design as protecting a compromised broker host. |
| K-002 | KNOWN LIMITATION | Secret lifetime | PAM and target passwords necessarily exist briefly as Python `str`/`bytes`; Python cannot guarantee deterministic zeroization. Assignment to empty values only drops references. | `src/application/authentication_service.py:3-4`; `src/main.py:119-134`; `src/tools/provision_lab.py:162-229`; `src/infrastructure/ssh/paramiko_connection.py:120-137`. | Document accurately; avoid the claim “credentials never exist in memory.” Keep lifetimes and object retention minimal. |
| K-003 | KNOWN LIMITATION | Authentication abuse | No brute-force lockout/rate limiting exists, and dummy verification removes the obvious unknown-user fast path without guaranteeing perfect timing indistinguishability. | `src/application/authentication_service.py:5-7,40-73`; no rate-limit component. | Document for the local single-instance MVP; add throttling/lockout only when an outer multi-user boundary is introduced. |
| K-004 | KNOWN LIMITATION | Authentication audit | Pre-authentication success/failure is not audited because the current `AuditEvent` requires authenticated actor and target identifiers. | `src/application/authentication_service.py:9-12`; `src/domain/audit.py:15-24`. | Keep as a stated schema limitation until Phase 10B decides whether ADR-004's broader contract belongs in this MVP. |
| K-005 | KNOWN LIMITATION | Audit assurance | The local HMAC chain detects field/middle-chain tampering, but valid suffix removal (including deleting the whole chain) is undetectable without a trusted external chain head. A host attacker holding the local audit key can recompute a chain. | `src/infrastructure/audit/__init__.py`; repository docstring; `tests/unit/test_audit_integrity.py:375-388`; `docs/LAB_NEGATIVE_E2E.md:110-113`. | Call it tamper-evident, never tamper-proof. Preserve the external-anchor limitation in public claims. |
| K-006 | KNOWN LIMITATION | Session governance | Sessions are unrestricted interactive shells; there is no transcript/keystroke recording, replay, or command filtering. This avoids persisting terminal secrets but limits accountability and control. | ADR-004 “Storage and Lifecycle”; `src/infrastructure/ssh/terminal_relay.py` relays bytes without inspection or retention. | Document the tradeoff; do not imply command-level governance or session-content audit. |
| K-007 | KNOWN LIMITATION | Authorization model | The MVP supports one unambiguous privileged account per target and direct user-target-action policy. Roles/groups/RBAC/ABAC are absent; `REQUIRES_APPROVAL` deliberately denies because there is no approval engine. | ADR-003; `src/application/policy_evaluator.py:20-59`; `src/infrastructure/config/sqlite_privileged_account_repository.py:24-31,78-84`. | Present this as deliberate YAGNI scope, not incomplete authorization. |
| K-008 | KNOWN LIMITATION | Provisioning atomicity | Provisioning is one-shot across multiple SQLite databases with no distributed transaction. A fresh failed runtime may contain partial data and requires manual removal after inspection. | `src/tools/provision_lab.py:1-7,145-231`; run-time databases are rejected on rerun. | Keep the explicit fresh-directory/manual-cleanup procedure; do not add distributed transactions for this MVP. |
| K-009 | KNOWN LIMITATION | Deployment / concurrency | SQLite and local files target a single-instance deployment. `BEGIN IMMEDIATE` serializes audit appends, but lock timeout/backpressure, multi-process load, retention, and HA are not productized. | `src/infrastructure/audit/sqlite_audit_repository.py:72-116`; short per-operation SQLite connections throughout; no HA components. | State single-instance expectations and avoid distributed/HA claims. |
| K-010 | KNOWN LIMITATION | Platform | The local terminal adapter is POSIX/Linux-only (`termios`, `tty`, file descriptors, `select`). | `src/infrastructure/terminal/terminal_mode.py`; `src/infrastructure/terminal/local_terminal_io.py`; `src/infrastructure/ssh/terminal_relay.py`. | Document Linux as a requirement; cross-platform terminal support is not required for this MVP. |
| F-001 | FUTURE | Authorization growth | Roles, groups, RBAC, and ABAC would reduce direct-policy management at larger scale. | ADR-003 explicitly defers them. | Introduce only with real multi-user policy requirements, preserving deny precedence and authenticated identity binding. |
| F-002 | FUTURE | Access governance | JIT grants and an approval workflow are enterprise growth features. | `REQUIRES_APPROVAL` already fails closed; no approval engine is claimed. | Design approval identity, expiry, race, revocation, and audit semantics before enabling the effect. |
| F-003 | FUTURE | Authentication | MFA is not part of the local-user MVP. | No MFA model or claim. | Add when the product has an appropriate second-factor enrollment/recovery boundary. |
| F-004 | FUTURE | Identity integration | LDAP/AD/OIDC/SAML federation is product expansion, not current technical debt. | Current implementation intentionally uses `SQLiteUserAuthRepository`. | Add through authentication ports while continuing to issue the same non-secret `AuthenticatedPrincipal`. |
| F-005 | FUTURE | Secret operations | Credential rotation, key rotation, and KMS/HSM integration are lifecycle capabilities outside MVP scope. | ADR-002 consequences; `encryption_version` is persisted but no rotation API exists. | Define versioned migration, backup/recovery, rollback, and audit procedures before implementation. |
| F-006 | FUTURE | SSH identity | SSH certificates are not required for the current password-injection demonstration. | `ParamikoSshConnector` implements password authentication only. | Consider short-lived SSH certificates when moving beyond a single lab account. |
| F-007 | FUTURE | Audit platform | Remote SIEM/WORM storage and external chain-head anchoring are enterprise assurance features. | Current audit is local SQLite plus local HMAC key. | Add an authenticated export/anchor protocol with explicit failure and availability semantics. |
| F-008 | FUTURE | Scale | Distributed databases, multi-node coordination, and HA are unnecessary for the single-instance MVP. | Runtime composition is deliberately local. | Revisit only when availability and concurrency requirements change. |
| F-009 | FUTURE | User experience | A web UI/API is product expansion and not required to prove the current secure CLI flow. | CLI is the only supported outer boundary. | Add only with separate web threat modeling, CSRF/session/auth controls, and no plaintext secret parameters. |

# BLOCKERS

## B-001: Missing security baseline documents

This is the most important publication blocker. The four accepted ADRs repeatedly depend on a Phase 1 Threat Model that is not present in the current tree or tracked history. There is also no PRD against which FR/NFR completion can be checked. Consequently, an outside reviewer cannot determine, from the repository, whether “PAM host compromise,” file-only theft, a malicious target, a same-UID local attacker, or operational misconfiguration are in or out of scope. This ambiguity directly affects how ADR-002 key placement and local audit-key assurance should be judged.

The code and tests provide strong evidence for many controls, but code cannot substitute for declaring assets, actors, trust boundaries, abuse cases, and accepted residual risks. Phase 10B should restore the missing artifacts or create current versions rather than reconstructing claims implicitly in the README.

## B-002: Fresh-clone lab reproduction is incomplete

The two runbooks are good execution checklists once the author's environment exists, but they are not a build guide. Another engineer cannot recreate the demonstrated VM, network, privileged account, OpenSSH service, fingerprint pin, or baseline runtime using tracked instructions alone. The fixed IP and fingerprint are appropriate as a record of the tested lab, not as universal configuration.

A public portfolio project should allow a reviewer to reach the same result without receiving undocumented commands or secrets from the author. A manual build procedure is sufficient; cloud-init and Docker are not required.

# SHOULD FIX

Recommended order by value before publication:

1. **S-001 — Reconcile key placement and threat claims.** This is the sharpest contradiction between an accepted security decision and the running layout.
2. **S-002 — Make audit scope honest and useful.** Decide whether missing ADR events are implementation work or explicitly deferred scope; add protected diagnosis without weakening CLI redaction.
3. **S-003 — Handle clock rollback at terminal transitions.** Preserve terminal lifecycle evidence even when wall time moves backward.
4. **S-004 — Pin a modern SSH algorithm policy.** The successful Debian connection does not prove all future target negotiations remain modern.
5. **S-005/S-006/S-007 — Close narrow secret/data/filesystem hardening gaps.** Redact encrypted-object representations, validate Vault schema, and make key/runtime path handling consistent with DB no-follow checks.
6. **S-008/S-009 — Make setup and verification reproducible.** Declare Python/Linux support and add dev dependencies, CI, lint/type/coverage, and dependency scanning.
7. **S-010 — Add the few missing high-value tests and improve test layering.** Avoid expanding low-value test volume.
8. **S-011 — Improve secret-free operator diagnosis and validation CLI handling.** Generic user output should remain generic.
9. **S-012 — Add terminal size/resize support.** This is a product-quality improvement after security/evidence work.
10. **S-013 — Add license, reviewable ADRs, and a sanitized validation record.** These materially improve public review and portfolio presentation.

# KNOWN LIMITATIONS

K-001 through K-010 are acceptable within a local, single-instance MVP if stated plainly. They must not be reframed as solved controls. In particular:

- “Encrypted at rest” means `vault.db` alone does not reveal the password; it does not mean a compromised PAM process/host or a copy containing both DB and key is safe.
- “Tamper-evident” means verification detects authenticated-field modification or middle-chain deletion; it does not mean tamper-proof, externally anchored, or resistant to valid tail truncation.
- “Credential hiding” means no CLI prompt/output/API/audit persistence of the target password; it does not mean the credential never exists in process memory.
- The interactive session is duration-bounded and lifecycle-audited, not recorded or command-governed.
- The dummy hash removes an obvious account-absence fast path, not all timing leakage, and it is not a rate limiter.

# FUTURE

F-001 through F-009 are product/enterprise evolution. None is required to claim that the scoped single-user, single-target, single-instance CLI MVP works as designed. Adding them prematurely would increase attack surface and obscure the demonstrated trust path.

# Security Control Traceability

Because the referenced PRD and Threat Model are absent, “documented intent” below is limited to the four ADRs and inline documentation.

| Critical control | Documented intent | Implementation | Automated evidence | Live evidence / audit conclusion |
| --- | --- | --- | --- | --- |
| Identity spoofing | ADR-003 uses authenticated `user_id` for policy. Referenced T01 is unavailable. | CLI derives `AccessRequest.user_id` from `AuthenticatedPrincipal`; `AccessService` rejects mismatch before policy. | `test_authenticated_access_binds_principal_and_restores_terminal`; `test_authenticated_identity_mismatch_stops_before_policy_and_access`; authenticated-flow test. | Wrong-PAM live scenario reported complete; control is credible. |
| DENY fail-closed | ADR-003: no match denies; explicit DENY wins; no Vault/SSH. | `PolicyEvaluator` checks DENY, unsupported approval, ALLOW, then default DENY; repository exceptions propagate. | Policy precedence/failure tests; access-service explicit/no-policy denial tests. | DENY live scenario reported exit 3/no shell. |
| Disabled target/account | Not explicit in available ADRs; implied configuration safety. | Target is checked before account/Vault; account is checked before Vault/broker. | `test_disabled_target_denies_before_account_vault_broker_or_session`; corresponding disabled-account test; scenario-copy tests. | Both live scenarios reported complete. Documentation requirement is missing under B-001. |
| Encrypted credential persistence | ADR-002 selects AES-256-GCM and database-only theft protection. | 32-byte AESGCM key, fresh 12-byte random nonce, authenticated decrypt; SQLite stores version/nonce/ciphertext. | Cipher round-trip/fresh nonce/tamper/wrong-key tests; raw Vault DB absence test; provisioning raw-file tests. | Successful live session and wrong-target-password scenario support correct injection without output. S-006 remains. |
| Vault/audit key separation | ADR-002 requires distinct purposes. ADR-004 requires distinct audit key. | Composition validates distinct canonical key paths and compares 32-byte values; provisioning generates and checks separately. | Composition same-path/same-value tests; provisioning distinct-key tests; DB absence tests. | Runtime metadata confirms separate `0600` files; S-001 covers co-location semantics. |
| Host key before authentication | ADR-005 pins target identity. | Connector completes SSH negotiation, calculates/compares SHA-256 pin with `compare_digest`, then calls password authentication. No TOFU/AutoAddPolicy path exists. | `test_host_key_mismatch_happens_before_authentication_and_closes_resources` proves zero `auth_password` calls; matching/mismatch cleanup tests. | Bad-pin live scenario reported exit 4/no shell. Specific audit-event claim is not met (S-002). |
| Credential hiding/injection | ADR-002 forbids CLI/API/audit/log persistence. | Access CLI prompts only for PAM password; Vault returns redacted `BrokerCredential`; connector injects it after pin verification. | CLI parser/no-target-prompt tests; redacted broker tests; audit/config/auth/vault marker tests; real composition to fake final broker. | Live shell opened without target-password prompt. S-005 is an encrypted-ciphertext representation gap, not plaintext exposure. |
| Session lifecycle | ADR-004 requires opening/active/closed/failed audit. | Strict `OPENING -> ACTIVE -> CLOSED/FAILED` model; broker/channel close paths are idempotent and nested cleanup is attempted. | Domain transition tests; broker/channel cleanup tests; access relay/open/close failure tests; real SQLite lifecycle test. | Normal/negative sessions reported complete. S-003 and missing terminal audit-failure branches remain. |
| Maximum duration | Phase documentation states total elapsed cap. | Relay uses monotonic deadline; activity does not reset it; timeout returns controlled close reason. | no-I/O timeout, active timeout, and no-wall-clock source tests; access-service timeout audit test; CLI mapping test. | Five-second live closure reported exit 0 with restored terminal. |
| Audit tamper evidence | ADR-004 selects structured append-only audit and later HMAC hardening. | Canonical ordered JSON, sequence + previous MAC, HMAC-SHA256, dedicated key, `compare_digest`, `BEGIN IMMEDIATE`, no update/delete port. | field/middle deletion/forgery/reorder/wrong-key/canonicalization tests; negative tool tests. | Baseline verification and copied direct-tamper failure reported complete. Tail limitation is K-005. |
| Secret hygiene | ADR-002/004 forbid passwords, keys, transcript in persistent/user output. | getpass, parameterized SQL, redacted public credential/hash types, generic CLI errors, no transcript logger. | Raw DB/output marker checks across provisioning, Vault, audit, CLI, SSH. | Filename-only repository/history scan found no likely real secret artifacts. S-005 remains. |
| Runtime permissions | ADR-002 requires restricted key file; later hardening covers DBs. | Provisioned lab dir `0700`; keys `0600`; all SQLite adapters use shared no-follow regular-file creation/tightening to exact `0600`. | permissive-umask fresh DB and broad-existing-mode tests for audit/auth/config/policy/Vault; provisioning/scenario mode tests. | Metadata-only inspection confirms baseline artifact modes. Key/runtime symlink gap is S-007. |

# Architecture Assessment

## Dependency direction

- `src/domain` imports only standard-library types. It has no SQLite, Paramiko, Argon2, crypto, filesystem, CLI, or terminal dependency.
- `src/application` depends on domain models and ports. It does not instantiate infrastructure. Authentication and authorization are separate use cases.
- Ports are cohesive and infrastructure-neutral. `BrokerCredential.as_bytes()` is necessarily an opaque-to-plaintext boundary for the SSH adapter; its representation is redacted.
- Infrastructure owns SQLite, AES-GCM, Argon2, Paramiko, filesystem modes, terminal relay, time/UUID implementations, and adapter errors.
- `src/bootstrap/application.py` is a legitimate composition root. It validates settings/key separation and wires concrete dependencies without access business decisions.
- `src/main.py` is a thin outer CLI/orchestrator. It gets the PAM secret, binds the principal, enters terminal mode, invokes the use case, and maps results.
- `src/tools` reuses adapters for provisioning/verification; the direct scenario SQL mutation is correctly isolated as lab tooling. No mutation API was added to production repositories for negative tests.

## SOLID/Clean Architecture judgment

The implementation demonstrates SRP and DIP in material places. `PolicyEvaluator`, cipher/key provider, repositories, connector/channel/relay, and terminal-mode context are usefully separate. Protocol use is proportionate; there is no generic manager framework, DI container, circular import, speculative RBAC abstraction, or God Repository. `AccessService` is the largest coordinator because the security ordering belongs in one use case; splitting it solely to reduce line count would make the trust path harder to inspect.

Debt hotspots are narrow: audit event/error taxonomy (S-002), terminal transition failure semantics (S-003), and runtime security adapters (S-005 through S-007). None requires changing existing application/domain public APIs merely to preserve the current MVP.

# Test Assessment

## Strengths

- 356 tests execute in about two seconds with no real network dependency.
- Negative authorization ordering is asserted explicitly: DENY and disabled configuration stop before Vault/broker.
- The Paramiko seam proves host mismatch precedes and prevents password authentication.
- Real SQLite adapters are exercised for storage, malformed rows, permissions, duplicates, tampering, schema compatibility (except Vault), and integration with `AccessService`.
- Cryptographic tests cover key sizes, fresh 96-bit nonces, authenticated tamper/wrong-key failure, raw-file plaintext/key absence, and separate keys.
- Terminal tests cover partial writes, EOF, I/O errors, elapsed timeout, activity not resetting duration, and restoration on normal/setup/error paths.
- CLI tests cover authentication-first order, no password/user-ID options, getpass-before-raw-mode, exit mapping, secret-free messages, restoration, composition, and a fake final network boundary.
- Provisioning and negative-tool tests cover one-shot behavior, baseline copy preservation, `0600`/`0700` modes, secret-free output, and Git ignore behavior.

## Gaps and quality risks

- The suite has strong integration content but its directory labels everything “unit,” obscuring the test pyramid.
- Several composition tests reach private attributes, and several security tests inspect source strings. These can be helpful guardrails but are brittle substitutes for public behavioral contracts.
- Missing high-value cases are the S-003 clock rollback, S-006 corrupt Vault schema/ambiguous rows, concurrent audit append, audit persistence failure during terminal event append, and a clean-environment install/CLI smoke test.
- There is no measured coverage, so test count cannot establish untested branches.
- Live runbooks describe expected outcomes, but the tracked repository has no sanitized pass/fail evidence record. The live results in the audit brief were accepted as operator-provided evidence and were not rerun.
- Static password/credential values occur only as clearly named synthetic test markers. No real target password is required by automated tests.

The suite gives credible confidence in the central security ordering and adapters. It does not eliminate the focused gaps above, and the absence of the threat model prevents a formal claim of threat-control completeness.

# Error-Handling and Failure-Mode Assessment

| Failure | Fail closed / cleanup | User output and audit assessment |
| --- | --- | --- |
| Auth DB unavailable/corrupt | Yes; dummy verification runs and no access/Vault/SSH occurs. | Generic authentication failure (exit 2), which prevents enumeration but gives operators no separate diagnosis; no pre-auth audit (K-004/S-011). |
| Config DB unavailable/corrupt | Yes; repository error propagates before later dependencies. | Generic privileged-session failure (exit 4); usually no event because a valid decision/context could not be formed. |
| Vault DB/key unavailable, wrong key, or ciphertext tamper | Missing key fails startup; resolve/decrypt failure prevents broker. | Generic startup/session failure; no Vault-specific event despite ADR-004 (S-002). Cipher errors are secret-free. |
| Audit DB/key unavailable | Startup or append fails; opening/active audit failure prevents relay or closes an opened broker. | Fail-closed and secret-free, but multi-event lifecycle is not atomic and terminal-event append failures need tests/defined semantics. |
| Target unreachable / SSH negotiation | No session channel; socket/transport cleanup attempted. | Generic session failure; audit records `broker_open_failed`, not cause-specific target-unavailable event. |
| Host-key mismatch | Password authentication is not called; socket/transport closed. | Generic session failure, preventing library leakage; audit lacks promised `HOST_KEY_MISMATCH`. |
| SSH password failure | Occurs only after host verification; resources closed; no shell. | Generic session failure; target password is not displayed/audited. |
| PTY/shell failure | Partial channel and verified connection are closed. | Generic session failure and generic broker-open audit reason. |
| Relay/local I/O failure | Relay closes channel; access service closes broker; session fails. | `SESSION_FAILED/relay_failed`; terminal restoration context runs. |
| Broker cleanup failure | Connection close is attempted even when channel close raises; access marks failure. | `SESSION_FAILED/broker_close_failed`; raw terminal restoration still runs. |
| Local raw-mode setup/restoration failure | Setup attempts immediate restore; outer context always attempts final restore. OS-level restoration failure cannot be guaranteed away. | Generic session failure; if raw setup fails, `AccessService` was not entered and no lifecycle event exists. |
| Wall clock moves backward | Broker cleanup still occurs through `finally`. | Session transition can raise and omit a terminal event (S-003). |

Expected failures are user-secret-free. The main deficiency is operator diagnosis and audit specificity, not fail-open behavior.

# Data and Concurrency Assessment

- SQL values are parameterized throughout production repositories. Scenario tooling uses fixed statements and parameters against copied lab DBs.
- Each repository uses short-lived SQLite connections. Auth/config/Vault writes are atomic per statement/connection transaction.
- Audit append uses `BEGIN IMMEDIATE`, reads the current head and inserts the next sequence/MAC in the same transaction. A unique sequence number and primary event ID protect duplicate writes; errors roll back and propagate.
- Audit lifecycle consists of separate append transactions. A crash or later append failure may leave a valid prefix such as `ACCESS_ALLOWED`/`SESSION_OPENING` without a terminal event. This is fail-closed for access but operationally incomplete.
- Concurrent audit writers should serialize under SQLite locking, but default busy timeout and contention behavior are not explicitly configured or tested. This is acceptable for the single-instance scope, with S-010 as targeted assurance work.
- Policy/config reads can race with out-of-band lab mutation, but production exposes no update API. Orphan/missing/malformed configuration denies or fails rather than allowing.
- Provisioning intentionally has no cross-database transaction and may leave partial fresh state; its one-shot detection prevents silent overwrite (K-008).
- PostgreSQL/distributed transactions are not warranted by current claims.

# Dependency, Packaging, and Reproducibility Assessment

`requirements.txt` exactly pins the three direct runtime packages, and the existing environment matches them:

- `cryptography==50.0.1`
- `paramiko==5.0.0`
- `argon2-cffi==25.1.0`

The local environment also contains `pytest==9.1.1`, but pytest is not declared by the repository. Python is 3.14.7; the source itself requires at least 3.11 because it imports `enum.StrEnum`. Official PyPI metadata currently lists Python 3.14 support for [cryptography 50.0.1](https://pypi.org/project/cryptography/) and [argon2-cffi 25.1.0](https://pypi.org/project/argon2-cffi/); [Paramiko 5.0.0](https://pypi.org/project/paramiko/) declares Python `>=3.9` but its published classifiers shown during this audit extend through 3.13. The suite passing on 3.14 is useful local evidence, not a replacement for a declared/tested version matrix.

No dependency scanner was installed or run, by instruction. `pip check` proves dependency consistency, not absence of known vulnerabilities. Current official project records were reviewed, but no “vulnerability-free” conclusion is made.

The project intentionally does not need Docker. A normal venv workflow, declared Python/Linux support, deterministic dev dependencies, and a CI matrix are sufficient.

# Repository and Secret Hygiene

- `runtime/`, `*.db`, `*.key`, `.env`, `.venv`, Python bytecode, and pytest cache are ignored.
- `git check-ignore` confirms baseline and scenario DB/key examples are excluded by `runtime/`.
- `git ls-files` and full tracked-name history contain no runtime DB/key, `.env`, PEM/private-key, or similar secret artifact.
- Filename-only current/history content searches found no PEM private-key block and no serialized Argon2 hash literal.
- A safe AST scan found password/credential literal markers only in tests; production assignments are empty-string cleanup, public fingerprint/reference constants, or values derived at runtime. No marker value is reproduced here.
- The pinned SSH host fingerprint, target ID/name/address, account name, and credential reference are non-secret lab metadata. The target password and generated keys were not inspected or printed.
- The DOCX files were text-extracted in memory for review; no password/private-key material was identified.
- Current runtime metadata, not contents, was inspected. Baseline files remain unchanged by this audit.

The current ignore rules are adequate for the deterministic MVP artifacts. A future project that introduces `.env.*`, alternate DB extensions, SSH private keys, exports, or backups must extend the rules narrowly and add an automated secret scan.

# Tooling Recommendations

| Tool | Recommendation | Classification | Concrete value here |
| --- | --- | --- | --- |
| Ruff | Add before publication. | SHOULD FIX (S-009) | Enforces import hygiene/style and catches simple defects across 61 source and 34 test modules; replaces ad hoc manual checks. No obvious TODO/FIXME/HACK or unused import was found manually. |
| mypy or pyright | Add incrementally before publication, starting with domain/application/ports. | SHOULD FIX (S-009) | Checks Protocol/adapter signatures, optional `AccessResult.session`, SQLite `tuple[object, ...]` reconstruction, and fake fidelity. Runtime validation remains necessary. |
| Coverage | Measure branch coverage and set an evidence-based floor after viewing the first report. | SHOULD FIX (S-009/S-010) | A 356-test count does not expose missing clock rollback, Vault schema, terminal audit failure, or concurrency branches. Avoid gaming a percentage. |
| GitHub Actions | Add a minimal Linux Python matrix. | SHOULD FIX (S-009) | Reproduces install, compile, tests, lint/type, coverage, and dependency audit outside the author's venv; catches the current undeclared-pytest/Python-version gap. |

# Portfolio Readiness

## Is it portfolio-ready now?

**Not for public publication yet.** The implementation is interview-worthy now and the core MVP is functionally complete, but B-001 and B-002 prevent an independent reviewer from understanding the promised security boundary and reproducing the signature live demo.

## What must be done before publishing?

1. Resolve both BLOCKERs: source-controlled security/product documentation and a fresh-clone lab build/run path.
2. Reconcile the key-location and audit-event ADR contradictions so every security claim is honest.
3. Address the highest-value security hardening: clock rollback lifecycle, SSH algorithm policy, encrypted-object redaction, Vault schema validation, and key path handling.
4. Declare Python/Linux/dev dependencies and run the same checks in CI.
5. Add a license.

## What would materially improve interview/demo value?

- A README that leads with the threat model, trust boundaries, credential flow, security guarantees, and what is explicitly not guaranteed.
- One small architecture/sequence diagram showing `getpass -> AuthenticationService -> principal-bound policy -> Vault -> pinned SSH -> PTY -> audit`.
- A reproducible demo section with the successful and negative matrix, deterministic exit codes, and a sanitized dated validation record.
- A traceability table linked to code/tests, adapted from this audit.
- CI/coverage badges backed by a clean fresh-environment job, not raw test-count marketing.
- Precise language: “tamper-evident,” “encrypted at rest against DB-only theft,” “brief plaintext process lifetime,” and “single-instance Linux MVP.” Avoid “enterprise-ready,” “tamper-proof,” “zero trust,” “production-ready,” “credentials never exist in memory,” or “timing-proof.”

# Phase 10B Recommended Work

1. **Author/restore the PRD, Threat Model, domain model, trust boundaries, and consolidated limitations in Markdown.** Resolve dangling T/D identifiers and define database-only theft versus PAM-host/directory compromise.
2. **Create the top-level README and reproducible Fedora/libvirt/Debian lab guide.** Include venv/setup, target construction, OpenSSH, `pamadmin`/sudo, networking, fingerprint acquisition, provisioning, access, negative scenarios, audit verification, reset/snapshot, and machine-specific-value guidance—without secrets.
3. **Reconcile ADR-002/004/005 with the shipped system.** Decide key path separation and the honest audit event contract; date/version the decisions.
4. **Apply the focused security hardening.** Enforce a modern SSH algorithm policy, redact `EncryptedSecret`, validate/version Vault schema, harden key/runtime no-follow checks, and define backward-clock terminal transitions.
5. **Add the targeted regression tests.** Cover clock rollback, close/failure audit append errors, corrupt/ambiguous Vault schema, concurrent audit writers, key/runtime symlinks, and allowed SSH algorithm negotiation.
6. **Add packaging/developer metadata.** Declare Python 3.11+ (or the chosen tested range), Linux-only terminal support, runtime/dev dependencies, and a deterministic constraints/lock strategy.
7. **Add minimal quality automation.** GitHub Actions, Ruff, incremental mypy/pyright, coverage measurement, and dependency/secret scanning; keep the unit suite network-free.
8. **Improve protected operator diagnostics and CLI robustness.** Catch `validate` failures and retain generic user output while making auth/config/Vault/audit/SSH/PTY causes diagnosable to the operator.
9. **Finish public-repository polish.** Add a license, reviewable Markdown ADRs, a sanitized live-validation record, and terminal resize support.

Proceed to Phase 10B. The first two actions are publication blockers; actions 3-5 provide the largest security/evidence return; actions 6-9 complete portfolio polish without expanding MVP scope.
