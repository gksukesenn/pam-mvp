# PAM MVP

This project is a small privileged access management (PAM) reference
implementation for brokering an interactive SSH session to a managed Linux
target. It demonstrates how local user authentication, fail-closed
authorization, encrypted credential retrieval, pinned server identity,
session lifecycle control, and tamper-evident audit can be composed without
putting the target password in the access command.

## Scope

The supported product is a single-instance, local Linux command-line MVP. It
uses one local PAM user, direct user-to-target policy, one privileged account
per target, local SQLite persistence, and a separately managed Debian SSH
target. The lab is intentionally small enough for its security ordering to be
reviewed end to end.

## Core security flow

```text
PAM user
  -> AuthenticationService
  -> AuthenticatedPrincipal
  -> principal-bound AccessRequest
  -> PolicyEvaluator
  -> Target and PrivilegedAccount configuration
  -> encrypted Vault
  -> pinned SSH host-key verification
  -> target-password authentication
  -> brokered interactive PTY
  -> Session lifecycle and structured audit
```

The CLI never accepts a caller-supplied `user_id`. After authentication it
uses the principal's `user_id` in the access request, and `AccessService`
rejects an identity mismatch before policy, Vault, or SSH work.

## Security guarantees

Within the [documented threat model](docs/THREAT_MODEL.md), the implementation
and tests support these claims:

- PAM login passwords are persisted as salted Argon2id hashes, not plaintext.
- Target credentials are encrypted at rest with AES-256-GCM and a fresh
  96-bit random nonce for each encryption.
- The Vault database does not contain its encryption key. Vault and audit use
  distinct key paths and distinct key bytes.
- During access, the operator enters only the PAM login password. The target
  password is resolved from the encrypted Vault and is not displayed.
- Authorization is bound to `AuthenticatedPrincipal`. Missing policy and
  explicit `DENY` fail closed; `DENY` takes precedence over `ALLOW`.
- Disabled targets and privileged accounts stop before Vault or broker use.
- The configured SSH host key is compared before target-password
  authentication. There is no trust-on-first-use path, and the Paramiko
  adapter disables its legacy CBC/3DES ciphers, SHA-1/MD5 MACs, and
  `ssh-rsa`/SHA-1 host/public-key signature algorithm.
- Session state transitions are constrained, broker/channel cleanup is
  attempted on every path, and local terminal restoration is protected by a
  context manager.
- The maximum session duration is a total elapsed-time limit measured with a
  monotonic clock; activity does not reset it.
- Access and session lifecycle events are stored in an append-only application
  interface and linked with HMAC-SHA256 for tamper evidence.
- Provisioned/access runtime directories are required to be `0700`; key and
  SQLite files are `0600`. Key and DB leaf paths reject symbolic links and
  non-regular files.

The precise guarantee for the current lab is that **database-only theft or
accidental disclosure of `vault.db` does not reveal the target credential
without `vault.key`**. The lab stores keys and databases as separate files in
the same owner-only runtime directory.

## Explicit non-guarantees

This MVP does not claim to protect secrets after compromise of the PAM host,
the PAM OS account, the running process, or root. Copying the entire runtime
directory captures both encrypted data and local file keys.

Passwords exist briefly in process memory, and Python cannot guarantee
deterministic memory zeroization. The local audit chain is tamper-evident, not
tamper-proof: valid tail truncation cannot be detected without an externally
trusted chain-head anchor, and compromise of the local audit key permits chain
recomputation.

Sessions are not recorded and commands are not filtered. The MVP has no MFA,
RBAC/ABAC, JIT grant, approval engine, brute-force lockout/rate limiting,
credential rotation, key rotation, external identity provider, SSH
certificate support, remote SIEM/WORM storage, or high-availability
deployment. See [Known Limitations](docs/KNOWN_LIMITATIONS.md).

## Quick start

The commands must be run from the repository root on Linux.

1. Build the host and Debian target by following
   [Lab Setup](docs/LAB_SETUP.md). It includes portable target-IP and host-key
   configuration; do not assume the tested example values match another VM.
2. Provision a fresh ignored runtime with the interactive provisioning command
   in that guide. Passwords are read with `getpass`, never command-line flags.
3. Run the [successful access procedure](docs/LAB_E2E.md).
4. Optionally run the isolated [negative-security procedure](docs/LAB_NEGATIVE_E2E.md).

The access command has this shape:

```bash
python -m src.main access \
    --runtime-dir ./runtime/lab \
    --username goksu \
    --target-id target-001
```

## Tests

The automated suite uses fakes at the final network boundary; it does not
connect to the Debian VM. From an environment in which the test dependency is
available:

```bash
.venv/bin/pytest -q
```

The suite exercises domain invariants, fail-closed ordering, real SQLite and
crypto adapters, SSH host-key-before-authentication behavior, cleanup,
terminal restoration, provisioning, CLI result mapping, runtime permissions,
and audit integrity. Test volume alone is not treated as proof of security.
Manual environment-specific evidence is recorded in
[Live Validation](docs/LIVE_VALIDATION.md).

## Documentation

- [Product Requirements](docs/PRD.md)
- [Threat Model and trust boundaries](docs/THREAT_MODEL.md)
- [Domain Model](docs/DOMAIN_MODEL.md)
- [Known Limitations](docs/KNOWN_LIMITATIONS.md)
- [Lab Setup](docs/LAB_SETUP.md)
- [Successful E2E Runbook](docs/LAB_E2E.md)
- [Negative E2E Runbook](docs/LAB_NEGATIVE_E2E.md)
- [Live Validation Record](docs/LIVE_VALIDATION.md)
- [Final Gap Audit](docs/FINAL_GAP_AUDIT.md)
- [ADR-002: Vault and Master Key Strategy](docs/adr/ADR-002-vault-key-strategy.md)
- [ADR-003: Access Policy Model](docs/adr/ADR-003-access-policy.md)
- [ADR-004: Audit and Integrity Strategy](docs/adr/ADR-004-audit-integrity.md)
- [ADR-005: Target and Lab Strategy](docs/adr/ADR-005-target-lab-strategy.md)

The original DOCX ADR artifacts remain under `ADRS- PRD/` as historical
source material. The Markdown versions preserve their intent and identify
current implementation revisions explicitly.
