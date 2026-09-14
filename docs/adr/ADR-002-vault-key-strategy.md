# ADR-002: Vault and Master Key Strategy

Status: accepted; local-MVP deployment note revised in Phase 10B-1

Historical source: [`ADRS- PRD/PAM-MVP-ADR-002-Vault-Key-Strategy.docx`](../../ADRS-%20PRD/PAM-MVP-ADR-002-Vault-Key-Strategy.docx)

## Context

The target credential must not be persisted in plaintext, committed to Git,
entered by the access operator, or exposed by ordinary object/error output.
The accepted decision addressed threats referenced as T02, T03, and T05 and
deferred complete PAM-host compromise as D01.

The original document evaluated source-embedded keys, environment variables,
a key beside the database, and a separately permissioned key file. It rejected
placing the key in the same storage location as the Vault because a single
filesystem disclosure could capture both.

## Decision

- Encrypt target credentials with AES-256-GCM.
- Generate a fresh 96-bit cryptographically random nonce per encryption.
- Obtain the 32-byte key through a `KeyProvider`; do not store it in source,
  Git, or `vault.db`.
- Resolve/decrypt credentials only after policy and configuration permit an
  access attempt.
- Fail closed on missing/invalid key, authentication-tag failure, or storage
  error.
- Use a separate key for audit HMAC; the Vault and audit key paths and bytes
  must be distinct.
- Treat KMS/HSM integration, backup, and rotation as future work.

`FileKeyProvider` and the Vault remain independent abstractions. This keeps a
stronger deployment possible without coupling domain/application code to a
particular key location.

## Current implementation note

The reproducible local lab stores these separate files beneath one provisioned
runtime directory:

```text
runtime/lab/
  vault.key
  audit.key
  auth.db
  config.db
  vault.db
  audit.db
```

The directory is `0700` and each key/database file is `0600`. The Vault key is
not in `vault.db`; the audit key is not in `audit.db`; key bytes are not
persisted in any database. Composition rejects equal canonical key paths and
equal key bytes. `FileKeyProvider` opens key leaf paths with `O_NOFOLLOW`,
validates the opened descriptor is a regular file, accepts only owner-only
permission modes, and reads exactly from that descriptor. Provisioning and
the lab access command reject a symbolic-link runtime-directory leaf; access
also requires the provisioned `0700` directory mode. SQLite leaf paths retain
the equivalent no-follow/regular-file protection.

`vault.db` schema version 1 validates the exact credential table shape,
primary key, and required `NOT NULL` constraints before use. An exact legacy
version-0 schema is recognized by shape and upgraded only by setting
`PRAGMA user_version = 1`; credential rows are not migrated or rewritten.
Unsupported versions, incompatible schemas, and malformed row types fail
closed.

For the local MVP, this co-located owner-only directory **supersedes the
historical rejection of a shared storage location as a deployment
requirement**. It preserves logical key separation and protects against
database-only theft or accidental DB disclosure. It does not protect copying
the complete runtime directory and does not claim to withstand compromise of
the PAM OS account, process, root, or host.

A KMS/HSM, secret service, or otherwise independently protected key location
remains deployment hardening for a broader product. The implementation's
`KeyProvider` boundary intentionally permits that evolution.

This is local leaf-path hardening, not a filesystem sandbox. Ancestor-path,
mount, PAM-account, and root control remain inside the trusted-host boundary.

## Consequences

- The current claim is narrower and testable: `vault.db` alone is insufficient
  to recover the credential.
- Lab setup remains reproducible with owner-only POSIX permissions.
- Backup and movement of the complete runtime must be treated as movement of
  all secrets, not as encrypted-data-only handling.
- Local key compromise defeats the corresponding at-rest/integrity control.
