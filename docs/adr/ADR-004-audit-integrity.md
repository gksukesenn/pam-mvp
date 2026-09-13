# ADR-004: Audit and Integrity Strategy

Status: accepted; current event contract clarified in Phase 10B-1

Historical source: [`ADRS- PRD/PAM-MVP-ADR-004-Audit-Integrity.docx`](../../ADRS-%20PRD/PAM-MVP-ADR-004-Audit-Integrity.docx)

## Context

Privileged access needs structured lifecycle evidence without recording or
leaking secrets. The historical decision referenced T05 through T08 and
deferred sensitive terminal content/recording as D02. It described a broader
desired event set, including authentication, access-request, host-key, Vault,
and target-unavailable events.

## Decision retained

- Persist structured audit records through an append-only application port.
- Do not store PAM/target passwords, hashes, keys, ciphertext, credential
  objects, MAC secrets, or terminal content as audit payload.
- Link records with a deterministic HMAC-SHA256 chain covering every persisted
  event field, using a key separate from the Vault key.
- Verify links/sequences and use constant-time MAC comparison.
- Keep lifecycle audit orchestration in `AccessService`, not the CLI.
- Treat remote/WORM storage and external chain anchoring as future hardening.

The original ADR described HMAC as a `SHOULD`/MVP+ control. It is implemented
in the shipped MVP.

## Current implemented event contract

Production emits exactly these `AuditEventType` values:

- `ACCESS_ALLOWED`
- `ACCESS_DENIED`
- `SESSION_OPENING`
- `SESSION_ACTIVE`
- `SESSION_CLOSED`
- `SESSION_FAILED`

`SESSION_FAILED` uses the generic reason `broker_open_failed` when broker open
fails. Expected CLI errors are intentionally generic and do not expose raw
Paramiko, Vault, or SQLite details.

The historical broader coverage is **deferred, not implemented** in the
current MVP:

- no pre-authentication `AUTH_SUCCESS` or `AUTH_FAILURE`;
- no separate `ACCESS_REQUESTED`;
- no cause-specific `HOST_KEY_MISMATCH`, Vault-error, or
  target-unavailable event type.

Pre-authentication audit is constrained by the current event schema, which
requires both an actor and target. Cause-specific protected operator
observability needs a deliberate schema and disclosure policy; it must not be
inferred from generic user output. This clarification preserves the
historical design intent without claiming the code already fulfills it.

## Integrity boundary and consequences

The local chain detects changes to authenticated fields and interior deletion
or reordering while the audit key remains trusted. It is tamper-evident, not
tamper-proof. A valid suffix can be removed without detection when no external
trusted chain-head exists, and audit-key compromise permits chain
recomputation. The lab co-locates `audit.key` and `audit.db` in the protected
runtime directory, so complete runtime compromise is out of scope.

Audit persistence failure fails the access/session operation closed according
to the application lifecycle path; it is not silently converted into a
successful unaudited operation. Local SQLite remains a single-instance MVP
choice.
