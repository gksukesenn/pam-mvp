# Domain Model

Status: implemented local CLI MVP

## Purpose and boundaries

The domain models the security-relevant facts and lifecycle of one privileged
access request. Application services orchestrate those facts through ports.
SQLite, Paramiko, Argon2, AES-GCM, terminal file descriptors, `argparse`,
`getpass`, and libvirt are implementation or lab concerns, not domain logic.

## Core concepts

| Concept | Meaning and important fields |
| --- | --- |
| `User` | Provisioned PAM identity: immutable `user_id`, normalized username, Argon2 password hash, and active flag. Its representation redacts the hash. |
| `AuthenticatedPrincipal` | Proof that authentication completed: `user_id` and username only. It contains no password or hash. |
| `AccessRequest` | Principal-bound intent: `user_id`, `target_id`, `AccessAction`, and timezone-aware `requested_at`. The current action is `OPEN_PRIVILEGED_SESSION`. |
| `AccessPolicy` | Direct user/target/action rule with `ALLOW`, `DENY`, or `REQUIRES_APPROVAL`. |
| `AccessDecision` | Fail-closed evaluator result with an allowed flag and stable non-secret reason code. |
| `Target` | Non-secret endpoint identity: ID, name, host, port, exact `HostKeyFingerprint`, and enabled flag. |
| `HostKeyFingerprint` | Validated `SHA256:` pin value used to compare the received SSH server key. |
| `PrivilegedAccount` | Non-secret target/account mapping: account ID, target ID, username, opaque `CredentialRef`, and enabled flag. |
| `CredentialRef` | Opaque identifier used to retrieve the target secret from the Vault. It is not the credential. |
| `Session` | State machine for one allowed access attempt, including identity, target/account IDs, start/end times, and terminal reason. It stores no credential or terminal bytes. |
| `AuditEvent` | Structured lifecycle fact with ID, event type, actor, target, session, timestamp, result, and optional reason. It contains no password, key, credential, or transcript. The SQLite adapter adds the sequence, previous MAC, and event MAC when persisting it. |

## Security invariants

### Authentication and identity

- Authentication precedes privileged access.
- The `AuthenticatedPrincipal` is the authority for identity. The CLI does not
  accept a `user_id`.
- `AccessService` requires `principal.user_id == request.user_id` before policy
  lookup. A mismatch cannot reach policy, configuration, Vault, or broker.
- Authentication failure exposes one generic public result for unknown user,
  wrong password, inactive user, and repository failure.

### Authorization and configuration

- No matching policy means `DENY`.
- Any matching explicit `DENY` takes precedence over `ALLOW`.
- `REQUIRES_APPROVAL` cannot grant access because no approval engine exists.
- A denial creates no `Session` and performs no Vault or broker call.
- An allowed request still requires one enabled valid target and one
  unambiguous enabled privileged account for that target.
- Target/account failure occurs before Vault and broker use.

### Credential and SSH ordering

```text
authenticated principal
  -> policy ALLOW
  -> enabled target
  -> exactly one enabled account reference
  -> Vault resolve(CredentialRef)
  -> TCP/SSH handshake
  -> compare received host key to pin
  -> target password authentication
  -> PTY
  -> shell
```

- Configuration contains only a `CredentialRef`, never the target password.
- The target password is resolved only after policy/configuration checks.
- The received host key must match before the password reaches the SSH
  authentication method.
- `Session`, `AuditEvent`, `Target`, and `PrivilegedAccount` never store the
  target credential.

### Session lifecycle

The valid transitions are deliberately narrow:

```text
OPENING -> ACTIVE -> CLOSED
    |         |
    +---------+-> FAILED
```

`CLOSED` and `FAILED` are terminal. Invalid transitions, double close, and
double failure are rejected. Entering terminal states requires an end time and
a non-empty reason. An allowed broker attempt therefore cannot be represented
as active indefinitely after an ordinary handled failure.

The terminal relay enforces a maximum total duration using monotonic elapsed
time. User activity does not extend it. Local raw-terminal changes live in an
outer context manager so normal logout, remote EOF, timeout, denial, relay
failure, and exceptions restore terminal attributes.

Session retains the invariant `ended_at >= started_at`. If the host UTC clock
moves behind `started_at`, `AccessService` clamps the terminal lifecycle
timestamp to `started_at` for both the terminal state and terminal audit event.
This deliberately preserves a valid terminal record; it does not claim that
the clamped value is a precise observation of wall-clock time. Duration
enforcement remains independent and monotonic.

### Audit lifecycle

The current production vocabulary is exactly:

- `ACCESS_ALLOWED`
- `ACCESS_DENIED`
- `SESSION_OPENING`
- `SESSION_ACTIVE`
- `SESSION_CLOSED`
- `SESSION_FAILED`

The application service owns these writes; CLI/tools do not duplicate them.
Authentication events and cause-specific SSH/Vault events are not part of the
current domain contract. See [ADR-004](adr/ADR-004-audit-integrity.md).

## Application services and ports

- `AuthenticationService` coordinates user lookup, dummy-hash behavior,
  Argon2 verification, active status, and principal creation through
  infrastructure-neutral authentication ports.
- `PolicyEvaluator` reduces policies to a fail-closed decision.
- `AccessService` coordinates identity binding, policy/config checks, Vault
  resolution, broker execution, session transitions, and lifecycle audit.

Ports describe cohesive capabilities such as user authentication storage,
policy/target/account lookup, Vault resolution, audit append, clock/ID supply,
and session brokering. They do not expose SQLite connections, Paramiko
transports, Argon2 objects, AES primitives, or CLI types.

The bootstrap layer is the composition root: it is allowed to instantiate
concrete adapters. The CLI and lab tools are outer boundaries. They parse
arguments, collect secrets, construct settings, invoke application services,
and map results; they do not decide authorization or implement cryptography.
