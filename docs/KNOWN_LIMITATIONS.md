# Known Limitations and Future Enhancements

Status: current local CLI MVP

This document distinguishes accepted constraints of the demonstrated MVP from
future product growth. Neither category is a claim that the control already
exists.

## Accepted MVP limitations

| Limitation | Consequence / accurate boundary |
| --- | --- |
| PAM host, root, OS-account, or process compromise | An attacker controlling these can observe process memory, read local keys/databases, alter code, or bypass application controls. This is outside the MVP protection scope. |
| Key/database co-location in the local lab | Vault and audit keys are distinct files/bytes but share the owner-only runtime directory with the databases. Database-only disclosure is protected; theft of the complete runtime is not. |
| Plaintext credentials briefly in memory | Both the PAM login password and decrypted target password necessarily exist during verification/use. They are not intentionally persisted or logged. |
| Python zeroization | Python immutable objects, copies, garbage collection, and dependency internals prevent a guarantee of deterministic secret-memory erasure. |
| No rate limiting or account lockout | Generic errors and dummy hashing reduce enumeration leakage but do not stop online guessing. The CLI is intended for a trusted local-host deployment boundary. |
| Limited pre-authentication audit | Authentication success/failure is not persisted because the current audit schema requires an actor and target. Access/session events begin after successful authentication and request construction. |
| Valid audit-tail truncation | The HMAC chain detects modified/reordered/interior-deleted records, but removing a valid suffix cannot be detected without an externally trusted chain-head anchor. |
| Local audit-key compromise | A party with the audit key and writable DB access can recompute a valid chain. Storage is tamper-evident while the key is trusted, not tamper-proof. |
| No session recording | Audit captures lifecycle metadata only. There is no command/output replay, and terminal content is intentionally not retained. |
| No command filtering | Once connected, the privileged account's target-side authorization applies. The broker does not inspect or restrict shell commands. |
| One privileged account per target | Repository and service behavior require unambiguous selection; multi-account selection is not modeled. |
| Direct user-based policy | Policies map user/target/action directly. There are no roles, groups, attributes, schedules, or contextual policy inputs. |
| Approval is fail-closed only | `REQUIRES_APPROVAL` is represented but cannot grant access because no approval workflow exists. |
| SQLite and single instance | Local files fit the one-host demo. There is no distributed transaction, multi-node coordination, or resilience claim. Provisioning spans multiple DBs without a distributed transaction and is intentionally one-shot. |
| Linux/POSIX terminal | Interactive relay relies on `termios`, `select`, and file descriptors. Windows terminals are unsupported. |
| Generic operational errors | Expected CLI failures hide adapter details and secrets, but cause-specific protected operator diagnostics are limited. Broker-open causes collapse to a generic session failure. |

## Future enhancements

| Enhancement | Product value |
| --- | --- |
| MFA | Strengthen PAM-user authentication beyond a single password. |
| Credential rotation | Change target secrets safely and revoke older material. |
| Key rotation and managed keys | Rotate Vault/audit keys and optionally use KMS/HSM or a separately protected key service/location. |
| Brute-force controls | Add rate limiting, backoff, lockout policy, and protected authentication telemetry. |
| RBAC/ABAC and JIT | Scale authorization from direct user rules to roles/attributes, expiring grants, and contextual controls. |
| Approval workflow | Implement approvers, durable request state, expiry, and auditable decisions for `REQUIRES_APPROVAL`. |
| Session recording and replay | Provide governed evidence with separate privacy, access-control, integrity, and retention design. |
| Command filtering | Add constrained-session policy where target-side controls alone are insufficient. |
| High availability | Replace local single-instance assumptions with coordinated durable services and explicit failure semantics. |
| External identity provider | Integrate LDAP/AD/OIDC/SAML and lifecycle-managed identities. |
| SSH certificates | Replace or complement reusable target passwords with short-lived signed credentials. |
| Remote SIEM/WORM audit | Export audit to independently administered, retention-controlled storage. |
| External chain-head anchoring | Publish or store trusted checkpoints so valid local tail truncation becomes detectable. |

The future list is not a public roadmap or a prerequisite for demonstrating
the current MVP. Any addition must be threat-modeled before changing the
security claims.
