# ADR-003: Access Policy Model

Status: accepted

Historical source: [`ADRS- PRD/PAM-MVP-ADR-003-Access-Policy.docx`](../../ADRS-%20PRD/PAM-MVP-ADR-003-Access-Policy.docx)

## Context

The MVP needs a small authorization model that cannot accidentally permit
privileged access when policy is missing, contradictory, unsupported, or
unavailable. The accepted decision references T01 and T09.

## Decision

- Model policy directly as user, target, action, and effect.
- Support the action `OPEN_PRIVILEGED_SESSION`.
- Support effects `ALLOW`, `DENY`, and `REQUIRES_APPROVAL`.
- Default to `DENY` when no matching policy exists or policy storage fails.
- Give an explicit `DENY` precedence over any matching `ALLOW`.
- Do not allow `REQUIRES_APPROVAL` to open a session until an approval engine
  exists.
- Evaluate the identity from `AuthenticatedPrincipal`, never a caller-chosen
  `user_id`.
- Do not resolve Vault credentials or call the broker after denial.

## Current implementation

`AuthenticationService` creates the principal. The CLI uses its `user_id` to
build `AccessRequest`, and `AccessService` independently rejects a mismatch
before policy lookup. `PolicyEvaluator` implements the fail-closed reduction.
An allowed policy is necessary but not sufficient: the target and exactly one
privileged account must also exist, validate, and be enabled before Vault use.

## Consequences

The model is deliberately reviewable and sufficient for the single-user lab.
It does not implement roles, attributes, groups, schedules, JIT grants, or an
approval workflow. Those are product evolution, not hidden behavior in the
current `REQUIRES_APPROVAL` value.
