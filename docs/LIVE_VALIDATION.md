# Live Validation Record

This is a sanitized record of manual environment-specific evidence completed
before Phase 10B-1. The exact execution date was not retained in tracked
artifacts. No password, key bytes, ciphertext, MAC, or terminal transcript is
recorded here.

## Environment

- Fedora Linux host
- QEMU/KVM and libvirt default NAT network
- Debian 13 minimal target
- target name/hostname: `linux-server-1`
- tested address/port: `192.168.122.227:22`
- privileged target account: `pamadmin`
- local Python CLI PAM MVP

The address and pinned host key belong to this tested VM. They are not
portable defaults for another engineer; see [Lab Setup](LAB_SETUP.md).

## Successful access

The operator ran the access command, entered the PAM application password at a
non-echoing prompt, and was not prompted for the target password. The brokered
shell opened and harmless identity checks produced:

```text
whoami   -> pamadmin
hostname -> linux-server-1
exit     -> Session closed.
```

The command returned normally and the local terminal mode was restored.

## Negative validation matrix

| Scenario | Observed user-visible result | Exit code | Evidence established |
| --- | --- | ---: | --- |
| Wrong PAM password against baseline | `Authentication failed.`; no shell | 2 | Authentication gates the access command and does not disclose the failure cause. |
| Policy changed to `DENY` in isolated runtime | `Access denied.`; no shell | 3 | Explicit policy denial is enforced in the integrated path. |
| Target disabled in isolated runtime | `Access denied.`; no shell | 3 | Disabled target cannot open a session. |
| Privileged account disabled in isolated runtime | `Access denied.`; no shell | 3 | Disabled account cannot open a session. |
| Deliberately wrong pinned host key in isolated runtime | `Privileged session failed.`; no shell | 4 | Host identity mismatch denies the live connection without exposing Paramiko details. Automated tests, not this observation alone, prove password authentication was not called. |
| Wrong target SSH password in separately provisioned runtime | `Privileged session failed.`; no shell | 4 | Correct host verification followed by failed target authentication is handled safely. |
| Five-second maximum total duration | `Session closed: maximum duration reached.` | 0 | An active shell is closed at the total duration and timeout is a controlled close. |
| Baseline audit verification | `Audit integrity: OK` | 0 | The current local chain verifies with its configured key. |
| Copied audit with one persisted field modified | `Audit integrity: FAILED` | nonzero | Direct modification is detected without displaying record/MAC/key detail. |
| Baseline verified again after copied tamper | `Audit integrity: OK` | 0 | Scenario tooling/tampering did not alter the baseline runtime. |

The isolated preparation and exact operator commands are documented in
[Negative E2E](LAB_NEGATIVE_E2E.md). Runtime key/database permission hardening
was also verified separately: provisioned directories are owner-only and
runtime artifacts are `0600`.

## Evidence limits

These results demonstrate one real integration environment; they are not
automated CI tests and do not establish portability to an arbitrary VM,
network, terminal, or SSH server. Internal properties such as “bad pin results
in zero password-authentication calls,” “DENY reaches neither Vault nor
broker,” and terminal restoration on injected exceptions are established by
the automated suite.

No terminal session transcript is retained. The audit contains structured
access/session lifecycle metadata only. Successful tamper detection does not
make local audit tamper-proof: valid tail truncation and chain recomputation
after audit-key compromise remain documented limitations.
