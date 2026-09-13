# PAM lab negative security validation

Run these checks manually from the repository with the virtual environment
active. Codex does not run live network checks. Never use
`runtime/lab` as a scenario destination: the preparation tool rejects it.
Every scenario destination is one-shot; remove it manually before recreating
it. Do not prepare a copy while another PAM CLI process is writing the
baseline audit database. No command below contains a password.

After each access command, run `echo $?` to observe its exit code.

## Scenario preparation

```bash
python -m src.tools.prepare_negative_lab --source ./runtime/lab \
    --destination ./runtime/scenarios/deny --scenario deny
python -m src.tools.prepare_negative_lab --source ./runtime/lab \
    --destination ./runtime/scenarios/disabled-target \
    --scenario disabled-target
python -m src.tools.prepare_negative_lab --source ./runtime/lab \
    --destination ./runtime/scenarios/disabled-account \
    --scenario disabled-account
python -m src.tools.prepare_negative_lab --source ./runtime/lab \
    --destination ./runtime/scenarios/bad-host-key --scenario bad-host-key
```

Prepared directories are `0700`; copied keys and databases are `0600`.
Preparation copies only known runtime files and changes only the selected copy.

## Manual test matrix

Use this command template, substituting the runtime directory shown below:

```bash
python -m src.main access --runtime-dir RUNTIME_DIRECTORY \
    --username goksu --target-id target-001
```

| Scenario | VM | Runtime | Expected output / exit | Invariant |
| --- | --- | --- | --- | --- |
| Wrong PAM password | Not required; may be OFF | `runtime/lab` | `Authentication failed.` / `2` | Authentication failure never reaches `AccessService`, SSH, or the target credential path. |
| DENY policy | Not required; may be OFF | `runtime/scenarios/deny` | `Access denied.` / `3` | PAM authentication succeeds; `ACCESS_DENIED` is audited; Vault and broker are not reached. |
| Disabled target | Not required; may be OFF | `runtime/scenarios/disabled-target` | `Access denied.` / `3` | Denial reason is `target_disabled`; account, Vault, and broker are not reached. |
| Disabled account | Not required; may be OFF | `runtime/scenarios/disabled-account` | `Access denied.` / `3` | Denial reason is `privileged_account_disabled`; Vault and broker are not reached. |
| Bad host key | ON and reachable | `runtime/scenarios/bad-host-key` | `Privileged session failed.` / `4` | The connection is rejected at pinned-key verification and no shell opens. |

For the wrong PAM-password case, enter an intentionally wrong PAM application
password at the prompt. For the other four cases, enter the correct PAM
application password. The CLI never prompts for the target password.

The live bad-host-key result demonstrates connection denial. The existing
automated connector regression proves that Paramiko `auth_password` receives
zero calls after a host-key mismatch.

## Wrong target credential

The VM must be ON and reachable. Create a new isolated runtime; never edit the
baseline Vault:

```bash
python -m src.tools.provision_lab \
    --runtime-dir ./runtime/scenarios/wrong-target-password
python -m src.main access \
    --runtime-dir ./runtime/scenarios/wrong-target-password \
    --username goksu --target-id target-001
```

During provisioning, enter the intended PAM application password and an
intentionally wrong `pamadmin` SSH password. Access must authenticate the PAM
user, verify the host key, fail SSH password authentication, open no shell,
print `Privileged session failed.`, and exit `4`. Passwords must not appear in
CLI or audit output.

## Maximum elapsed duration

The VM must be ON and reachable. Use the unchanged baseline:

```bash
python -m src.main access --runtime-dir ./runtime/lab \
    --username goksu --target-id target-001 --max-session-seconds 5
```

After successful login, the session must terminate after approximately five
elapsed seconds even with activity. The CLI prints
`Session closed: maximum duration reached.`, exits `0`, records
`SESSION_CLOSED` with `max_duration_exceeded`, and restores the local terminal.
Timeout is a controlled close, not a failure.

## Audit integrity and tampering

The VM may be OFF. First verify the untouched baseline:

```bash
python -m src.tools.verify_audit --runtime-dir ./runtime/lab
```

Expected: `Audit integrity: OK` and exit `0`.

Prepare and verify an isolated tampered copy:

```bash
python -m src.tools.prepare_negative_lab --source ./runtime/lab \
    --destination ./runtime/scenarios/tampered-audit \
    --scenario tampered-audit
python -m src.tools.verify_audit \
    --runtime-dir ./runtime/scenarios/tampered-audit
python -m src.tools.verify_audit --runtime-dir ./runtime/lab
```

The tampered copy prints `Audit integrity: FAILED` and exits `1`; the baseline
still prints `Audit integrity: OK`. Verification never displays events, MACs,
or keys. Valid tail truncation remains undetectable without an externally
anchored trusted chain head.

## Cleanup

After recording results, remove only the explicit scenario directories:

```bash
rm -r -- runtime/scenarios/deny
rm -r -- runtime/scenarios/disabled-target
rm -r -- runtime/scenarios/disabled-account
rm -r -- runtime/scenarios/bad-host-key
rm -r -- runtime/scenarios/wrong-target-password
rm -r -- runtime/scenarios/tampered-audit
```

Do not remove or modify `runtime/lab`.
