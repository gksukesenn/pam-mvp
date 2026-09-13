# PAM lab end-to-end access

## Prerequisites

- Complete [Lab Setup](LAB_SETUP.md) first. It explains how to create the VM,
  discover its address, verify its host fingerprint, and provision portable
  target metadata.
- `linux-server-1` is running and the address stored in the provisioned
  `config.db` is reachable. The completed test environment used
  `192.168.122.227`; that address is not universal.
- `runtime/lab` has been created with the provisioning tool.
- The project virtual environment is active.

## Run

```bash
python -m src.main access \
    --runtime-dir ./runtime/lab \
    --username goksu \
    --target-id target-001
```

Enter only the PAM application password at the `PAM password:` prompt. The
target `pamadmin` password is loaded from the encrypted Vault and is never
prompted or displayed.

## Expected result

1. An SSH shell opens with a `pamadmin@linux-server-1` prompt.
2. `whoami` prints `pamadmin`.
3. `hostname` prints `linux-server-1`.
4. `exit` returns to the PAM CLI and prints `Session closed.`.
5. The local terminal behaves normally after exit.

The CLI exits with `0` after normal completion or an enforced maximum-duration
closure. Authentication failure, access denial, session failure, and
startup/internal failure use exit codes `2`, `3`, `4`, and `1`, respectively.

## Audit post-check

After an allowed session, confirm `runtime/lab/audit.db` exists. A normal
session contains `ACCESS_ALLOWED`, `SESSION_OPENING`, `SESSION_ACTIVE`, and
`SESSION_CLOSED`, written by `AccessService`. Verify integrity without
displaying events, MACs, or keys:

```bash
python -m src.tools.verify_audit --runtime-dir ./runtime/lab
```

Expected: `Audit integrity: OK` and exit `0`.
