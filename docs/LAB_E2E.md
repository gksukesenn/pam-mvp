# PAM lab end-to-end access

## Prerequisites

- `linux-server-1` is running and `192.168.122.227` is reachable.
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
displaying event MACs or keys:

```bash
python - <<'PY'
from pathlib import Path

from src.infrastructure.audit.sqlite_audit_repository import SQLiteAuditRepository
from src.infrastructure.security.file_key_provider import FileKeyProvider

root = Path("runtime/lab")
repository = SQLiteAuditRepository(
    root / "audit.db",
    FileKeyProvider(root / "audit.key"),
)
repository.verify_integrity()
print("Audit integrity verified.")
PY
```
