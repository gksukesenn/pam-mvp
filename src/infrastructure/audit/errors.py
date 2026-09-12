class AuditStorageError(Exception):
    """Raised when an audit event cannot be persisted safely."""


class DuplicateAuditEventError(AuditStorageError):
    """Raised when an audit event ID has already been persisted."""


class AuditIntegrityError(AuditStorageError):
    """Raised when persisted audit-chain integrity cannot be verified."""


class UnsupportedAuditSchemaError(AuditStorageError):
    """Raised when an audit database uses an unsupported schema."""
