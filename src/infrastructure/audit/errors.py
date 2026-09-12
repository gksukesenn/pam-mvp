class AuditStorageError(Exception):
    """Raised when an audit event cannot be persisted safely."""


class DuplicateAuditEventError(AuditStorageError):
    """Raised when an audit event ID has already been persisted."""
