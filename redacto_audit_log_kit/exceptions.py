"""
Custom exceptions for the Redacto Audit Log Kit.
All exception messages start with 'REDACTO AUDIT LOG KIT ERROR ...'
"""

class AuditKitError(Exception):
    """Base exception for all Redacto Audit Log Kit errors."""
    def __init__(self, message):
        super().__init__(f"REDACTO AUDIT LOG KIT ERROR: {message}")

class AuditKitConfigurationError(AuditKitError):
    """Raised for configuration errors (e.g., missing env vars)."""
    pass

class AuditKitConnectionError(AuditKitError):
    """Raised for network/connection errors to external services."""
    pass

class AuditKitExternalServiceError(AuditKitError):
    """Raised when the external service returns an error response."""
    def __init__(self, status_code, message):
        super().__init__(f"External Service error {status_code}: {message}")
        self.status_code = status_code

class AuditKitInvalidDataError(AuditKitError):
    """Raised for invalid or malformed audit log data."""
    pass

class AuditKitEventProcessingError(AuditKitError):
    """Raised for errors during event definition or transformation."""
    pass