import os

from redacto_audit_log_kit.adapter import AuditServerAdapter, GrafanaLokiAdapter
from redacto_audit_log_kit.exceptions import AuditKitConfigurationError

AUDIT_LOG_BACKEND_ENV = "AUDIT_LOG_BACKEND"
AUDIT_LOG_BACKEND_LOKI = "loki"
AUDIT_LOG_BACKEND_DUAL = "dual"
AUDIT_LOG_BACKEND_AUDIT_SERVER = "audit_server"
AUDIT_LOG_READ_FROM_ENV = "AUDIT_LOG_READ_FROM"

BACKENDS = {
    AUDIT_LOG_BACKEND_LOKI: (GrafanaLokiAdapter,),
    AUDIT_LOG_BACKEND_DUAL: (GrafanaLokiAdapter, AuditServerAdapter),
    AUDIT_LOG_BACKEND_AUDIT_SERVER: (AuditServerAdapter,),
}


def adapters_from_env() -> list:
    """
    Builds the adapters AUDIT_LOG_BACKEND names, in write order: "loki" (the default
    when unset), "dual" (Loki, then audit-server) or "audit_server". A bad value or
    URL raises here, so a bad deploy fails at startup instead of on every event.
    """
    backend = os.getenv(AUDIT_LOG_BACKEND_ENV, AUDIT_LOG_BACKEND_LOKI).strip().lower()
    if backend not in BACKENDS:
        raise AuditKitConfigurationError(
            f"{AUDIT_LOG_BACKEND_ENV}={backend!r} is not one of {', '.join(BACKENDS)}."
        )
    return [adapter() for adapter in BACKENDS[backend]]


def reader_from_env(adapters: list):
    """
    Picks which of the written adapters reads go to. AUDIT_LOG_READ_FROM names "loki"
    or "audit_server"; unset, reads go to Loki while it is written, because only Loki
    holds the events from before audit-server was switched on.
    """
    read_from = os.getenv(AUDIT_LOG_READ_FROM_ENV, "").strip().lower()
    if not read_from:
        return next((a for a in adapters if a.name == AUDIT_LOG_BACKEND_LOKI), adapters[0])
    reader = next((a for a in adapters if a.name == read_from), None)
    if reader is None:
        raise AuditKitConfigurationError(
            f"{AUDIT_LOG_READ_FROM_ENV}={read_from!r} names no store {AUDIT_LOG_BACKEND_ENV} writes."
        )
    return reader
