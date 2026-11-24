import os
from urllib.parse import urlsplit

from redacto_audit_log_kit.constants import (
    AUDIT_LOG_BACKEND_AUDIT_SERVER,
    AUDIT_LOG_BACKEND_LOKI,
    AUDIT_SERVER_BASE_URL_ENV,
    LOKI_BASE_URL_ENV,
    LOKI_METADATA_ESCAPED_BEFORE_NS_ENV,
)
from redacto_audit_log_kit.core import LokiProtocolAdapter
from redacto_audit_log_kit.exceptions import AuditKitConfigurationError


class GrafanaLokiAdapter(LokiProtocolAdapter):
    name = AUDIT_LOG_BACKEND_LOKI
    base_url_env = LOKI_BASE_URL_ENV
    store = "Loki"

    def metadata_is_escaped(self, timestamp_ns: int) -> bool:
        cutover = os.getenv(LOKI_METADATA_ESCAPED_BEFORE_NS_ENV)
        return not cutover or timestamp_ns < int(cutover)


class AuditServerAdapter(LokiProtocolAdapter):
    """
    audit-server serves Loki's API under its /audit base path. AUDIT_SERVER_BASE_URL
    carries the service's client credentials as userinfo, e.g.
    http://<client-id>:<client-secret>@audit-server:8080/audit; requests sends them
    as HTTP Basic auth.
    """

    name = AUDIT_LOG_BACKEND_AUDIT_SERVER
    base_url_env = AUDIT_SERVER_BASE_URL_ENV
    store = "audit-server"
    error_hints = {
        401: f"the credentials in {AUDIT_SERVER_BASE_URL_ENV} were rejected",
        403: "this client may not use this service_name; add it to its AUDIT_CLIENTS entry",
    }

    def __init__(self):
        super().__init__()
        url = urlsplit(self.base_url())
        if not (url.username and url.password):
            raise AuditKitConfigurationError(
                f"{AUDIT_SERVER_BASE_URL_ENV} must carry the client credentials, "
                "http://<client-id>:<client-secret>@<host>/audit"
            )
