# Matches the Go ledger's Loki client and audit-server's write timeout; a hung backend
# otherwise holds the Dramatiq worker until its time limit kills it.
PUSH_TIMEOUT_SECONDS = 10
# Loki's HTTP server cuts a response at its default 30s write timeout, so a long-range
# query_range can take that long and waiting longer gains nothing.
QUERY_TIMEOUT_SECONDS = 30

AUDIT_LOG_SIGNING_KEY_ENV = "AUDIT_LOG_SIGNING_KEY"
LOKI_BASE_URL_ENV = "LOKI_BASE_URL"
AUDIT_SERVER_BASE_URL_ENV = "AUDIT_SERVER_BASE_URL"
LOKI_METADATA_ESCAPED_BEFORE_NS_ENV = "LOKI_METADATA_ESCAPED_BEFORE_NS"

AUDIT_LOG_BACKEND_ENV = "AUDIT_LOG_BACKEND"
AUDIT_LOG_READ_FROM_ENV = "AUDIT_LOG_READ_FROM"
AUDIT_LOG_BACKEND_LOKI = "loki"
AUDIT_LOG_BACKEND_DUAL = "dual"
AUDIT_LOG_BACKEND_AUDIT_SERVER = "audit_server"
