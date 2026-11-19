# Changelog

## [0.2.1](https://github.com/redactolabs/redacto_audit_log_kit/compare/v0.2.0...v0.2.1) (2026-11-19)


### Bug Fixes

* give query_range reads a 30s timeout ([0f27629](https://github.com/redactolabs/redacto_audit_log_kit/commit/0f276295e3fb80a2abc2d9a6952a72adc615bafe))
* harden kit pushes for audit-server (timeout, no URL print, stable retries) ([7f03329](https://github.com/redactolabs/redacto_audit_log_kit/commit/7f03329b493dbce7d37d105dcfd2433337bae4a7))
* stamp an event's time once so a retried push dedupes ([762bf04](https://github.com/redactolabs/redacto_audit_log_kit/commit/762bf04c0086f26545b08f7e1e5bf111df59f3bd))
* time out kit HTTP calls and stop printing the base URL ([6481947](https://github.com/redactolabs/redacto_audit_log_kit/commit/6481947bb2b518d4f60a89beba53c8424d1f5c24))
