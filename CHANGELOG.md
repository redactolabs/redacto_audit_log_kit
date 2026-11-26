# Changelog

## [0.3.0](https://github.com/redactolabs/redacto_audit_log_kit/compare/v0.2.0...v0.3.0) (2026-11-26)


### Features

* choose the read store and reconcile Loki against audit-server ([27db748](https://github.com/redactolabs/redacto_audit_log_kit/commit/27db748fe87f372eb86debb6d059ab475dd9c38b))
* dual-write pushed events to audit-server ([411200e](https://github.com/redactolabs/redacto_audit_log_kit/commit/411200ee6e74af84abe821919f21f038091ea625))
* dual-write pushed events to audit-server ([8255aba](https://github.com/redactolabs/redacto_audit_log_kit/commit/8255aba55ab5e4c1ac74d823b335518e4f2bd841))
* normalize reads with get_page and share one adapter base ([e8942dd](https://github.com/redactolabs/redacto_audit_log_kit/commit/e8942dda27b505bea55df62fdfd4de94d56acdcd))


### Bug Fixes

* exit 2 when reconcile cannot read a store ([39b3de7](https://github.com/redactolabs/redacto_audit_log_kit/commit/39b3de74727188b1e5c93365fa903610d30020af))
* give query_range reads a 30s timeout ([0f27629](https://github.com/redactolabs/redacto_audit_log_kit/commit/0f276295e3fb80a2abc2d9a6952a72adc615bafe))
* harden kit pushes for audit-server (timeout, no URL print, stable retries) ([7f03329](https://github.com/redactolabs/redacto_audit_log_kit/commit/7f03329b493dbce7d37d105dcfd2433337bae4a7))
* raise a retryable store failure ahead of a permanent one ([4d7dbc2](https://github.com/redactolabs/redacto_audit_log_kit/commit/4d7dbc2afdfa87f257b2ca3fc8b78d410b0b3af9))
* stamp an event's time once so a retried push dedupes ([762bf04](https://github.com/redactolabs/redacto_audit_log_kit/commit/762bf04c0086f26545b08f7e1e5bf111df59f3bd))
* time out kit HTTP calls and stop printing the base URL ([6481947](https://github.com/redactolabs/redacto_audit_log_kit/commit/6481947bb2b518d4f60a89beba53c8424d1f5c24))
