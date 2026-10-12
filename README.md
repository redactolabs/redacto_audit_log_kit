# Redacto Audit Log Kit

![Redacto](https://img.shields.io/badge/Redacto-Audit%20Log%20Kit-blue)
[![Python](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/release/python-312/)
[![Django](https://img.shields.io/badge/django-4.2%2B-green.svg)](https://www.djangoproject.com/)

A unified audit logging solution for all Redacto services. This package provides a standardized approach to record, store, and query audit logs across the entire Redacto ecosystem.

## 🚀 Features

- Standardized audit event schema across services
- Configurable adapters for different audit log backends
- Comprehensive search query generation
- Django integration
- Unified interface for logging and retrieving audit events

## 📦 Installation

### Installing from Private GitHub Repository

1. **Add to your project's `pyproject.toml`**:

```toml
[tool.poetry.dependencies]
# Your other dependencies
redacto-audit-log-kit = {git = "git@github.com:redactolabs/redacto_audit_log_kit.git"}
```

2. **Configure SSH for GitHub access**:

Follow the guide at [Setting up SSH keys with GitHub](https://leangaurav.medium.com/setup-ssh-key-with-git-github-clone-private-repo-using-ssh-d983ab7bb956) to set up SSH authentication.

3. **Docker Integration**:

Update your `Dockerfile` to include SSH configuration:

```dockerfile
# Add SSH support for private repositories
RUN mkdir -p /root/.ssh && \
    ssh-keyscan github.com >> /root/.ssh/known_hosts

# Use SSH mount to access credentials during build
RUN --mount=type=ssh poetry install --no-interaction --no-cache
```

And in your `docker-compose.yml`:

```yaml
services:
  your_service:
    build:
      context: .
      ssh:
        - default  # Uses the SSH agent socket from your host
    # other configuration...
```

4. **Install the package**:

```bash
# Using Poetry (with SSH configured)
poetry install redacto_audit_log_kit
```

## 🧪 Running Tests

The package includes unit tests located in `redacto_audit_log_kit/tests/`. Tests are divided into two categories:

- **Unit Tests**: Tests that don't require external dependencies (default)
- **Integration Tests**: Tests that require a running Loki instance

### Run Unit Tests Only (No Loki Required)

By default, tests requiring a Loki instance are skipped. You can also explicitly set `SKIP_INTEGRATION_TESTS=1`:

```bash
# From the redacto_audit_log_kit subdirectory
cd redacto_audit_log_kit

# Default behavior (skips Loki tests)
python -m unittest discover -s tests -p "test_*.py"

```

### Run All Tests (Including Loki Integration Tests)

To run tests that require a running Loki instance, set `SKIP_INTEGRATION_TESTS=0`:

```bash
# Ensure Loki is running, then:
cd redacto_audit_log_kit
SKIP_INTEGRATION_TESTS=0 python -m unittest discover -s tests -p "test_*.py"
```

### Run Individual Test Files

```bash
# Run specific test file
python -m unittest tests.test_audit_client_flow
python -m unittest tests.test_generate_search_query
python -m unittest tests.test_logql_query_generation
```

### Run with Verbose Output

```bash
# Unit tests only (verbose)
python -m unittest discover -s tests -p "test_*.py" -v

# All tests including Loki integration (verbose)
SKIP_INTEGRATION_TESTS=0 python -m unittest discover -s tests -p "test_*.py" -v
```

## 🔐 Event Signing (HMAC-SHA256)

Starting from the next version, the Audit Log Kit signs all events with HMAC-SHA256 to ensure tamper-proofing of individual log records. This is a **breaking change** that requires configuration before upgrading.

### Migration Guide

**⚠️ Important:** You must configure the signing key on all microservices *before* deploying the updated Audit Log Kit.

#### Step 1: Generate a Signing Key

Generate a secure 256-bit (32-byte) key:

```bash
# Using Python
python -c "import secrets; print(secrets.token_hex(32))"

# Using OpenSSL
openssl rand -hex 32
```

#### Step 2: Configure Environment Variables

Add the signing key to all microservices that use the Audit Log Kit:

```bash
# Required for all services using the Audit Log Kit
export AUDIT_LOG_SIGNING_KEY="your-256-bit-hex-key-here"
```

For Docker deployments, add to your `docker-compose.yml` or secrets management:

```yaml
services:
  your_service:
    environment:
      - AUDIT_LOG_SIGNING_KEY=${AUDIT_LOG_SIGNING_KEY}
```

#### Step 3: Deploy

1. **First**, deploy the environment variable changes to all microservices
2. **Then**, upgrade the Audit Log Kit package across services
3. Verify events are being signed by checking for `event_signature` in structured metadata

### Verifying Event Signatures

To verify an event's integrity:

```python
from redacto_audit_log_kit.signing import verify_event_signature

# event_dict should have: timestamp, body, labels, structured_metadata
signature = event_dict["structured_metadata"]["event_signature"]
is_valid = verify_event_signature(event_dict, signature, signing_key)

if not is_valid:
    # Event has been tampered with
    raise ValueError("Audit log integrity check failed")
```

## 🏷️ Category, Attributes and Event IDs (0.2.0)

Four optional fields on `AuditEvent`. All are additive: an event that sets none of them produces exactly the same labels, structured metadata, body and signature as 0.1.0.

| Field | Type | Written to Loki as |
|---|---|---|
| `log_category` | `consent_lifecycle` \| `system_processing` \| `grievance_rights` | Stream **label**, only when set |
| `attributes` | `dict[str, str]`, keys `^[a-z][a-z0-9_]*$`, max 64 chars, max 100 keys | Structured metadata, each key prefixed `attr_` |
| `event_id` | lowercase canonical UUID of any version: `new_event_id()` for a fresh UUIDv7, or a deterministic UUIDv5 for events that must deduplicate across retries or producers | Structured metadata |
| `actor_type` | `human_user` \| `end_user` \| `service_account` \| `scheduled_job` \| `system` | Structured metadata |

```python
from redacto_audit_log_kit.attributes import build_attributes
from redacto_audit_log_kit.schema import AuditEvent, new_event_id

AuditEvent(
    organization_uuid=org_uuid,
    workspace_uuid=workspace_uuid,
    service_name="consent",
    action="accessed",
    crud="r",
    actor_name=actor_name,
    actor_uuid=actor_uuid,
    resource_type="user_consent",
    resource_uuid=resource_uuid,
    description="Accessed consent history",
    log_category="grievance_rights",
    event_id=new_event_id(),
    actor_type="end_user",
    attributes=build_attributes({"identifier_field": "org_user_id", "result_count": 3}),
)
```

- Put extra detail in `attributes` instead of appending `key=value` text to `description`, and build it with `build_attributes(extra_fields)` rather than by hand. It normalizes keys to `^[a-z][a-z0-9_]*$` (64 chars max), turns values into strings (`true`/`false`, compact JSON with sorted keys for lists and dicts, `str()` otherwise), drops `None`, truncates any value over 8 KB with `...[truncated N bytes]`, keeps the total under 48 KB and at most 100 keys, and lists anything it had to drop in `dropped_attributes` (or `N attributes` when the list itself is too long). `AuditEvent` rejects attributes over these caps, so a hand-built dict can't produce a line Loki refuses. The Go ledger applies the same rules.
- Personal data is allowed in `description` and `attributes`. Audit logs are retained compliance evidence under the DPDP Act: they prove who did what to whose data, so they may name the data principal or the operator. They are never erased per data principal; rows leave Loki only through the per-category retention rules.
- `log_category` is a label so Loki `retention_stream` rules can keep each DPDP category for its own period. Query it with `SearchQuery(log_category=...)`.
- `event_id` gives every event a stable id for deduplication, including a later backfill from Loki into Postgres. Use a fresh UUIDv7 per request-driven action. For an event that happens at most once per resource and can be re-sent by a retried task or by another producer (consent granted/denied/expired, user linked/nominated), derive a UUIDv5 from a stable key instead with `derive_event_id("consent.event:<uuid>")`, which the Go ledger's `DeriveEventID` reproduces exactly. Validation accepts any UUID version, so don't extract a timestamp from the id.
- Every new field is covered by `event_signature`.

### Upgrading

1. Pin a tag instead of `branch = "main"`: `redacto-audit-log-kit = {git = "https://github.com/redactolabs/redacto_audit_log_kit", tag = "v0.2.0"}` and re-lock.
2. Deploy the version bump on its own. No code change is needed and output is unchanged.
3. Only after **every** worker that builds `AuditEvent` from a queued payload runs 0.2.0, start setting the new fields. A 0.1.0 worker silently drops unknown keys, so an event sent with the new fields during a mixed rollout would lose its category and attributes.

## 🏗️ Architecture

The Redacto Audit Log Kit is designed with flexibility in mind, featuring a modular architecture:

- **Client Interface**: A unified entry point for all audit log operations
- **Adapters**: Backend-specific implementations (currently supporting Grafana Loki)
- **Schema**: Standardized data models for audit events and queries
- **Django Integration**: Seamless integration with Django applications


