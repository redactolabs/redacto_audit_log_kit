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

## 🏗️ Architecture

The Redacto Audit Log Kit is designed with flexibility in mind, featuring a modular architecture:

- **Client Interface**: A unified entry point for all audit log operations
- **Adapters**: Backend-specific implementations (currently supporting Grafana Loki)
- **Schema**: Standardized data models for audit events and queries
- **Django Integration**: Seamless integration with Django applications


