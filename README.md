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

## 🏗️ Architecture

The Redacto Audit Log Kit is designed with flexibility in mind, featuring a modular architecture:

- **Client Interface**: A unified entry point for all audit log operations
- **Adapters**: Backend-specific implementations (currently supporting Grafana Loki)
- **Schema**: Standardized data models for audit events and queries
- **Django Integration**: Seamless integration with Django applications
