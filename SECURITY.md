# Security Policy

## Security Architecture Decisions

This document explains the security architecture of Secure Proxy Manager and the rationale behind key security decisions.

### Docker Socket Removed

**Previous State**: The backend container had access to `/var/run/docker.sock` to query container statistics.

**Current State**: Docker socket access has been **removed** as of version 0.0.9.

**Rationale**: Mounting the Docker socket into a web-facing container creates a critical vulnerability. If an attacker compromises the backend application, they gain root-level access to the host system. This risk was deemed unacceptable for a security-focused proxy manager.

**Impact**: Container statistics (memory, CPU, uptime) now show "N/A" in the dashboard. Cache statistics are calculated from database logs instead.

**Future**: We may implement a Prometheus metrics endpoint on the proxy container for safer metrics collection.

---

### Non-Root Container Execution

The backend container now runs as a non-root user (`proxyuser`) to limit the blast radius of any potential container compromise.

---

### NET_ADMIN Capability

The proxy container requires `NET_ADMIN` capability for:
- Transparent proxy mode via iptables rules
- NAT redirection of HTTP/HTTPS traffic

**Risk**: This capability allows network configuration changes within the container. The proxy container does NOT have Docker socket access and is isolated from the backend.

**Mitigation**: If transparent proxy mode is not needed, you can remove this capability from `docker-compose.yml`:

```yaml
proxy:
  # Remove or comment out:
  # cap_add:
  #   - NET_ADMIN
```

---

### Authentication

The application uses HTTP Basic Authentication. While Basic Auth is simple, note:

- Always use HTTPS in production to protect credentials in transit
- Change the default `admin/admin` credentials immediately
- Credentials are stored hashed in SQLite

---

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it responsibly by opening a private security advisory on GitHub.

## Version History

- **0.0.9**: Removed Docker socket mount, enabled non-root user, security hardening
- **0.0.8**: Initial security headers and rate limiting
