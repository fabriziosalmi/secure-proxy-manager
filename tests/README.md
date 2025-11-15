# Tests Directory

This directory contains test suites for Secure Proxy Manager.

## Available Tests

### 🧪 [e2e_test.py](e2e_test.py)

Comprehensive end-to-end testing script that validates:
- Proxy connectivity and basic functionality
- Domain and IP blacklisting
- HTTPS filtering and SSL inspection
- Direct IP blocking
- API endpoints and authentication
- Configuration validation

## Running Tests

### Prerequisites

Install required Python packages:

```bash
pip install rich requests
```

Or use the automatic installation (script will install dependencies if missing).

### Basic Test Execution

```bash
# Make sure Secure Proxy Manager is running
docker-compose up -d

# Run tests from the repository root
cd tests
python3 e2e_test.py
```

### Test Options

```bash
# Verbose output
python3 e2e_test.py -v

# Custom proxy configuration
python3 e2e_test.py --proxy-host localhost --proxy-port 3128

# Custom UI configuration
python3 e2e_test.py --ui-host localhost --ui-port 8011
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--proxy-host` | Proxy server hostname | `localhost` |
| `--proxy-port` | Proxy server port | `3128` |
| `--ui-host` | Web UI hostname | `localhost` |
| `--ui-port` | Web UI port | `8011` |
| `-v, --verbose` | Enable verbose output | `False` |

## Test Coverage

The end-to-end test suite validates:

1. **Proxy Connectivity**
   - HTTP proxy connection
   - HTTPS proxy connection
   - Basic request forwarding

2. **Security Features**
   - Domain blacklist enforcement
   - IP blacklist enforcement
   - Direct IP access blocking
   - HTTPS filtering capabilities

3. **API Functionality**
   - Authentication
   - Blacklist management endpoints
   - Configuration endpoints
   - Status and health checks

4. **Configuration Validation**
   - Squid configuration parsing
   - Security settings verification
   - ACL rule validation

## Understanding Test Results

Tests use color-coded output:
- ✅ **Green**: Test passed
- ❌ **Red**: Test failed
- ⚠️ **Yellow**: Warning or skipped
- ℹ️ **Blue**: Information

## Continuous Integration

These tests can be integrated into CI/CD pipelines. Example for GitHub Actions:

```yaml
- name: Run End-to-End Tests
  run: |
    docker-compose up -d
    sleep 15  # Wait for services to be ready
    cd tests
    pip install rich requests
    python3 e2e_test.py
```

## Contributing Test Cases

When adding new features, please:

1. Add corresponding test cases to `e2e_test.py`
2. Ensure tests are atomic and independent
3. Use descriptive test names
4. Include both positive and negative test cases
5. Document any special setup requirements

See [CONTRIBUTING.md](../CONTRIBUTING.md) for detailed guidelines.

## Troubleshooting Tests

### Tests Failing to Connect

```bash
# Check if services are running
docker-compose ps

# View service logs
docker-compose logs backend
docker-compose logs proxy

# Restart services
docker-compose restart
```

### Permission Errors

```bash
# Ensure script has execute permissions
chmod +x e2e_test.py

# Check Python version (3.6+ required)
python3 --version
```

### Import Errors

```bash
# Install missing dependencies
pip install -r ../backend/requirements.txt
pip install rich requests
```

## Test Development

To add new tests:

1. Follow the existing test structure in `e2e_test.py`
2. Use the `ProxyTester` class framework
3. Add clear assertions and error messages
4. Test both success and failure scenarios
5. Update this README with new test descriptions

## Additional Resources

- [Main README](../README.md) - Project documentation
- [API Documentation](../README.md#-api-documentation) - API reference
- [Contributing Guide](../CONTRIBUTING.md) - Contribution guidelines

---

**Note:** Always run tests against a test/development instance, not production systems.
