# Contributing to Secure Proxy Manager

Thank you for your interest in contributing to Secure Proxy Manager! We welcome contributions from the community and appreciate your efforts to improve the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Enhancements](#suggesting-enhancements)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and collaborative environment for everyone. Please be kind and courteous in all interactions.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/secure-proxy-manager.git
   cd secure-proxy-manager
   ```
3. **Add the upstream repository** as a remote:
   ```bash
   git remote add upstream https://github.com/fabriziosalmi/secure-proxy-manager.git
   ```

## How to Contribute

### Reporting Bugs

If you find a bug, please create an issue on GitHub with the following information:

- **Clear title** describing the bug
- **Detailed description** of the issue
- **Steps to reproduce** the behavior
- **Expected behavior** vs actual behavior
- **Environment details** (OS, Docker version, browser, etc.)
- **Screenshots or logs** if applicable

### Suggesting Enhancements

We welcome feature suggestions! Please create an issue with:

- **Clear title** describing the enhancement
- **Detailed description** of the proposed feature
- **Use case** explaining why this would be valuable
- **Possible implementation** approach (if you have ideas)

### Code Contributions

1. **Check existing issues** to see if someone is already working on it
2. **Create an issue** first for major changes to discuss the approach
3. **Follow the branch naming convention** (see below)
4. **Make your changes** following our coding standards
5. **Test your changes** thoroughly
6. **Submit a pull request** with a clear description

## Development Setup

### Prerequisites

- Docker (v20.10.0+)
- Docker Compose (v2.0.0+)
- Python 3.9+ (for local testing)
- Git

### Local Development

1. **Start the development environment**:
   ```bash
   docker-compose up -d
   ```

2. **View logs** to ensure all services are running:
   ```bash
   docker-compose logs -f
   ```

3. **Access the application**:
   - Web UI: http://localhost:8011
   - Backend API: http://localhost:5001
   - Proxy: http://localhost:3128

4. **Stop the environment**:
   ```bash
   docker-compose down
   ```

### Running Tests Locally

Execute the end-to-end test suite:

```bash
cd tests
python3 e2e_test.py
```

Install test dependencies if needed:

```bash
pip install rich requests
```

## Coding Standards

### Python Code

- Follow **PEP 8** style guidelines
- Use **meaningful variable names**
- Add **docstrings** to functions and classes
- Keep functions **focused and concise**
- Use **type hints** where appropriate

Example:
```python
def add_ip_to_blacklist(ip_address: str) -> bool:
    """
    Add an IP address to the blacklist.
    
    Args:
        ip_address: The IP address to blacklist
        
    Returns:
        True if successful, False otherwise
    """
    # Implementation here
    pass
```

### JavaScript/HTML/CSS

- Use **consistent indentation** (2 spaces)
- Follow **Bootstrap conventions** for UI components
- Keep JavaScript **modular and well-commented**

### Git Commit Messages

Write clear, descriptive commit messages:

- Use the **imperative mood** ("Add feature" not "Added feature")
- Keep the **first line under 50 characters**
- Provide **detailed explanation** in the body if needed
- Reference **issue numbers** when applicable

Examples:
```
feat: Add support for IPv6 blacklisting

- Implement IPv6 validation
- Update database schema
- Add UI controls for IPv6 entries

Fixes #123
```

```
docs: Update API documentation for import endpoints
```

```
fix: Resolve race condition in cache invalidation
```

### Branch Naming Convention

Use descriptive branch names with prefixes:

- `feature/` - New features (e.g., `feature/add-ldap-auth`)
- `fix/` - Bug fixes (e.g., `fix/memory-leak-in-logger`)
- `docs/` - Documentation updates (e.g., `docs/improve-readme`)
- `refactor/` - Code refactoring (e.g., `refactor/simplify-api-routes`)
- `test/` - Test additions or fixes (e.g., `test/add-blacklist-tests`)

## Testing Guidelines

### Test Coverage

- Write tests for **new features**
- Update tests for **modified features**
- Ensure **existing tests pass** before submitting PR
- Aim for **meaningful test coverage**, not just high percentages

### Types of Tests

1. **End-to-End Tests**: Test complete workflows (in `tests/e2e_test.py`)
2. **Unit Tests**: Test individual functions and methods
3. **Integration Tests**: Test component interactions

### Running Specific Tests

```bash
# Run all tests
python3 tests/e2e_test.py

# Run with verbose output
python3 tests/e2e_test.py -v

# Test specific proxy configuration
python3 tests/e2e_test.py --proxy-host localhost --proxy-port 3128
```

## Pull Request Process

### Before Submitting

1. **Update your fork** with the latest upstream changes:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run tests** to ensure everything works:
   ```bash
   python3 tests/e2e_test.py
   ```

3. **Review your changes**:
   ```bash
   git diff upstream/main
   ```

### Submitting the PR

1. **Push your changes** to your fork:
   ```bash
   git push origin your-branch-name
   ```

2. **Create a Pull Request** on GitHub with:
   - **Clear title** describing the change
   - **Detailed description** of what and why
   - **Related issue** references (e.g., "Fixes #123")
   - **Testing performed** and results
   - **Screenshots** for UI changes

### PR Template

```markdown
## Description
Brief description of changes

## Motivation
Why is this change needed?

## Changes Made
- Change 1
- Change 2
- Change 3

## Testing
- [ ] End-to-end tests pass
- [ ] Manual testing completed
- [ ] New tests added (if applicable)

## Screenshots (if applicable)
Add screenshots here

## Related Issues
Fixes #123
```

### Code Review Process

- At least **one maintainer review** is required
- Address **all review comments**
- Be **responsive** to feedback
- **Update your PR** based on feedback
- Once approved, a maintainer will **merge your PR**

## Documentation

When making changes, please update relevant documentation:

- **README.md** - For major features or changes to setup
- **API Documentation** - For new or modified endpoints
- **Code Comments** - For complex logic
- **Examples** - In the `examples/` directory

## Questions?

If you have questions or need help:

- **Create an issue** for general questions
- **Check existing issues** - your question might already be answered
- **Review the README** for common setup and usage information

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (MIT License).

## Thank You!

Your contributions help make Secure Proxy Manager better for everyone. We appreciate your time and effort!
