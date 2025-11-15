# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive CONTRIBUTING.md with detailed contribution guidelines
- LICENSE file (MIT License)
- This CHANGELOG.md file to track project changes
- Expanded API documentation with all available endpoints organized by category
- Database management endpoints for optimization and statistics
- Client and domain statistics endpoints
- Security scanning endpoints

### Changed
- Fixed repository URL in README.md (corrected from secure-proxy to secure-proxy-manager)
- Improved API endpoint documentation with better categorization
- Enhanced documentation structure and formatting

### Fixed
- Repository clone URL inconsistency in Quick Start guide

## [1.0.0] - 2024-11-15

### Added
- Initial release of Secure Proxy Manager
- Squid-based proxy engine with advanced caching
- Flask-based backend API for proxy management
- Modern Bootstrap 5 web UI
- IP and domain blacklisting with CIDR and wildcard support
- Blacklist import functionality (URL and direct content)
- Support for multiple file formats (plain text, JSON)
- Real-time traffic monitoring and analytics
- Security scoring and assessment
- Rate limiting protection
- HTTPS filtering with SSL certificate management
- Comprehensive logging and analysis
- Configuration backup and restore
- Health check endpoints
- Docker containerization with docker-compose
- Role-based access control
- API documentation endpoint
- End-to-end testing suite

### Security
- Basic authentication for API endpoints
- Rate limiting to prevent brute force attacks
- Security headers on all responses
- SSL/TLS certificate validation
- Configurable content policies

## Version History Notes

### How to Use This Changelog

- **Added** - New features
- **Changed** - Changes in existing functionality
- **Deprecated** - Soon-to-be removed features
- **Removed** - Removed features
- **Fixed** - Bug fixes
- **Security** - Security-related changes

### Contributing

When contributing, please update this changelog with your changes under the `[Unreleased]` section.
Follow the format above and be concise but descriptive.

[Unreleased]: https://github.com/fabriziosalmi/secure-proxy-manager/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/fabriziosalmi/secure-proxy-manager/releases/tag/v1.0.0
