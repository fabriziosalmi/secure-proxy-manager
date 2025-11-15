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
  - Authentication & Session Management endpoints
  - Proxy Status & Settings endpoints  
  - Blacklist Management endpoints
  - Logs & Analytics endpoints
  - Cache Management endpoints
  - Security endpoints
  - Database & Maintenance endpoints
- Database management endpoints for optimization and statistics
- Client and domain statistics endpoints
- Security scanning endpoints
- Table of Contents in README for better navigation
- Quick Links section for easy access to key resources
- Project structure diagram showing directory layout
- FAQ section answering common questions
- Security Configuration section with best practices
- Enhanced Support section with detailed guidance
- README files for examples/ and tests/ directories
- Improved documentation for test scripts

### Changed
- Fixed repository URL in README.md (corrected from secure-proxy to secure-proxy-manager)
- Improved API endpoint documentation with better categorization
- Enhanced documentation structure and formatting
- Updated Flask version badge (2.0+ → 3.0+)
- Expanded environment variables documentation with all docker-compose variables
- Renamed "Backup and Restore" section to "Database Export and Backup" for accuracy
- Improved SSL certificate installation instructions with OS-specific details
- Enhanced Contributing section with link to CONTRIBUTING.md
- Updated License section with link to LICENSE file
- Fixed internal link to Transparent Proxy Setup section
- Improved test_import.sh script with comprehensive header documentation
- Made test_import.sh executable

### Fixed
- Repository clone URL inconsistency in Quick Start guide
- Removed non-existent API endpoints from documentation:
  - `/api/maintenance/backup-config`
  - `/api/maintenance/restore-config`
  - `/api/maintenance/update-blacklists`
  - `/api/maintenance/clear-cache`
- Corrected network requirements with all actual ports (8011, 3128, 5001)
- Fixed Backup and Restore section to reflect actual database export functionality
- Updated environment variables table to match docker-compose.yml

### Security
- Added security warning about HTTPS filtering and man-in-the-middle inspection
- Documented importance of changing default credentials
- Added guidance for HTTPS deployment with reverse proxy
- Included security best practices section

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
