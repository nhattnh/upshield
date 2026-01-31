# Contributing to UpShield WAF

Thank you for your interest in contributing to UpShield WAF.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)

---

## Code of Conduct

This project adheres to a Code of Conduct. By participating, you are expected to uphold this code. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

---

## How to Contribute

### Reporting Bugs

Before creating a bug report, check existing issues. Include:

- Clear, descriptive title
- Steps to reproduce the issue
- Expected vs. actual behavior
- Environment details (WordPress version, PHP version, server configuration)
- Screenshots or logs if applicable

### Suggesting Features

Feature suggestions are welcome. Please:

1. Check if the feature already exists or has been previously requested
2. Create an issue with `[Feature Request]` prefix
3. Describe the use case and expected benefits

### Code Contributions

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit changes: `git commit -m 'Add feature description'`
4. Push to branch: `git push origin feature/your-feature`
5. Open a Pull Request

---

## Development Setup

### Prerequisites

- PHP 7.4 or higher
- WordPress 5.0 or higher
- Composer (optional, for development tools)
- Node.js 16+ (optional, for asset building)

### Installation

```bash
# Clone the repository
git clone https://github.com/nhattnh/upshield.git
cd upshield

# Install PHP dependencies (optional)
composer install

# Create symlink in WordPress plugins directory
ln -s /path/to/upshield /path/to/wordpress/wp-content/plugins/upshield-waf
```

### Running Tests

```bash
# PHP Unit tests
composer test

# Code style check
composer phpcs
```

---

## Pull Request Process

1. Update documentation for any functionality changes
2. Add tests for new features
3. Ensure code follows WordPress coding standards
4. Write clear, descriptive commit messages
5. Reference related issues in the PR description

### Commit Message Format

```
[type] Brief description

Types:
- feat: New feature
- fix: Bug fix
- docs: Documentation changes
- style: Code formatting
- refactor: Code restructuring
- test: Test additions
- chore: Maintenance tasks
```

---

## Coding Standards

### PHP

- Follow [WordPress Coding Standards](https://developer.wordpress.org/coding-standards/)
- Use meaningful variable and function names
- Document functions with PHPDoc comments
- Use type hints where applicable

### Example

```php
/**
 * Process incoming request for threats.
 *
 * @param array $request_data Request data to analyze.
 * @return bool True if request is safe, false otherwise.
 */
public function process_request( array $request_data ): bool {
    // Implementation
}
```

---

## Questions

- Open an issue with `[Question]` prefix
- Email: info@uptech.vn

---

**Thank you for contributing.**
