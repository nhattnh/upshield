# Contributing to UpShield WAF

First off, thank you for considering contributing to UpShield! 🎉

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Style Guidelines](#style-guidelines)

---

## 📜 Code of Conduct

This project adheres to a Code of Conduct. By participating, you are expected to uphold this code.

**Be respectful, inclusive, and constructive.**

---

## 🤝 How Can I Contribute?

### 🐛 Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Clear title** describing the issue
- **Steps to reproduce** the behavior
- **Expected behavior** vs actual behavior
- **Screenshots** if applicable
- **Environment details** (WordPress version, PHP version, etc.)

### 💡 Suggesting Features

Feature suggestions are welcome! Please:

1. Check if the feature already exists
2. Check if it's already been suggested
3. Create an issue with the `[Feature Request]` prefix
4. Describe the use case and benefits

### 🔧 Code Contributions

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 🛠️ Development Setup

### Prerequisites

- PHP 7.4+
- WordPress 5.0+
- Composer
- Node.js 16+ (for build tools)

### Installation

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/upshield.git
cd upshield

# Install PHP dependencies
composer install

# Install Node dependencies (optional, for building assets)
npm install

# Create a symlink in your WordPress plugins directory
ln -s /path/to/upshield /path/to/wordpress/wp-content/plugins/upshield-waf
```

### Running Tests

```bash
# PHP Unit tests
composer test

# PHP CodeSniffer
composer phpcs

# Fix coding standards automatically
composer phpcbf
```

---

## 🔀 Pull Request Process

1. **Update documentation** if you're changing functionality
2. **Add tests** for new features
3. **Follow coding standards** (WordPress VIP)
4. **Write clear commit messages**
5. **Reference related issues** in PR description

### PR Title Format

```
[Type] Short description

Types:
- feat: New feature
- fix: Bug fix
- docs: Documentation only
- style: Code style (formatting, etc.)
- refactor: Code refactoring
- test: Adding tests
- chore: Maintenance tasks
```

---

## 📝 Style Guidelines

### PHP

- Follow [WordPress Coding Standards](https://developer.wordpress.org/coding-standards/wordpress-coding-standards/php/)
- Use meaningful variable and function names
- Comment complex logic
- Use type hints where possible

```php
/**
 * Process incoming request.
 *
 * @param array $request_data Request data to process.
 * @return bool True if request is safe, false otherwise.
 */
public function process_request( array $request_data ): bool {
    // Implementation
}
```

### JavaScript

- Use ES6+ syntax
- Follow WordPress JavaScript coding standards
- Use meaningful variable names

### CSS

- Use BEM naming convention
- Mobile-first approach
- Use CSS custom properties for theming

---

## 🏷️ Versioning

We use [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backwards compatible)
- **PATCH**: Bug fixes (backwards compatible)

---

## 📞 Questions?

Feel free to:
- Open an issue with the `[Question]` prefix
- Email us at dev@uptech.vn

---

**Thank you for contributing! 🙏**
