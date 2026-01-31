# Changelog

All notable changes to UpShield WAF will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] - 2024-01-31

### ✨ Added
- **Two-Factor Authentication (2FA)** - TOTP-based authentication compatible with Google Authenticator, Authy, and other TOTP apps
- **Telegram Alerts** - Real-time security notifications via Telegram bot
- **HTTP Security Headers** - Configurable security headers (CSP, HSTS, X-Frame-Options, etc.)
- **Settings UI** - New tabbed interface for managing all features
- Badge indicators for new features in settings

### 🔧 Changed
- Updated version to 1.1.0
- Improved autoloader with new class mappings
- Enhanced plugin initialization flow

### 🐛 Fixed
- Fixed singleton pattern implementation in WAF engine
- Fixed namespace case sensitivity issues

---

## [1.0.0] - 2024-01-31

### ✨ Added
- **Core WAF Engine** - Real-time request analysis and threat detection
- **SQL Injection Protection** - Comprehensive SQLi pattern detection
- **XSS Prevention** - Cross-site scripting attack blocking
- **RCE Protection** - Remote code execution attempt prevention
- **LFI Protection** - Local file inclusion attack blocking
- **Bad Bot Blocking** - Known malicious bot user-agent filtering
- **XML-RPC Protection** - Optional XML-RPC endpoint blocking
- **User Enumeration Prevention** - Author archive and REST API protection
- **Rate Limiting** - Global and per-endpoint request limiting
- **Country Blocking** - Geo-based access control
- **IP Management** - Whitelist and blacklist management
- **Threat Intelligence** - Integration with threat feed (400K+ IPs)
- **Live Traffic Monitor** - Real-time request logging and visualization
- **Login Security** - Brute force protection with lockouts
- **Malware Scanner** - File integrity and malware detection
- **CAPTCHA Integration** - Support for reCAPTCHA, hCaptcha, Turnstile
- **Admin Dashboard** - Comprehensive security overview
- **Setup Wizard** - Guided first-time configuration

### 🏗️ Architecture
- Modular design with separate components for each feature
- Singleton pattern for core engine
- WordPress hooks and filters integration
- Database tables for logs and settings
- Cron jobs for scheduled tasks

---

## [Unreleased]

### 🔮 Planned Features
- Dark mode dashboard
- REST API endpoint protection
- GraphQL attack prevention
- Advanced bot detection with ML
- Login URL customization
- Database backup before attacks
- Multi-site network support
- WP-CLI commands
- Import/Export settings

---

## Version History Summary

| Version | Date | Highlights |
|---------|------|------------|
| 1.1.0 | 2024-01-31 | 2FA, Telegram, Security Headers |
| 1.0.0 | 2024-01-31 | Initial release with full WAF |

---

[1.1.0]: https://github.com/nhattnh/upshield/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/nhattnh/upshield/releases/tag/v1.0.0
[Unreleased]: https://github.com/nhattnh/upshield/compare/v1.1.0...HEAD
