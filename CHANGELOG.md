# Changelog

All notable changes to UpShield WAF will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] - 2024-01-31

### Added
- Two-Factor Authentication (2FA) with TOTP support
- Telegram real-time alert notifications
- HTTP Security Headers configuration (CSP, HSTS, X-Frame-Options)
- New tabbed settings interface for feature management

### Changed
- Updated version to 1.1.0
- Improved autoloader with new class mappings
- Enhanced plugin initialization flow

### Fixed
- Singleton pattern implementation in WAF engine
- Namespace case sensitivity issues

---

## [1.0.0] - 2024-01-31

### Added
- Core WAF Engine with real-time request analysis
- SQL Injection (SQLi) protection
- Cross-Site Scripting (XSS) prevention
- Remote Code Execution (RCE) blocking
- Local File Inclusion (LFI) protection
- Bad bot user-agent filtering
- XML-RPC endpoint protection
- User enumeration prevention
- Rate limiting (global and per-endpoint)
- Country-based access control
- IP whitelist and blacklist management
- Threat intelligence feed integration
- Live traffic monitoring
- Login security with brute force protection
- Malware file scanner
- CAPTCHA integration (reCAPTCHA, hCaptcha, Turnstile)
- Admin dashboard with security overview
- Setup wizard for first-time configuration

---

## Planned Features

- Dark mode dashboard
- REST API endpoint protection
- GraphQL attack prevention
- Login URL customization
- Multi-site network support
- WP-CLI command interface
- Settings import/export

---

[1.1.0]: https://github.com/nhattnh/upshield/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/nhattnh/upshield/releases/tag/v1.0.0
