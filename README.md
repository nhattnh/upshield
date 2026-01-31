# UpShield WAF

<div align="center">

![UpShield](https://img.shields.io/badge/UpShield-WAF-00875A?style=for-the-badge&logo=wordpress&logoColor=white)
![Version](https://img.shields.io/badge/version-1.1.0-blue?style=for-the-badge)
![PHP](https://img.shields.io/badge/PHP-7.4+-777BB4?style=for-the-badge&logo=php&logoColor=white)
![License](https://img.shields.io/badge/license-GPL--3.0-green?style=for-the-badge)

**Enterprise-Grade Web Application Firewall for WordPress**

*Developed by [UpTech](https://uptech.vn)*

[Documentation](#documentation) • [Quick Start](#quick-start) • [Features](#features) • [Contributing](#contributing)

</div>

---

## Why UpShield?

Most WordPress security plugins are bloated, slow, and expensive. UpShield is different:

| Problem | UpShield Solution |
|---------|-------------------|
| Slow scans | Optimized async scanning |
| Expensive premium | Free forever, no feature locks |
| Closed source | 100% open source |
| No visibility | Real-time traffic monitoring |
| US/EU focused | Built for APAC + Global |

---

## Features

### Core Protection

- SQL Injection (SQLi) Detection
- Cross-Site Scripting (XSS) Prevention
- Remote Code Execution (RCE) Blocking
- Local File Inclusion (LFI) Protection
- XML-RPC Attack Prevention
- User Enumeration Blocking

### Intelligent Defense

- AI-Powered Bot Detection
- Behavioral Analysis
- Rate Limiting (Global + Per-Endpoint)
- Country-Based Blocking/Allowing
- Threat Intelligence Integration (400K+ IPs)

### Modern Features (v1.1+)

- Two-Factor Authentication (TOTP)
- Telegram Real-Time Alerts
- HTTP Security Headers (CSP, HSTS, etc.)

### Monitoring & Analytics

- Live Traffic Monitor
- Attack Pattern Analysis
- Geographic Threat Map
- Detailed Security Reports

---

## Quick Start

### Installation

**Method 1: WordPress Admin**

1. Download the latest release
2. Go to Plugins → Add New → Upload Plugin
3. Activate UpShield WAF
4. Navigate to UpShield → Settings

**Method 2: WP-CLI**

```bash
wp plugin install upshield-waf --activate
```

**Method 3: Composer**

```bash
composer require uptech/upshield-waf
```

### First-Time Setup

The setup wizard will guide you through:

1. Enable WAF protection
2. Configure protection level
3. Set up alerts (email/Telegram)
4. Optional: Enable 2FA for admins

---

## Documentation

| Topic | Description |
|-------|-------------|
| [Installation Guide](docs/installation.md) | Step-by-step setup |
| [Configuration](docs/configuration.md) | All settings explained |
| [Threat Intelligence](docs/threat-intel.md) | How our threat feed works |
| [API Reference](docs/api.md) | REST API documentation |
| [Troubleshooting](docs/troubleshooting.md) | Common issues & fixes |
| [Changelog](CHANGELOG.md) | Version history |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    UpShield WAF Engine                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │   Request    │  │    Rule      │  │   Threat     │       │
│  │   Analyzer   │──│   Matcher    │──│  Detector    │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
│         │                                    │               │
│         ▼                                    ▼               │
│  ┌──────────────┐                    ┌──────────────┐       │
│  │     Rate     │                    │   Response   │       │
│  │   Limiter    │                    │   Handler    │       │
│  └──────────────┘                    └──────────────┘       │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│  Integrations: Telegram │ 2FA │ Cloudflare │ Security Hdrs  │
└─────────────────────────────────────────────────────────────┘
```

---

## Performance

Benchmarked on standard WordPress installation:

| Metric | Without UpShield | With UpShield | Impact |
|--------|------------------|---------------|--------|
| TTFB | 245ms | 248ms | +1.2% |
| Memory | 48MB | 52MB | +8.3% |
| CPU | Baseline | +0.5% | Minimal |

UpShield is optimized to add minimal overhead while providing maximum protection.

---

## Security

### Responsible Disclosure

Found a vulnerability? Please email **security@uptech.vn**.

**Do NOT create public GitHub issues for security vulnerabilities.**

See [SECURITY.md](SECURITY.md) for full details.

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Development setup
git clone https://github.com/nhattnh/upshield.git
cd upshield
composer install
```

---

## License

UpShield WAF is open-source software licensed under the [GPL-3.0 License](LICENSE).

---

## Support

If UpShield helps protect your site, consider:

- **Star this repo** - It helps others discover UpShield
- **Report bugs** - Help us improve
- **Suggest features** - Shape the roadmap

---

<div align="center">

**Made with care by [UpTech](https://uptech.vn)**

*Protecting WordPress sites since 2024*

</div>
