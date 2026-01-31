# UpShield WAF

<div align="center">

![WordPress](https://img.shields.io/badge/WordPress-5.0+-21759B?style=flat-square&logo=wordpress&logoColor=white)
![PHP](https://img.shields.io/badge/PHP-7.4+-777BB4?style=flat-square&logo=php&logoColor=white)
![License](https://img.shields.io/badge/License-GPL--3.0-blue?style=flat-square)
![Version](https://img.shields.io/badge/Version-1.1.0-green?style=flat-square)

**Enterprise-Grade Web Application Firewall for WordPress**

[Documentation](#documentation) · [Installation](#installation) · [Features](#features) · [Contributing](#contributing)

</div>

---

## Overview

UpShield WAF is a comprehensive security solution designed to protect WordPress websites from common web vulnerabilities and attacks. Built with performance in mind, it provides real-time threat detection without compromising site speed.

**Developed by [UpTech](https://uptech.vn)**

---

## Features

### Core Protection

- **SQL Injection Detection** - Pattern-based SQLi attack prevention
- **Cross-Site Scripting (XSS)** - Input sanitization and output encoding
- **Remote Code Execution (RCE)** - Command injection blocking  
- **Local File Inclusion (LFI)** - Path traversal prevention
- **XML-RPC Protection** - Optional endpoint blocking
- **User Enumeration Prevention** - Author archive protection

### Intelligent Defense

- **Rate Limiting** - Configurable per-endpoint throttling
- **Country-Based Blocking** - Geo-restriction capabilities
- **Threat Intelligence** - Integration with curated threat feeds (400K+ IPs)
- **Behavioral Analysis** - Automated threat pattern recognition

### Additional Modules

- **Two-Factor Authentication** - TOTP-based verification
- **Real-Time Alerts** - Telegram notification integration
- **HTTP Security Headers** - CSP, HSTS, X-Frame-Options configuration
- **Live Traffic Monitor** - Request logging and analysis

---

## Architecture

```
+------------------------------------------------------------------+
|                      UpShield WAF Engine                          |
+------------------------------------------------------------------+
|                                                                   |
|  +----------------+  +----------------+  +------------------+     |
|  | Request        |  | Rule           |  | Threat           |     |
|  | Analyzer       |->| Matcher        |->| Detector         |     |
|  +----------------+  +----------------+  +------------------+     |
|         |                                         |               |
|         v                                         v               |
|  +----------------+                      +------------------+     |
|  | Rate           |                      | Response         |     |
|  | Limiter        |                      | Handler          |     |
|  +----------------+                      +------------------+     |
|                                                                   |
+------------------------------------------------------------------+
|  Integrations: Telegram | 2FA | Cloudflare | Security Headers    |
+------------------------------------------------------------------+
```

---

## Installation

### Method 1: WordPress Admin

1. Download the latest release from [GitHub Releases](https://github.com/nhattnh/upshield/releases)
2. Navigate to **Plugins > Add New > Upload Plugin**
3. Upload the ZIP file and activate

### Method 2: WP-CLI

```bash
wp plugin install upshield-waf --activate
```

### Method 3: Manual Installation

```bash
cd /path/to/wordpress/wp-content/plugins
git clone https://github.com/nhattnh/upshield.git upshield-waf
```

---

## Configuration

After activation, navigate to **UpShield** in the WordPress admin menu.

### Recommended Initial Setup

1. Enable WAF protection
2. Set firewall mode to "Protecting"
3. Whitelist administrator IPs
4. Configure rate limiting thresholds
5. Enable Two-Factor Authentication for admin accounts

For detailed configuration options, see [docs/configuration.md](docs/configuration.md).

---

## Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| WordPress | 5.0     | 6.0+        |
| PHP       | 7.4     | 8.0+        |
| MySQL     | 5.6     | 8.0+        |

---

## Performance

Benchmarked on standard WordPress installation:

| Metric        | Impact    |
|---------------|-----------|
| TTFB          | +1.2%     |
| Memory Usage  | +4-8 MB   |
| CPU Overhead  | Minimal   |

---

## Documentation

- [Installation Guide](docs/installation.md)
- [Configuration Reference](docs/configuration.md)
- [Changelog](CHANGELOG.md)
- [Security Policy](SECURITY.md)
- [Contributing Guidelines](CONTRIBUTING.md)

---

## Support

- **Documentation**: [uptech.vn/docs](https://uptech.vn)
- **Issues**: [GitHub Issues](https://github.com/nhattnh/upshield/issues)
- **Email**: info@uptech.vn

---

## License

UpShield WAF is open-source software licensed under the [GPL-3.0 License](LICENSE).

---

<div align="center">

**UpShield WAF** · Developed by [UpTech](https://uptech.vn)

</div>
