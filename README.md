# UpShield WAF

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![PHP](https://img.shields.io/badge/PHP-7.4%2B-purple.svg)
![WordPress](https://img.shields.io/badge/WordPress-5.0%2B-green.svg)
![License](https://img.shields.io/badge/license-GPLv2-orange.svg)

High-performance Web Application Firewall for WordPress with real-time threat detection and blocking.

## 🛡️ Features

### Core Protection
- **SQL Injection (SQLi)** - Blocks UNION SELECT, time-based, and error-based attacks
- **Cross-Site Scripting (XSS)** - Prevents script injection
- **Remote Code Execution (RCE)** - Stops shell command execution
- **Local File Inclusion (LFI)** - Blocks path traversal attacks
- **Bad Bots & Scanners** - Identifies and blocks automated attack tools

### Security Features
- ✅ Real-time threat detection and blocking
- ✅ Live traffic monitoring
- ✅ IP whitelist/blacklist management
- ✅ Geo-blocking by country
- ✅ Rate limiting
- ✅ Brute force protection
- ✅ File integrity scanner
- ✅ Malware scanner
- ✅ Threat intelligence integration
- ✅ Cloudflare compatibility
- ✅ CAPTCHA challenge support

## 📦 Installation

### From ZIP
1. Download the latest release
2. Go to WordPress Admin → Plugins → Add New → Upload Plugin
3. Upload `upshield-waf-v1.0.0.zip`
4. Activate the plugin
5. Complete the setup wizard

### Manual
```bash
cd /path/to/wp-content/plugins/
git clone https://github.com/YOUR_USERNAME/upshield-waf.git
wp plugin activate upshield-waf
```

## 🚀 Quick Start

1. After activation, go to **UpShield WAF** in the admin menu
2. Complete the **Setup Wizard**
3. Configure protection settings:
   - Enable/disable attack type blocking
   - Set rate limits
   - Add trusted IPs to whitelist
4. Monitor attacks in the **Dashboard**

## 📊 Admin Pages

| Page | Description |
|------|-------------|
| **Dashboard** | Overview stats, recent attacks, top blocked IPs |
| **Firewall** | IP whitelist/blacklist management |
| **Live Traffic** | Real-time request monitoring |
| **Login Security** | Brute force protection settings |
| **File Scanner** | WordPress file integrity checks |
| **Malware Scanner** | Detect malicious code |
| **Settings** | All configuration options |

## 🔧 Configuration

### Protection Modes
- **Learning Mode** - Log threats but don't block (for testing)
- **Protecting Mode** - Block threats and log

### Rate Limiting
```
Global: 250 requests/minute
Login: 20 requests/minute  
XML-RPC: 20 requests/minute
```

## 📁 File Structure

```
upshield-waf/
├── upshield-waf.php          # Main plugin file
├── uninstall.php             # Cleanup on uninstall
├── admin/                    # Admin dashboard
│   ├── class-admin-dashboard.php
│   ├── class-admin-wizard.php
│   ├── css/
│   ├── js/
│   └── views/
├── includes/
│   ├── waf/                  # WAF engine
│   ├── firewall/             # Firewall components
│   ├── scanner/              # File & malware scanners
│   ├── logging/              # Traffic logger
│   └── integrations/         # Login security, Cloudflare
├── rules/                    # Attack detection rules (JSON)
├── templates/                # Block page templates
└── assets/                   # CSS for block pages
```

## 🔒 Security Rules

| Rule Set | Patterns |
|----------|----------|
| SQL Injection | 232 rules |
| XSS | 277 rules |
| LFI | 232 rules |
| RCE | 232 rules |
| Bad Bots | 277 rules |
| Malware Signatures | 197 patterns |

## 📋 Requirements

- PHP 7.4+
- WordPress 5.0+
- MySQL 5.6+ / MariaDB 10.0+

## 📄 License

GPLv2 or later - https://www.gnu.org/licenses/gpl-2.0.html

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Support

For issues and feature requests, please use [GitHub Issues](https://github.com/YOUR_USERNAME/upshield-waf/issues).

---

**Made with ❤️ by UpShield Security**
