# Configuration Guide

## 🎛️ Settings Overview

UpShield settings are organized into tabs for easy navigation:

| Tab | Purpose |
|-----|---------|
| General | Core WAF settings |
| Firewall | Rule configuration |
| Login Security | Brute force protection |
| Malware Scanner | File scanning settings |
| IP Management | Whitelist/Blacklist |
| Threat Intel | External threat feeds |
| Telegram | Alert notifications |
| 2FA | Two-factor authentication |
| Headers | HTTP security headers |

---

## 🛡️ General Settings

### WAF Status
```php
waf_enabled: true/false
```
Master switch for WAF protection.

### Firewall Mode
```php
firewall_mode: 'learning' | 'protecting'
```
- **Learning**: Log threats but don't block
- **Protecting**: Actively block threats

### Log Settings
```php
log_all_traffic: true/false    // Log every request
log_blocked_only: true/false   // Log only blocked requests
```

---

## 🔥 Firewall Settings

### Attack Protection

| Setting | Default | Description |
|---------|---------|-------------|
| `sqli_protection` | ✅ On | SQL Injection |
| `xss_protection` | ✅ On | Cross-Site Scripting |
| `rce_protection` | ✅ On | Remote Code Execution |
| `lfi_protection` | ✅ On | Local File Inclusion |
| `xmlrpc_protection` | ✅ On | XML-RPC attacks |

### Rate Limiting
```php
rate_limiting_enabled: true
rate_limit_requests: 60        // Requests per minute
rate_limit_window: 60          // Window in seconds
```

---

## 🔐 Login Security

### Brute Force Protection
```php
login_security_enabled: true
max_login_attempts: 5          // Before lockout
lockout_duration: 1800         // 30 minutes
```

### CAPTCHA
```php
captcha_enabled: true
captcha_provider: 'recaptcha_v3' | 'hcaptcha' | 'turnstile'
captcha_site_key: 'your-site-key'
captcha_secret_key: 'your-secret-key'
```

---

## 📱 Telegram Alerts

```php
telegram_enabled: true
telegram_bot_token: 'your-bot-token'
telegram_chat_id: 'your-chat-id'
```

### How to Get Bot Token
1. Message [@BotFather](https://t.me/BotFather) on Telegram
2. Send `/newbot` and follow instructions
3. Copy the token provided

### How to Get Chat ID
1. Message your bot
2. Visit: `https://api.telegram.org/bot<TOKEN>/getUpdates`
3. Find your chat ID in the response

---

## 🔒 Two-Factor Authentication

```php
two_factor_enabled: true
two_factor_require_admin: true  // Force 2FA for admins
```

### Supported Apps
- Google Authenticator
- Authy
- Microsoft Authenticator
- Any TOTP-compatible app

---

## 🌐 Security Headers

```php
security_headers_enabled: true
header_x_frame_options: 'SAMEORIGIN'
header_x_content_type_options: true
header_x_xss_protection: true
header_referrer_policy: 'strict-origin-when-cross-origin'
header_hsts_enabled: true
header_hsts_max_age: 31536000  // 1 year
```

---

## 📡 Threat Intelligence

```php
threat_intel_enabled: true
threat_intel_sync_interval: 43200  // 12 hours
```

---

## 💾 Exporting Settings

```bash
# Via WP-CLI
wp option get upshield_options --format=json > upshield-settings.json

# Via Admin
UpShield → Settings → Export (coming soon)
```

---

## 🆘 Support

- 📧 Email: info@uptech.vn
- 🐛 Issues: [GitHub Issues](https://github.com/nhattnh/upshield/issues)
