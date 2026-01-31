# Installation Guide

## 📋 Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| WordPress | 5.0+ | 6.0+ |
| PHP | 7.4+ | 8.0+ |
| MySQL | 5.6+ | 8.0+ |
| Memory | 64MB | 128MB+ |

---

## 🚀 Installation Methods

### Method 1: WordPress Admin (Recommended)

1. Download the latest release from [GitHub Releases](https://github.com/nhattnh/upshield/releases)
2. Go to **Plugins → Add New → Upload Plugin**
3. Choose the downloaded `.zip` file
4. Click **Install Now**
5. Click **Activate Plugin**

### Method 2: FTP/SFTP

```bash
# 1. Download and extract
wget https://github.com/nhattnh/upshield/archive/refs/heads/main.zip
unzip main.zip

# 2. Upload to WordPress
# Upload the 'upshield-waf' folder to /wp-content/plugins/

# 3. Activate via WordPress admin
```

### Method 3: WP-CLI

```bash
# Install from GitHub
wp plugin install https://github.com/nhattnh/upshield/archive/refs/heads/main.zip --activate

# Or if published on WordPress.org
wp plugin install upshield-waf --activate
```

### Method 4: Composer

```bash
# Add to your composer.json
composer require uptech/upshield-waf

# Or add to require section
{
    "require": {
        "uptech/upshield-waf": "^1.0"
    }
}
```

---

## ⚙️ Initial Setup

After activation, you'll be guided through the setup wizard:

### Step 1: Enable Protection
- Turn on WAF protection
- Choose protection mode (Learning or Protecting)

### Step 2: Configure Basics
- Set blocked countries (optional)
- Configure rate limiting
- Enable/disable XML-RPC

### Step 3: Set Up Alerts
- Configure email notifications
- Set up Telegram alerts (optional)

### Step 4: Admin Security
- Enable Two-Factor Authentication
- Configure login security

---

## 🔧 Post-Installation Checklist

- [ ] WAF enabled and in "Protecting" mode
- [ ] Admin IP whitelisted
- [ ] 2FA enabled for all admins
- [ ] Telegram/Email alerts configured
- [ ] Initial malware scan completed
- [ ] Backup created before testing

---

## 🆘 Need Help?

- 📖 [Full Documentation](https://uptech.vn/docs/upshield)
- 🐛 [Report Issues](https://github.com/nhattnh/upshield/issues)
- 📧 [Contact Support](mailto:info@uptech.vn)
