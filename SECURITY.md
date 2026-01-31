# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.1.x | Active support |
| 1.0.x | Security fixes only |
| < 1.0 | No longer supported |

---

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

### How to Report

1. **Email**: Send details to **security@uptech.vn**
2. **Subject**: `[SECURITY] UpShield WAF - Brief Description`
3. **Include**:
   - Type of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

| Timeline | Action |
|----------|--------|
| 24 hours | Acknowledgment of your report |
| 72 hours | Initial assessment |
| 7 days | Status update |
| 30 days | Fix deployed (for valid vulnerabilities) |

### Safe Harbor

We consider security research conducted in good faith:

- Make a good faith effort to avoid privacy violations
- Give us reasonable time to respond before disclosure
- Do not access or modify data that doesn't belong to you
- Do not degrade our services

We will:

- Work with you to understand and resolve the issue
- Not pursue legal action for good faith research
- Credit you in our security advisories (if desired)

---

## Security Best Practices

When using UpShield WAF:

1. **Keep WordPress updated** - Always run the latest version
2. **Keep plugins updated** - Including UpShield
3. **Use strong passwords** - Enable 2FA for all admins
4. **Regular backups** - Before any security changes
5. **Monitor logs** - Review Live Traffic regularly

---

## Security Checklist

After installing UpShield:

- [ ] Enable WAF protection
- [ ] Enable Login Security
- [ ] Enable 2FA for admin accounts
- [ ] Configure Telegram alerts
- [ ] Review blocked countries
- [ ] Set up rate limiting
- [ ] Enable Security Headers
- [ ] Run initial malware scan

---

## Protection Coverage

| Attack Type | Protection Level |
|-------------|-----------------|
| SQL Injection | High |
| XSS | High |
| RCE | High |
| LFI/RFI | High |
| Brute Force | High |
| Bad Bots | Medium |
| DDoS | Medium (Rate Limiting) |
| Zero-Day | Medium (Threat Intel) |

---

**Thank you for helping keep UpShield and its users safe!**
