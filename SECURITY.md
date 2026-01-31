# Security Policy

## Supported Versions

| Version | Status              |
|---------|---------------------|
| 1.1.x   | Actively supported  |
| 1.0.x   | Security fixes only |
| < 1.0   | End of life         |

---

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

### Reporting Process

1. Email security concerns to **info@uptech.vn**
2. Use subject line: `[SECURITY] UpShield WAF - Brief Description`
3. Include:
   - Vulnerability type and severity assessment
   - Steps to reproduce
   - Potential impact analysis
   - Suggested remediation (if applicable)

### Response Timeline

| Timeframe  | Action                          |
|------------|--------------------------------|
| 24 hours   | Acknowledgment of report       |
| 72 hours   | Initial assessment completed   |
| 7 days     | Status update provided         |
| 30 days    | Fix deployed (valid issues)    |

### Responsible Disclosure

We follow coordinated disclosure practices:

- Provide reasonable time for remediation before public disclosure
- Credit reporters in security advisories upon request
- Do not pursue legal action for good-faith security research

---

## Security Features

UpShield provides protection against:

| Threat Type           | Protection Level |
|-----------------------|------------------|
| SQL Injection         | High             |
| XSS                   | High             |
| RCE                   | High             |
| LFI/RFI               | High             |
| Brute Force           | High             |
| Bad Bots              | Medium           |
| DDoS (Rate Limiting)  | Medium           |
| Zero-Day (Threat Intel) | Medium         |

---

## Best Practices

After installing UpShield:

1. Enable WAF protection in "Protecting" mode
2. Configure Two-Factor Authentication for all admin accounts
3. Set up real-time alerts (Telegram or email)
4. Review and configure rate limiting thresholds
5. Run initial malware scan
6. Enable HTTP Security Headers
7. Regularly review Live Traffic logs

---

## Contact

- **Security Reports**: info@uptech.vn
- **General Support**: [GitHub Issues](https://github.com/nhattnh/upshield/issues)
