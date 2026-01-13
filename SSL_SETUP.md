# SSL Certificate Setup Guide

## Overview

The deploy script automatically handles SSL certificate configuration with the following priority:

1. **Let's Encrypt certificates** (preferred) - Free, auto-renewing certificates
2. **Existing self-signed certificates** - Uses calculator-selfsigned.crt if available
3. **Creates new self-signed certificate** - If no certificates exist

## Current Setup

The deploy script will:
- ✅ Detect and use existing SSL certificates
- ✅ Create self-signed certificates if none exist
- ✅ Configure nginx with modern SSL/TLS settings
- ✅ Set up proper security headers
- ✅ Enable HTTP → HTTPS redirect
- ✅ Support Let's Encrypt ACME challenge for future setup

## SSL Configuration Features

### Modern TLS Settings
- **Protocols**: TLSv1.2 and TLSv1.3 only
- **Ciphers**: Modern, secure cipher suites (ECDHE, DHE)
- **Session**: 10-minute cache, tickets disabled
- **OCSP Stapling**: Enabled for Let's Encrypt certificates

### Security Headers
- `Strict-Transport-Security` - Forces HTTPS
- `X-Frame-Options` - Prevents clickjacking
- `X-Content-Type-Options` - Prevents MIME sniffing
- `X-XSS-Protection` - XSS protection
- `Referrer-Policy` - Controls referrer information

## Setting Up Let's Encrypt (Recommended)

### Prerequisites
- Domain name pointing to the server IP (40.233.70.245)
- Ports 80 and 443 open in firewall
- Certbot installed (already installed on server)

### Steps

1. **SSH into the server:**
   ```bash
   ssh -i ssh/ssh-key-2025-12-26.key ubuntu@40.233.70.245
   ```

2. **Run certbot:**
   ```bash
   sudo certbot --nginx -d yourdomain.com
   ```
   
   Or for IP-based certificate (if supported):
   ```bash
   sudo certbot --nginx -d 40.233.70.245
   ```

3. **Certbot will:**
   - Obtain certificates from Let's Encrypt
   - Automatically update nginx configuration
   - Set up auto-renewal via systemd timer

4. **Verify auto-renewal:**
   ```bash
   sudo systemctl status certbot.timer
   ```

### After Let's Encrypt Setup

The deploy script will automatically detect Let's Encrypt certificates on future deployments and use them instead of self-signed certificates.

## Manual Certificate Management

### View Current Certificates
```bash
# Let's Encrypt
sudo ls -la /etc/letsencrypt/live/

# Self-signed
sudo ls -la /etc/ssl/certs/*selfsigned*
sudo ls -la /etc/ssl/private/*selfsigned*
```

### Check Certificate Expiry
```bash
# Let's Encrypt
sudo certbot certificates

# Self-signed
sudo openssl x509 -in /etc/ssl/certs/calculator-selfsigned.crt -noout -dates
```

### Renew Let's Encrypt Certificates
```bash
# Manual renewal
sudo certbot renew

# Test renewal (dry run)
sudo certbot renew --dry-run
```

## Troubleshooting

### Certificate Not Found
If the deploy script can't find certificates:
1. Check certificate paths: `/etc/ssl/certs/` and `/etc/ssl/private/`
2. Verify permissions: Private keys should be `600`, certificates `644`
3. The script will create a new self-signed certificate if needed

### Nginx SSL Errors
```bash
# Test nginx configuration
sudo nginx -t

# Check nginx error logs
sudo tail -f /var/log/nginx/error.log

# Verify certificate paths in config
sudo grep ssl_certificate /etc/nginx/sites-available/appmanager
```

### Browser SSL Warnings
- **Self-signed certificates**: Browsers will show warnings (expected)
- **Let's Encrypt**: No warnings, trusted by all browsers
- **Mixed content**: Ensure all resources use HTTPS

## Security Best Practices

1. **Use Let's Encrypt** for production (free, trusted certificates)
2. **Enable auto-renewal** for Let's Encrypt certificates
3. **Monitor certificate expiry** (Let's Encrypt auto-renews at 30 days)
4. **Keep nginx updated** for latest SSL/TLS support
5. **Review security headers** regularly
6. **Test SSL configuration** using [SSL Labs](https://www.ssllabs.com/ssltest/)

## Notes

- Self-signed certificates are fine for development/testing
- Let's Encrypt requires a valid domain name (IP-only certificates not supported)
- Certificates are automatically detected and used by the deploy script
- The nginx configuration supports both certificate types seamlessly


