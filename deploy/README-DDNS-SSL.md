# AppManager: DDNS (No-IP) and HTTPS

## DDNS (No-IP) – keep your hostname pointed at your home IP

Your public IP can change. The deploy script can install a **No-IP updater** on the server so `blackgrid.ddns.net` (or your `ddns_address`) always points to your current IP.

1. **In `../ssh/deploy_config.json`** set:
   - `ddns_address`: your No-IP hostname (e.g. `blackgrid.ddns.net`)
   - `noip_username`: your No-IP account email/username
   - `noip_password`: your No-IP account password

2. On deploy, the script will:
   - Install `/usr/local/bin/noip-update.sh` on the server
   - Store credentials in `/etc/noip-ddns-credentials` (chmod 600)
   - Add a **root cron job** to run the updater **every 10 minutes**

So the server will keep telling No-IP its current public IP; no need to run anything by hand when your IP changes.

**No-IP free tier:** You must **confirm your hostname every 30 days** (e.g. at [my.noip.com](https://www.noip.com) → Dynamic DNS → Confirm). Set a calendar reminder.

---

## HTTPS (Let's Encrypt)

1. **In `../ssh/deploy_config.json`** (optional):
   - `letsencrypt_email`: your email for expiry/recovery notices. **You can leave it empty** – the script then uses `--register-unsafely-without-email` and you still get a valid signed cert; you just won't get email reminders before expiry (certbot still auto-renews).

2. **Before the first deploy:**
   - On your **router**, forward **ports 80 and 443** to the server's LAN IP (e.g. `192.168.2.86`).
   - Ensure **only** 80 and 443 are forwarded for this host (so only AppManager is exposed).

3. On deploy, the script will:
   - Install Nginx and use `/var/www/appmanager-acme` for the HTTP-01 challenge
   - Run `certbot certonly --webroot` for `ddns_address` (with or without email)
   - Switch Nginx to the HTTPS config (HTTP redirects to HTTPS)
   - Certificates are in `/etc/letsencrypt/live/<ddns_address>/` and renew automatically (certbot's timer)

**One cert for the whole domain:** The certificate is for your `ddns_address` (e.g. `blackgrid.ddns.net`). AppManager, DeltaBooks, and any other app you serve through that hostname (e.g. via Nginx path or port proxy) all use this same cert – no separate cert or email per app.

---

## Firewall (only AppManager exposed)

The script configures **UFW** to allow only:

- **22** – SSH
- **80** – HTTP (redirects to HTTPS when cert is present)
- **443** – HTTPS

So only this app is exposed to the internet; other apps on the server are not reachable from outside unless you add more rules.
