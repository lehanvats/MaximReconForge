# Deployment Runbook — MaximReconForge

Production deployment for:
- **Frontend:** Vercel, served at `https://maximreconforge.tech`
- **Backend + worker + redis + nginx:** Hostinger KVM2 VPS, served at `https://api.maximreconforge.tech`
- **Database:** Supabase (Postgres + pgvector) — already provisioned

Because `maximreconforge.tech` and `api.maximreconforge.tech` share a registrable domain, the
auth cookies are **same-site**, so `SameSite=Lax; Secure` is enough.

---

## 0. Prerequisites (once)

- VPS running **Ubuntu 24.04 LTS** (install from the Hostinger panel — the plain
  Ubuntu template, NOT a "with CyberPanel/Plesk" one; those grab ports 80/443).
- The VPS public IPv4 address (Hostinger panel → your VPS → Overview).
- Domain `maximreconforge.tech` (managed in Hostinger hPanel → Domains → DNS Zone).
- Supabase `SERVICE_ROLE` key (Supabase dashboard → Project Settings → API).

---

## 1. DNS (Hostinger hPanel → Domains → maximreconforge.tech → DNS / Nameservers → DNS Zone)

Add these records:

| Type  | Host  | Value                       | Purpose                     |
|-------|-------|-----------------------------|-----------------------------|
| A     | `api` | `<VPS_PUBLIC_IP>`           | Backend on the VPS          |
| A     | `@`   | `76.76.21.21`               | Apex → Vercel (see note)    |
| CNAME | `www` | `cname.vercel-dns.com.`     | www → Vercel                |

> The apex/`www` values come from **Vercel → your project → Settings → Domains**
> when you add `maximreconforge.tech`. Use whatever Vercel shows there; the `76.76.21.21`
> above is Vercel's usual apex A record but confirm in the dashboard.

Verify `api` resolves before continuing:

```bash
dig +short api.maximreconforge.tech      # must return your VPS IP
```

DNS can take a few minutes to an hour to propagate.

---

## 2. Harden the VPS

SSH in as root (Hostinger emails you the root password), then:

```bash
# Create a non-root sudo user
adduser deploy
usermod -aG sudo deploy

# Copy your SSH key to the new user (run this on YOUR laptop, not the VPS):
#   ssh-copy-id deploy@api.maximreconforge.tech

# Firewall
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable

# (Recommended) disable root + password SSH login
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh
```

From here on, work as `deploy`: `ssh deploy@api.maximreconforge.tech`.

---

## 3. Install Docker + Compose

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker            # or log out/in so the group takes effect
docker compose version   # confirm the Compose plugin is present
```

---

## 4. Get the code

Push your repo to a **private** GitHub repo first (from your laptop), then on the VPS:

```bash
cd ~
git clone git@github.com:<you>/MaximReconForge.git
cd MaximReconForge
```

(If using HTTPS clone with a private repo, use a GitHub personal access token.)

---

## 5. Production `.env`

```bash
cp .env.example .env
nano .env
```

Set these for production:

```ini
ENVIRONMENT=production
JWT_SECRET_KEY=<paste output of: openssl rand -hex 32>

# Supabase — fill the blank one
SUPABASE_URL=<your value>
SUPABASE_SERVICE_ROLE_KEY=<your service role key>
DATABASE_URL=<your value>

# Redis stays as-is (in-cluster)
REDIS_URL=redis://redis:6379/0

# CORS — the Vercel frontend origin, exact, no trailing slash
FRONTEND_ORIGIN=https://maximreconforge.tech

# Same-site cookies over HTTPS
COOKIE_SAMESITE=lax
COOKIE_SECURE=true

# TLS
DOMAIN=api.maximreconforge.tech
CERTBOT_EMAIL=lehancodes@gmail.com

# LLM / embeddings — copy your existing keys
GROQ_API_KEY=<your key>
VOYAGEAI_API_KEY=<your key>
```

Generate the JWT secret:

```bash
openssl rand -hex 32
```

> Startup **fails fast** if `ENVIRONMENT=production` and `JWT_SECRET_KEY` is the
> dev placeholder or shorter than 32 chars — that's intentional.

---

## 6. Database migrations

If the Supabase schema isn't already applied, run Alembic once against it:

```bash
docker compose run --rm backend alembic upgrade head
```

(Skip if you've already applied migrations to this Supabase project.)

---

## 7. Bring up the stack + issue TLS

```bash
chmod +x scripts/init-tls.sh
./scripts/init-tls.sh          # dummy cert -> nginx up -> real Let's Encrypt cert -> reload
docker compose up -d           # start worker + redis + everything else
```

`init-tls.sh` handles the nginx/certbot chicken-and-egg. After it finishes:

```bash
curl https://api.maximreconforge.tech/health     # -> {"status":"ok"}
```

Cert auto-renewal is already wired: the `certbot` service in
`docker-compose.yml` runs `certbot renew` every 12h.

---

## 8. Configure Vercel (frontend)

In the Vercel project:

1. **Settings → Domains:** add `maximreconforge.tech` (and `www`), follow its DNS prompts.
2. **Settings → Environment Variables:**
   ```
   VITE_API_BASE_URL = https://api.maximreconforge.tech
   ```
3. **Redeploy** so the build picks up the new env var.

The frontend already sends `credentials: "include"`, so once the domain + env
var are set, login/session works against the VPS backend.

---

## 9. Smoke test

1. Open `https://maximreconforge.tech`, register/login.
2. In browser DevTools → Application → Cookies: confirm `access_token` /
   `refresh_token` are set on `api.maximreconforge.tech`, `Secure`, `SameSite=Lax`.
3. Start an engagement against a domain **you own / are authorized to test**.
4. Watch the WebSocket live output; confirm a report is produced.

```bash
docker compose ps                 # all services "Up"
docker compose logs -f backend    # tail backend
docker compose logs -f worker     # tail worker
```

---

## Updating later

```bash
cd ~/MaximReconForge
git pull
docker compose up -d --build
```

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Login works but `/auth/me` is 401 | `COOKIE_SECURE`/`SAMESITE` mismatch, or `FRONTEND_ORIGIN` wrong. Must be `https://maximreconforge.tech` exactly. |
| CORS error in browser console | `FRONTEND_ORIGIN` doesn't match the page origin exactly (scheme/host/trailing slash). |
| `init-tls.sh` fails at step 4 | `api.maximreconforge.tech` A record not pointing at the VPS yet, or port 80 blocked by `ufw`/Hostinger firewall. |
| nginx crash-loops | Cert missing — re-run `scripts/init-tls.sh`. |
| Backend won't start | Check `docker compose logs backend` — usually a bad `.env` value (JWT secret / DATABASE_URL). |
