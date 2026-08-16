#!/usr/bin/env bash
# One-time TLS bootstrap for api.maximreconforge.tech.
#
# Solves the chicken-and-egg problem: nginx won't start without a cert, but
# certbot's webroot challenge needs nginx running. We drop a throwaway
# self-signed cert so nginx boots, obtain the real Let's Encrypt cert over
# HTTP-01, then swap it in and reload.
#
# Prerequisites:
#   - DNS: api.maximreconforge.tech A record already points at this VPS's public IP.
#   - Docker + Compose plugin installed; run from the project root.
#   - CERTBOT_EMAIL set in .env.
set -euo pipefail

DOMAIN="api.maximreconforge.tech"
EMAIL="${CERTBOT_EMAIL:-$(grep -E '^CERTBOT_EMAIL=' .env | cut -d= -f2-)}"
CERT_DIR="certbot/conf/live/${DOMAIN}"

if [ -z "${EMAIL}" ]; then
  echo "ERROR: set CERTBOT_EMAIL in .env before running this." >&2
  exit 1
fi

echo "==> [1/5] Creating a throwaway self-signed cert so nginx can boot..."
mkdir -p "${CERT_DIR}"
openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
  -keyout "${CERT_DIR}/privkey.pem" \
  -out "${CERT_DIR}/fullchain.pem" \
  -subj "/CN=${DOMAIN}"

echo "==> [2/5] Starting nginx + backend..."
docker compose up -d nginx backend

echo "==> [3/5] Deleting the dummy cert so certbot writes a clean one..."
rm -rf "${CERT_DIR}" "certbot/conf/archive/${DOMAIN}" \
       "certbot/conf/renewal/${DOMAIN}.conf"

echo "==> [4/5] Requesting the real Let's Encrypt cert via webroot..."
docker compose run --rm --entrypoint certbot certbot \
  certonly --webroot -w /var/www/certbot \
  --email "${EMAIL}" --agree-tos --no-eff-email \
  -d "${DOMAIN}"

echo "==> [5/5] Reloading nginx with the real cert..."
docker compose exec nginx nginx -s reload

echo "Done. https://${DOMAIN}/health should now return {\"status\":\"ok\"}."
