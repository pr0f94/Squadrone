#!/usr/bin/env bash
# wp-init.sh — install WP-CLI (if missing) and run `wp core install` (idempotent).
# Reads WP_URL, WP_TITLE, WP_ADMIN_USER, WP_ADMIN_PASS, WP_ADMIN_EMAIL from env.
# Runs from /docker-entrypoint.d/ before apache exec, so wp-config.php already exists.

set -eu

WP_PATH="${WP_PATH:-/var/www/html}"
WP_URL="${WP_URL:-http://localhost:8080}"
WP_TITLE="${WP_TITLE:-Squadrone Sandbox}"
WP_ADMIN_USER="${WP_ADMIN_USER:-admin}"
WP_ADMIN_PASS="${WP_ADMIN_PASS:-password}"
WP_ADMIN_EMAIL="${WP_ADMIN_EMAIL:-admin@test.local}"

if ! command -v wp >/dev/null 2>&1; then
    echo "[wp-init] installing wp-cli"
    if command -v curl >/dev/null 2>&1; then
        curl -sSLo /usr/local/bin/wp \
            https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
    else
        apt-get update -qq && apt-get install -y --no-install-recommends curl ca-certificates >/dev/null
        curl -sSLo /usr/local/bin/wp \
            https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
    fi
    chmod +x /usr/local/bin/wp
fi

# Wait for db
for _ in $(seq 1 30); do
    if wp --allow-root --path="$WP_PATH" db check >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

if wp --allow-root --path="$WP_PATH" core is-installed >/dev/null 2>&1; then
    echo "[wp-init] core already installed — skipping"
    exit 0
fi

echo "[wp-init] running wp core install"
wp --allow-root --path="$WP_PATH" core install \
    --url="$WP_URL" \
    --title="$WP_TITLE" \
    --admin_user="$WP_ADMIN_USER" \
    --admin_password="$WP_ADMIN_PASS" \
    --admin_email="$WP_ADMIN_EMAIL" \
    --skip-email
