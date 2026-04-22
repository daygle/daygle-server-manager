#!/usr/bin/env bash
# Daygle Server Manager — First-time setup helper.
# Generates daygle_server_manager.conf with a random session secret.
# SSH keys are managed through the web interface — no manual key generation needed.
# Run once before `docker compose up -d`.
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}Daygle Server Manager — Setup${NC}"
echo "================================"
echo ""

extract_db_password() {
    local dsn="$1"
    echo "$dsn" | sed -n 's#^postgresql+psycopg2://[^:]*:\([^@]*\)@.*#\1#p'
}

set_or_add_conf_value() {
    local key="$1"
    local value="$2"
    local conf_file="daygle_server_manager.conf"

    if grep -q "^${key}=" "$conf_file"; then
        sed -i "s#^${key}=.*#${key}=${value}#" "$conf_file"
    else
        echo "${key}=${value}" >> "$conf_file"
    fi
}

# ---------------------------------------------------------------------------
# 1. Configuration file
# ---------------------------------------------------------------------------
if [[ -f daygle_server_manager.conf ]]; then
    echo -e "${YELLOW}daygle_server_manager.conf already exists — skipping conf generation.${NC}"
else
    if [[ ! -f daygle_server_manager.conf.example ]]; then
        echo -e "${RED}Error: daygle_server_manager.conf.example not found.${NC}"
        echo "Make sure you are running this script from the repository root."
        exit 1
    fi

    cp daygle_server_manager.conf.example daygle_server_manager.conf

    # Generate a cryptographically random session secret
    if command -v openssl &>/dev/null; then
        SECRET=$(openssl rand -hex 32)
    else
        SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    fi

    # Replace the placeholder in the conf file
    sed -i "s/replace-with-long-random-secret/${SECRET}/" daygle_server_manager.conf

    # Generate a DB password and keep DATABASE_URL + POSTGRES_PASSWORD in sync.
    if command -v openssl &>/dev/null; then
        DB_PASSWORD=$(openssl rand -hex 16)
    else
        DB_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(16))")
    fi

    DB_URL="postgresql+psycopg2://daygle_server_manager:${DB_PASSWORD}@db:5432/daygle_server_manager"
    set_or_add_conf_value "POSTGRES_PASSWORD" "$DB_PASSWORD"
    set_or_add_conf_value "DATABASE_URL" "$DB_URL"

    echo -e "${GREEN}Created daygle_server_manager.conf with a generated session secret.${NC}"
fi

# For existing conf files, ensure POSTGRES_PASSWORD matches DATABASE_URL.
if [[ -f daygle_server_manager.conf ]]; then
    DB_URL_LINE=$(grep '^DATABASE_URL=' daygle_server_manager.conf | head -n1 | cut -d'=' -f2- || true)
    if [[ -n "$DB_URL_LINE" ]]; then
        DB_PASSWORD_FROM_URL=$(extract_db_password "$DB_URL_LINE")
        if [[ -n "$DB_PASSWORD_FROM_URL" ]]; then
            set_or_add_conf_value "POSTGRES_PASSWORD" "$DB_PASSWORD_FROM_URL"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# 2. Summary
# ---------------------------------------------------------------------------
echo -e "${GREEN}Setup complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. Edit daygle_server_manager.conf if you need to change settings."
echo "  2. Run: docker compose up -d"
echo "  3. Open http://localhost:8000 to create your admin account."
echo "  4. Go to SSH Keys in the web interface to generate or import an SSH key."
echo "  5. Copy the displayed public key to each server you want to manage."
