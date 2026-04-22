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

    echo -e "${GREEN}Created daygle_server_manager.conf with a generated session secret.${NC}"
fi

# ---------------------------------------------------------------------------
# 2. Summary
# ---------------------------------------------------------------------------
echo -e "${GREEN}Setup complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. Edit daygle_server_manager.conf if you need to change the DB password or other settings."
echo "  2. Run: docker compose up -d"
echo "  3. Open http://localhost:8000 to create your admin account."
echo "  4. Go to SSH Keys in the web interface to generate or import an SSH key."
echo "  5. Copy the displayed public key to each server you want to manage."
