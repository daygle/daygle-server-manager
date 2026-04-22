#!/usr/bin/env bash

# ============================================
# Daygle Server Manager - Update Script
# ============================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$SCRIPT_DIR"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

FORCE=false
SKIP_START=false
CHECK_ONLY=false
DOCKER_COMPOSE=""

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_usage() {
    echo -e "${CYAN}Daygle Server Manager - Update Script${NC}"
    echo "==============================================="
    echo ""
    cat <<EOF
Usage:
  $(basename "$0") [options]

Options:
  -c, --check           Check for updates without applying
  -f, --force           Update without confirmation prompt
  --skip-start          Do not restart containers after update
  -h, --help            Show this help message

Examples:
  ./update.sh --check
  ./update.sh
  ./update.sh --force
  ./update.sh --skip-start

Notes:
    - Uses docker-compose only.
    - Preserves daygle_server_manager.conf and db/data contents.
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -c|--check)
                CHECK_ONLY=true
                shift
                ;;
            -f|--force)
                FORCE=true
                shift
                ;;
            --skip-start)
                SKIP_START=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                echo ""
                show_usage
                exit 1
                ;;
        esac
    done
}

check_git() {
    if ! command -v git >/dev/null 2>&1; then
        log_error "Git is required"
        exit 1
    fi
}

check_git_repo() {
    if ! git -C "$ROOT_DIR" rev-parse --git-dir >/dev/null 2>&1; then
        log_error "Not a git repository: $ROOT_DIR"
        exit 1
    fi
}

check_docker_compose() {
    if command -v docker-compose >/dev/null 2>&1; then
        DOCKER_COMPOSE="docker-compose"
    elif docker compose version >/dev/null 2>&1; then
        DOCKER_COMPOSE="docker compose"
    else
        log_error "Docker Compose is not available"
        exit 1
    fi
}

check_for_updates() {
    local branch current latest

    branch="$(git -C "$ROOT_DIR" rev-parse --abbrev-ref HEAD)"
    log_info "Current branch: $branch"

    git -C "$ROOT_DIR" fetch origin "$branch"

    current="$(git -C "$ROOT_DIR" rev-parse HEAD)"
    latest="$(git -C "$ROOT_DIR" rev-parse "origin/$branch")"

    if [[ "$current" == "$latest" ]]; then
        log_success "Already on latest version"
        return 1
    fi

    log_warning "Updates available"
    log_info "Current: $(git -C "$ROOT_DIR" log -1 --pretty=format:'%h - %s (%ar)' HEAD)"
    log_info "Latest : $(git -C "$ROOT_DIR" log -1 --pretty=format:'%h - %s (%ar)' "origin/$branch")"
    return 0
}

update_code() {
    local branch
    branch="$(git -C "$ROOT_DIR" rev-parse --abbrev-ref HEAD)"

    log_info "Saving current tracked changes"
    git -C "$ROOT_DIR" add -u
    git -C "$ROOT_DIR" commit -am "Before update on ${TIMESTAMP}" >/dev/null 2>&1 || true

    log_info "Merging latest code"
    if ! git -C "$ROOT_DIR" merge --ff-only "origin/$branch"; then
        log_warning "Fast-forward merge not possible, trying standard merge"
        git -C "$ROOT_DIR" merge -m "After update on ${TIMESTAMP}" "origin/$branch"
    fi

    log_success "Code updated"
}

start_containers() {
    if [[ "$SKIP_START" == true ]]; then
        log_warning "Skipping container restart (--skip-start)"
        log_info "Run manually: $DOCKER_COMPOSE up -d --build --remove-orphans"
        return 0
    fi

    log_info "Rebuilding and starting containers"
    cd "$ROOT_DIR"
    $DOCKER_COMPOSE up -d --build --remove-orphans
    log_success "Containers running"
}

main() {
    echo ""
    echo "============================================================"
    echo ""
    echo -e "        ${CYAN}Daygle Server Manager - Update Script${NC}"
    echo ""
    echo "============================================================"
    echo ""

    parse_args "$@"
    check_git
    check_git_repo
    check_docker_compose

    if [[ ! -f "$ROOT_DIR/docker-compose.yml" ]]; then
        log_error "docker-compose.yml not found in $ROOT_DIR"
        exit 1
    fi

    if [[ ! -f "$ROOT_DIR/daygle_server_manager.conf" ]]; then
        log_error "Missing daygle_server_manager.conf"
        log_info "Create it from daygle_server_manager.conf.example before running updates"
        exit 1
    fi

    if check_for_updates; then
        if [[ "$CHECK_ONLY" == true ]]; then
            log_info "Use ./update.sh to apply these updates"
            exit 0
        fi

        if [[ "$FORCE" == false ]]; then
            read -r -p "Do you want to update now? (y/n): " reply
            if [[ ! "$reply" =~ ^[Yy]$ ]]; then
                log_info "Update cancelled"
                exit 0
            fi
        fi

        update_code
        start_containers

        echo ""
        log_success "Update complete"
        log_info "View logs with: $DOCKER_COMPOSE logs -f"
        log_info "Stop services with: $DOCKER_COMPOSE down"
        echo ""
    else
        if [[ "$CHECK_ONLY" == false ]]; then
            log_info "Nothing to update"
        fi
    fi
}

main "$@"
