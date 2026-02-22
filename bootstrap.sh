#!/usr/bin/env bash
# SSHADmin Bootstrap — install agent on a new server.
# Usage: curl -sL https://center.example.com/api/bootstrap.sh | bash -s -- https://center.example.com
# Pure bash, no Python required.
set -euo pipefail

CONTROL_CENTER_URL="${1:?Usage: bootstrap.sh <control-center-url>}"
INSTALL_DIR="/root/manipulator"
SERVICE_NAME="sshadmin-agent"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ============================================================
# Pre-flight checks
# ============================================================

# --- Must be root ---
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
    exit 1
fi

# --- 1. Detect OS and package manager ---
detect_os() {
    if [[ ! -f /etc/os-release ]]; then
        error "Cannot detect OS: /etc/os-release not found"
        exit 1
    fi
    # shellcheck source=/dev/null
    source /etc/os-release
    OS_ID="${ID}"
    OS_VERSION="${VERSION_ID:-unknown}"
    OS_NAME="${PRETTY_NAME:-${ID} ${OS_VERSION}}"

    case "$OS_ID" in
        debian|ubuntu)
            PKG_MANAGER="apt-get"
            PKG_INSTALL="apt-get install -y -qq"
            PKG_UPDATE="apt-get update -qq"
            ;;
        centos|rhel|rocky|almalinux|ol)
            if command -v dnf &>/dev/null; then
                PKG_MANAGER="dnf"
                PKG_INSTALL="dnf install -y -q"
                PKG_UPDATE="true"
            else
                PKG_MANAGER="yum"
                PKG_INSTALL="yum install -y -q"
                PKG_UPDATE="true"
            fi
            ;;
        fedora)
            PKG_MANAGER="dnf"
            PKG_INSTALL="dnf install -y -q"
            PKG_UPDATE="true"
            ;;
        *)
            error "Unsupported OS: ${OS_ID}. Supported: debian, ubuntu, centos, rhel, rocky, almalinux, fedora"
            exit 1
            ;;
    esac

    info "Detected OS: ${OS_NAME} (package manager: ${PKG_MANAGER})"
}

# --- 2. Check and install system prerequisites ---
preflight_checks() {
    info "Running pre-flight checks..."

    local pkg_updated=false

    # --- systemd ---
    if ! command -v systemctl &>/dev/null; then
        error "systemd not found. This system must use systemd to run the agent."
        exit 1
    fi
    info "  [ok] systemd"

    # --- sshd ---
    if ! systemctl is-active --quiet sshd 2>/dev/null && ! systemctl is-active --quiet ssh 2>/dev/null; then
        warn "  SSH server (sshd) is not running. The agent manages SSH users — make sure sshd is installed."
    else
        info "  [ok] sshd running"
    fi

    # --- sudo ---
    if ! command -v sudo &>/dev/null; then
        warn "  sudo not found — installing..."
        if [[ "$pkg_updated" == "false" ]]; then
            $PKG_UPDATE 2>/dev/null || true
            pkg_updated=true
        fi
        $PKG_INSTALL sudo
        if command -v sudo &>/dev/null; then
            info "  [ok] sudo installed"
        else
            error "Failed to install sudo"
            exit 1
        fi
    else
        info "  [ok] sudo"
    fi

    # --- curl ---
    if ! command -v curl &>/dev/null; then
        warn "  curl not found — installing..."
        if [[ "$pkg_updated" == "false" ]]; then
            $PKG_UPDATE 2>/dev/null || true
            pkg_updated=true
        fi
        $PKG_INSTALL curl
        if command -v curl &>/dev/null; then
            info "  [ok] curl installed"
        else
            error "Failed to install curl"
            exit 1
        fi
    else
        info "  [ok] curl"
    fi

    # --- jq ---
    if ! command -v jq &>/dev/null; then
        warn "  jq not found — installing..."
        if [[ "$pkg_updated" == "false" ]]; then
            $PKG_UPDATE 2>/dev/null || true
            pkg_updated=true
        fi
        $PKG_INSTALL jq
        if command -v jq &>/dev/null; then
            info "  [ok] jq installed"
        else
            error "Failed to install jq"
            exit 1
        fi
    else
        info "  [ok] jq"
    fi

    # --- useradd / userdel / usermod ---
    local missing_cmds=()
    for cmd in useradd userdel usermod chpasswd groupadd; do
        if ! command -v "$cmd" &>/dev/null; then
            # On some systems these are in /usr/sbin which may not be in PATH
            if [[ -x "/usr/sbin/${cmd}" ]]; then
                continue
            fi
            missing_cmds+=("$cmd")
        fi
    done
    if [[ ${#missing_cmds[@]} -gt 0 ]]; then
        error "Missing required commands: ${missing_cmds[*]}"
        error "These are part of shadow-utils (RHEL/CentOS) or passwd (Debian/Ubuntu)."
        error "Install them manually and re-run bootstrap."
        exit 1
    fi
    info "  [ok] user management tools (useradd, userdel, usermod, chpasswd)"

    # --- /etc/ssh/sshd_config ---
    if [[ ! -f /etc/ssh/sshd_config ]]; then
        warn "  /etc/ssh/sshd_config not found. Agent won't be able to manage SSH policies."
        warn "  Install openssh-server if SSH access management is needed."
    else
        info "  [ok] /etc/ssh/sshd_config"
    fi

    # --- Network: can reach control center ---
    info "  Checking connectivity to control center..."
    if ! curl -sf --max-time 10 -o /dev/null "${CONTROL_CENTER_URL}/api/bootstrap.sh" 2>/dev/null; then
        # Try just the base URL
        if ! curl -sf --max-time 10 -o /dev/null "${CONTROL_CENTER_URL}/" 2>/dev/null; then
            error "Cannot reach control center at ${CONTROL_CENTER_URL}"
            error "Check the URL, DNS, firewall, and that the control center is running."
            exit 1
        fi
    fi
    info "  [ok] control center reachable"

    # --- Check if agent is already installed ---
    if [[ -f "${INSTALL_DIR}/agent.conf" ]]; then
        warn "Agent already installed at ${INSTALL_DIR}/"
        warn "To re-install, first remove the existing agent:"
        warn "  systemctl stop ${SERVICE_NAME} && rm -rf ${INSTALL_DIR}"
        error "Aborting to prevent duplicate registration."
        exit 1
    fi

    info "Pre-flight checks passed."
}

# --- 3. Collect existing users (UID >= 1000) ---
collect_existing_users() {
    info "Collecting existing users (UID >= 1000)..."

    local users_json="["
    local first=true

    while IFS=: read -r username _ uid _ _ home shell; do
        # Skip UIDs below 1000 and nobody
        if [[ "$uid" -lt 1000 ]] || [[ "$username" == "nobody" ]]; then
            continue
        fi

        # Collect SSH keys if authorized_keys exists
        local keys_json="[]"
        local auth_keys="${home}/.ssh/authorized_keys"
        if [[ -f "$auth_keys" ]]; then
            keys_json=$(
                while IFS= read -r line; do
                    # Skip empty lines and comments
                    line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                    if [[ -n "$line" ]] && [[ ! "$line" =~ ^# ]]; then
                        echo "$line"
                    fi
                done < "$auth_keys" | jq -R . | jq -s .
            )
        fi

        # Collect groups
        local user_groups
        user_groups=$(groups "$username" 2>/dev/null | cut -d: -f2 | xargs -n1 | jq -R . | jq -s . 2>/dev/null || echo "[]")

        # Check if user has sudo access
        local has_sudo=false
        if groups "$username" 2>/dev/null | grep -qE '\b(sudo|wheel)\b'; then
            has_sudo=true
        fi

        # Build user JSON
        if [[ "$first" == "true" ]]; then
            first=false
        else
            users_json+=","
        fi

        users_json+=$(jq -n \
            --arg u "$username" \
            --argjson k "$keys_json" \
            --argjson g "$user_groups" \
            --arg s "$shell" \
            --argjson sudo "$has_sudo" \
            '{username: $u, ssh_keys: $k, groups: $g, shell: $s, has_sudo: $sudo}')

        info "  Found user: ${username} (shell: ${shell}, keys: $(echo "$keys_json" | jq length), sudo: ${has_sudo})"
    done < /etc/passwd

    users_json+="]"
    echo "$users_json"
}

# --- 4. Register with control center ---
register_server() {
    info "Registering with control center..."

    local hostname
    hostname=$(hostname -f 2>/dev/null || hostname)
    local ip
    ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "unknown")
    local existing_users
    existing_users=$(collect_existing_users)

    local payload
    payload=$(jq -n \
        --arg h "$hostname" \
        --arg ip "$ip" \
        --arg os "${OS_NAME}" \
        --argjson users "$existing_users" \
        '{hostname: $h, ip_address: $ip, os_info: $os, existing_users: $users}')

    local response
    response=$(curl -sf --max-time 30 \
        -X POST "${CONTROL_CENTER_URL}/api/register" \
        -H "Content-Type: application/json" \
        -d "$payload") || {
        error "Failed to register with control center at ${CONTROL_CENTER_URL}"
        error "Check that the URL is correct and the server is running."
        exit 1
    }

    local status
    status=$(echo "$response" | jq -r '.status')
    AGENT_TOKEN=$(echo "$response" | jq -r '.agent_token')
    local server_id
    server_id=$(echo "$response" | jq -r '.server_id')

    if [[ -z "$AGENT_TOKEN" ]] || [[ "$AGENT_TOKEN" == "null" ]]; then
        error "Registration failed. Server response:"
        echo "$response" | jq . 2>/dev/null || echo "$response"
        exit 1
    fi

    info "Registered! Server ID: ${server_id}, Status: ${status}"
    info "Agent token received."
}

# --- 5. Install agent ---
install_agent() {
    info "Installing agent..."

    mkdir -p "$INSTALL_DIR"

    # Download agent.sh
    curl -sf --max-time 30 \
        "${CONTROL_CENTER_URL}/api/agent.sh" \
        -o "${INSTALL_DIR}/agent.sh" || {
        error "Failed to download agent.sh"
        exit 1
    }
    chmod +x "${INSTALL_DIR}/agent.sh"

    # Write config
    cat > "${INSTALL_DIR}/agent.conf" <<CONF
# SSHADmin Agent Configuration
CONTROL_CENTER_URL="${CONTROL_CENTER_URL}"
AGENT_TOKEN="${AGENT_TOKEN}"
POLL_INTERVAL=300
CONF
    chmod 600 "${INSTALL_DIR}/agent.conf"

    info "Agent installed to ${INSTALL_DIR}/"
}

# --- 6. Create systemd service ---
create_service() {
    info "Creating systemd service..."

    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<SVC
[Unit]
Description=SSHADmin Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/bin/bash ${INSTALL_DIR}/agent.sh
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVC

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}"
    systemctl start "${SERVICE_NAME}"

    info "Service ${SERVICE_NAME} enabled and started."
}

# ============================================================
# Main
# ============================================================

echo ""
echo "==============================="
echo "  SSHADmin Bootstrap Installer"
echo "==============================="
echo ""

detect_os
preflight_checks
register_server
install_agent
create_service

echo ""
info "Bootstrap complete!"
info "Server registered with status: PENDING"
info "An administrator must approve this server in the control center UI."
info ""
info "Agent logs: journalctl -u ${SERVICE_NAME} -f"
info "Agent config: ${INSTALL_DIR}/agent.conf"
echo ""
