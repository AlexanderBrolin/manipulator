#!/usr/bin/env bash
# SSHADmin Agent — runs on each managed server as a systemd service.
# Pure bash, no Python required. Dependencies: curl, jq.
set -u

# --- Configuration ---
CONFIG_DIR="/opt/sshadmin"
CONFIG_FILE="${CONFIG_DIR}/agent.conf"
SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_BACKUP="/etc/ssh/sshd_config.bak.sshadmin"

# Protected system users — never touch these
PROTECTED_USERS=(
    "root" "nobody" "daemon" "bin" "sys" "sync" "games" "man" "lp" "mail"
    "news" "uucp" "proxy" "www-data" "backup" "list" "irc" "gnats"
    "systemd-network" "systemd-resolve" "systemd-timesync" "messagebus"
    "sshd" "_apt" "ntp" "chrony" "polkitd" "dbus" "tss" "rtkit"
    "avahi" "colord" "geoclue" "pulse" "gdm" "gnome-initial-setup"
    "postfix" "tcpdump" "systemd-coredump" "lxd" "uuidd"
    "centos" "fedora" "ec2-user" "cloud-user"
)

MIN_UID=1000

# --- Find binaries (paths differ across distros) ---

find_bin() {
    local name="$1"
    local path
    path=$(command -v "$name" 2>/dev/null)
    if [[ -z "$path" ]]; then
        # Check common sbin locations not always in PATH
        for dir in /usr/sbin /sbin /usr/local/sbin /usr/local/bin; do
            if [[ -x "${dir}/${name}" ]]; then
                echo "${dir}/${name}"
                return
            fi
        done
        echo "$name"  # fallback to bare name, hope PATH has it
    else
        echo "$path"
    fi
}

BIN_CURL=$(find_bin curl)
BIN_JQ=$(find_bin jq)
BIN_AWK=$(find_bin awk)
BIN_USERADD=$(find_bin useradd)
BIN_USERDEL=$(find_bin userdel)
BIN_USERMOD=$(find_bin usermod)
BIN_CHPASSWD=$(find_bin chpasswd)
BIN_GETENT=$(find_bin getent)
BIN_ID=$(find_bin id)
BIN_SSHD=$(find_bin sshd)

# --- Helpers ---

log_info() {
    echo "[INFO] $*"
}

log_error() {
    echo "[ERROR] $*" >&2
}

is_protected() {
    local username="$1"
    for p in "${PROTECTED_USERS[@]}"; do
        if [[ "$p" == "$username" ]]; then
            return 0
        fi
    done
    return 1
}

# --- Load config ---

if [[ ! -f "$CONFIG_FILE" ]]; then
    log_error "Config file not found: ${CONFIG_FILE}"
    exit 1
fi

# shellcheck source=/dev/null
source "$CONFIG_FILE"

if [[ -z "${CONTROL_CENTER_URL:-}" ]]; then
    log_error "CONTROL_CENTER_URL not set in config"
    exit 1
fi
if [[ -z "${AGENT_TOKEN:-}" ]]; then
    log_error "AGENT_TOKEN not set in config"
    exit 1
fi
POLL_INTERVAL="${POLL_INTERVAL:-300}"

API_HEADERS=(-H "Authorization: Bearer ${AGENT_TOKEN}" -H "Content-Type: application/json")

# --- Get local users (UID >= 1000, not nobody, not protected) ---

get_local_users() {
    $BIN_AWK -F: -v min_uid="$MIN_UID" \
        '$3 >= min_uid && $1 != "nobody" { print $1 }' /etc/passwd
}

# --- User management ---

user_exists() {
    $BIN_ID "$1" &>/dev/null
}

create_user() {
    local username="$1"
    local shell="${2:-/bin/bash}"

    if is_protected "$username"; then
        log_error "Refusing to create protected user: ${username}"
        return 1
    fi

    if ! user_exists "$username"; then
        $BIN_USERADD -m -s "$shell" "$username" && \
            log_info "Created user: ${username}" || \
            log_error "Failed to create user: ${username}"
    fi
}

delete_user() {
    local username="$1"

    if is_protected "$username"; then
        log_error "Refusing to delete protected user: ${username}"
        return 1
    fi

    if user_exists "$username"; then
        $BIN_USERDEL -r "$username" 2>/dev/null || true
        rm -f "/etc/sudoers.d/${username}"
        log_info "Deleted user: ${username}"
    fi
}

set_password() {
    local username="$1"
    local password="$2"
    if [[ -z "$password" ]]; then
        return
    fi
    if is_protected "$username"; then return 1; fi
    echo "${username}:${password}" | $BIN_CHPASSWD 2>/dev/null && \
        log_info "Password set for user: ${username}" || \
        log_error "Failed to set password for user: ${username}"
}

lock_user() {
    local username="$1"
    if is_protected "$username"; then return 1; fi
    # Lock password
    $BIN_USERMOD -L "$username" 2>/dev/null || true
    # Expire account — prevents ALL login including SSH keys
    $BIN_USERMOD -e 1 "$username" 2>/dev/null || true
    # Remove authorized_keys to block key-based access
    local home_dir
    home_dir=$($BIN_GETENT passwd "$username" 2>/dev/null | cut -d: -f6)
    if [[ -n "$home_dir" ]] && [[ -f "${home_dir}/.ssh/authorized_keys" ]]; then
        mv -f "${home_dir}/.ssh/authorized_keys" "${home_dir}/.ssh/authorized_keys.blocked" 2>/dev/null || true
    fi
    log_info "Locked user: ${username} (password locked + account expired + keys removed)"
}

unlock_user() {
    local username="$1"
    if is_protected "$username"; then return 1; fi
    # Unlock password
    $BIN_USERMOD -U "$username" 2>/dev/null || true
    # Remove account expiry
    $BIN_USERMOD -e "" "$username" 2>/dev/null || true
}

sync_ssh_keys() {
    local username="$1"
    shift
    local keys=("$@")

    local home_dir
    home_dir=$($BIN_GETENT passwd "$username" 2>/dev/null | cut -d: -f6)
    if [[ -z "$home_dir" ]]; then
        return
    fi

    local ssh_dir="${home_dir}/.ssh"
    local auth_keys="${ssh_dir}/authorized_keys"

    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"

    # Write keys
    printf "" > "$auth_keys"
    for key in "${keys[@]}"; do
        if [[ -n "$key" ]]; then
            echo "$key" >> "$auth_keys"
        fi
    done

    chmod 600 "$auth_keys"
    chown -R "${username}:${username}" "$ssh_dir"
}

sync_sudo() {
    local username="$1"
    local is_sudo="$2"
    local sudoers_file="/etc/sudoers.d/${username}"

    if [[ "$is_sudo" == "true" ]]; then
        echo "${username} ALL=(ALL) NOPASSWD:ALL" > "$sudoers_file"
        chmod 440 "$sudoers_file"
    else
        rm -f "$sudoers_file"
    fi
}

# --- SSHD config management ---

apply_ssh_policy() {
    local password_auth="$1"
    local pubkey_auth="$2"

    local pa_value="no"
    local pk_value="yes"
    [[ "$password_auth" == "true" ]] && pa_value="yes"
    [[ "$pubkey_auth" == "false" ]] && pk_value="no"

    # Read current values
    local current_pa
    current_pa=$(grep -E "^PasswordAuthentication\s+" "$SSHD_CONFIG" 2>/dev/null | awk '{print $2}' || echo "")
    local current_pk
    current_pk=$(grep -E "^PubkeyAuthentication\s+" "$SSHD_CONFIG" 2>/dev/null | awk '{print $2}' || echo "")

    local changed=false

    if [[ "$current_pa" != "$pa_value" ]] || [[ "$current_pk" != "$pk_value" ]]; then
        # Backup before first modification
        if [[ ! -f "$SSHD_BACKUP" ]]; then
            cp "$SSHD_CONFIG" "$SSHD_BACKUP"
        fi

        # Update PasswordAuthentication
        if grep -qE "^#?PasswordAuthentication\s+" "$SSHD_CONFIG"; then
            sed -i "s/^#\?PasswordAuthentication\s\+.*/PasswordAuthentication ${pa_value}/" "$SSHD_CONFIG"
        else
            echo "PasswordAuthentication ${pa_value}" >> "$SSHD_CONFIG"
        fi

        # Update PubkeyAuthentication
        if grep -qE "^#?PubkeyAuthentication\s+" "$SSHD_CONFIG"; then
            sed -i "s/^#\?PubkeyAuthentication\s\+.*/PubkeyAuthentication ${pk_value}/" "$SSHD_CONFIG"
        else
            echo "PubkeyAuthentication ${pk_value}" >> "$SSHD_CONFIG"
        fi

        changed=true
    fi

    if [[ "$changed" == "true" ]]; then
        # Validate config before reloading
        if $BIN_SSHD -t 2>/dev/null; then
            systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
            log_info "SSHD config updated: PasswordAuth=${pa_value}, PubkeyAuth=${pk_value}"
        else
            log_error "SSHD config validation failed, restoring backup"
            cp "$SSHD_BACKUP" "$SSHD_CONFIG"
        fi
    fi
}

# --- Main sync cycle ---

do_sync() {
    log_info "Starting sync cycle..."

    # 1. Pull desired state from control center
    local response
    response=$($BIN_CURL -sf --max-time 30 \
        "${API_HEADERS[@]}" \
        "${CONTROL_CENTER_URL}/api/pull" 2>/dev/null) || {
        log_error "Failed to pull config from control center"
        return 1
    }

    # 2. Parse desired users
    local user_count
    user_count=$(echo "$response" | $BIN_JQ '.users | length')

    # Build list of desired usernames
    local -a desired_usernames=()
    local i
    for i in $(seq 0 $((user_count - 1))); do
        local username
        username=$(echo "$response" | $BIN_JQ -r ".users[$i].username")
        desired_usernames+=("$username")
    done

    # 3. Apply desired state for each user
    for i in $(seq 0 $((user_count - 1))); do
        local username shell is_sudo is_blocked password
        username=$(echo "$response" | $BIN_JQ -r ".users[$i].username")
        shell=$(echo "$response" | $BIN_JQ -r ".users[$i].shell // \"/bin/bash\"")
        is_sudo=$(echo "$response" | $BIN_JQ -r ".users[$i].is_sudo")
        is_blocked=$(echo "$response" | $BIN_JQ -r ".users[$i].is_blocked")
        password=$(echo "$response" | $BIN_JQ -r ".users[$i].password // \"\"")

        if is_protected "$username"; then
            continue
        fi

        # Read SSH keys into array
        local -a ssh_keys=()
        local key_count k
        key_count=$(echo "$response" | $BIN_JQ ".users[$i].ssh_keys | length")
        for k in $(seq 0 $((key_count - 1))); do
            local key
            key=$(echo "$response" | $BIN_JQ -r ".users[$i].ssh_keys[$k]")
            ssh_keys+=("$key")
        done

        # Create user if not exists
        create_user "$username" "$shell"

        # Handle blocked state
        if [[ "$is_blocked" == "true" ]]; then
            lock_user "$username"
            continue
        else
            unlock_user "$username"
        fi

        # Sync SSH keys, password, and sudo
        sync_ssh_keys "$username" "${ssh_keys[@]+"${ssh_keys[@]}"}"
        set_password "$username" "$password"
        sync_sudo "$username" "$is_sudo"
    done

    # 4. Remove users not in desired state
    local local_users
    local_users=$(get_local_users)
    local local_user
    for local_user in $local_users; do
        if is_protected "$local_user"; then
            continue
        fi
        local found=false
        local desired
        for desired in "${desired_usernames[@]+"${desired_usernames[@]}"}"; do
            if [[ "$desired" == "$local_user" ]]; then
                found=true
                break
            fi
        done
        if [[ "$found" == "false" ]]; then
            delete_user "$local_user"
        fi
    done

    # 5. Apply SSH policy
    local password_auth pubkey_auth
    password_auth=$(echo "$response" | $BIN_JQ -r '.ssh_policy.password_auth')
    pubkey_auth=$(echo "$response" | $BIN_JQ -r '.ssh_policy.pubkey_auth')
    apply_ssh_policy "$password_auth" "$pubkey_auth"

    # 6. Send heartbeat
    $BIN_CURL -sf --max-time 10 \
        "${API_HEADERS[@]}" \
        -X POST "${CONTROL_CENTER_URL}/api/heartbeat" >/dev/null 2>&1 || true

    log_info "Sync cycle complete."
}

# --- Main loop ---

log_info "SSHADmin Agent starting. Polling every ${POLL_INTERVAL}s."

while true; do
    do_sync || true
    sleep "$POLL_INTERVAL"
done
