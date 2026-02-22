import uuid
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request, send_from_directory

from server.app import db
from server.auth import agent_auth_required, audit_log
from server.models import Server, User

api_bp = Blueprint("api", __name__)


@api_bp.route("/register", methods=["POST"])
def register():
    """Register a new server. Called by bootstrap.sh. No auth required.

    Body: {
        hostname: str,
        ip_address: str,
        os_info: str,
        existing_users: [
            {username, ssh_keys: [str], groups: [str], shell: str}
        ]
    }
    """
    data = request.get_json()
    if not data or not data.get("hostname") or not data.get("ip_address"):
        return jsonify(msg="hostname and ip_address required"), 400

    token = str(uuid.uuid4())
    server = Server(
        hostname=data["hostname"],
        ip_address=data["ip_address"],
        os_info=data.get("os_info", ""),
        agent_token=token,
        status="pending",
    )
    db.session.add(server)
    db.session.flush()

    # Import existing users discovered on the server and link them to it
    imported = 0
    for eu in data.get("existing_users", []):
        username = eu.get("username", "").strip()
        if not username:
            continue
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(
                username=username,
                ssh_public_keys="\n".join(eu.get("ssh_keys", [])),
                shell=eu.get("shell", "/bin/bash"),
                source="discovered",
            )
            db.session.add(user)
            imported += 1
        # Link discovered user directly to this server so agent won't delete them
        if user not in server.direct_users:
            server.direct_users.append(user)

    db.session.commit()
    audit_log(
        "system",
        "server.register",
        f"server:{server.hostname}",
        f"Registered from {data['ip_address']}, imported {imported} users",
    )
    return jsonify(agent_token=token, server_id=server.id, status="pending"), 201


@api_bp.route("/pull", methods=["GET"])
@agent_auth_required
def pull():
    """Return desired state for this server.

    Returns: {
        users: [{username, ssh_keys, is_sudo, is_blocked, shell}],
        ssh_policy: {password_auth: bool, pubkey_auth: bool}
    }
    """
    server = request.server

    users_map = {}
    password_auth = False
    pubkey_auth = True

    def add_user_to_map(user):
        if user.username not in users_map:
            keys = (
                [k for k in user.ssh_public_keys.split("\n") if k.strip()]
                if user.ssh_public_keys
                else []
            )
            users_map[user.username] = {
                "username": user.username,
                "ssh_keys": keys,
                "password": user.password or "",
                "is_sudo": user.is_sudo,
                "is_blocked": user.is_blocked,
                "shell": user.shell,
            }

    # Users assigned directly to this server
    for user in server.direct_users:
        add_user_to_map(user)

    # Users assigned via groups
    for group in server.groups:
        if group.password_auth:
            password_auth = True
        if not group.pubkey_auth:
            pubkey_auth = False

        for user in group.users:
            add_user_to_map(user)

    return jsonify(
        users=list(users_map.values()),
        ssh_policy={"password_auth": password_auth, "pubkey_auth": pubkey_auth},
    )


@api_bp.route("/heartbeat", methods=["POST"])
@agent_auth_required
def heartbeat():
    """Agent heartbeat — update last_heartbeat timestamp."""
    server = request.server
    server.last_heartbeat = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify(status="ok")


# --- Static file endpoints for agent download ---


@api_bp.route("/agent.sh", methods=["GET"])
def download_agent():
    """Serve agent.sh for bootstrap to download."""
    import os

    agent_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "agent")
    return send_from_directory(agent_dir, "agent.sh", mimetype="text/plain")


@api_bp.route("/bootstrap.sh", methods=["GET"])
def download_bootstrap():
    """Serve bootstrap.sh."""
    import os

    root_dir = os.path.dirname(os.path.dirname(__file__))
    return send_from_directory(root_dir, "bootstrap.sh", mimetype="text/plain")
