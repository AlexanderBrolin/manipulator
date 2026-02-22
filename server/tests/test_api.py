import json

from server.models import Group, Server, User


def test_register_new_server(client):
    """POST /api/register creates server with pending status."""
    resp = client.post(
        "/api/register",
        json={
            "hostname": "web01",
            "ip_address": "10.0.0.1",
            "os_info": "Ubuntu 22.04",
            "existing_users": [
                {
                    "username": "deploy",
                    "ssh_keys": ["ssh-ed25519 AAAAC3..."],
                    "groups": ["sudo"],
                    "shell": "/bin/bash",
                }
            ],
        },
    )
    assert resp.status_code == 201
    data = resp.get_json()
    assert "agent_token" in data
    assert data["status"] == "pending"
    assert data["server_id"] is not None


def test_register_imports_existing_users(client, db_session):
    """Existing users from bootstrap are imported with source=discovered and linked to server."""
    resp = client.post(
        "/api/register",
        json={
            "hostname": "web02",
            "ip_address": "10.0.0.2",
            "existing_users": [
                {"username": "alice", "ssh_keys": ["ssh-rsa AAA..."], "shell": "/bin/zsh"},
                {"username": "bob", "ssh_keys": [], "shell": "/bin/bash"},
            ],
        },
    )
    alice = User.query.filter_by(username="alice").first()
    assert alice is not None
    assert alice.source == "discovered"
    assert alice.shell == "/bin/zsh"
    assert "ssh-rsa AAA..." in alice.ssh_public_keys

    bob = User.query.filter_by(username="bob").first()
    assert bob is not None
    assert bob.source == "discovered"

    # Verify discovered users are linked to the server
    server = Server.query.filter_by(hostname="web02").first()
    assert alice in server.direct_users
    assert bob in server.direct_users


def test_register_missing_hostname(client):
    """POST /api/register without hostname returns 400."""
    resp = client.post("/api/register", json={"ip_address": "10.0.0.1"})
    assert resp.status_code == 400


def test_pull_unapproved_server(client, db_session):
    """GET /api/pull with pending server token returns 403."""
    resp = client.post(
        "/api/register",
        json={"hostname": "web03", "ip_address": "10.0.0.3"},
    )
    token = resp.get_json()["agent_token"]

    resp = client.get(
        "/api/pull",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


def test_pull_approved_server(client, db_session):
    """GET /api/pull with approved server returns users and policy."""
    # Register
    resp = client.post(
        "/api/register",
        json={"hostname": "web04", "ip_address": "10.0.0.4"},
    )
    token = resp.get_json()["agent_token"]

    # Approve server
    server = Server.query.filter_by(agent_token=token).first()
    server.status = "approved"
    db_session.commit()

    # Create a group with a user and assign server
    user = User(username="testuser", ssh_public_keys="ssh-ed25519 AAAA", is_sudo=True)
    group = Group(name="testgroup", pubkey_auth=True, password_auth=False)
    group.users.append(user)
    group.servers.append(server)
    db_session.add_all([user, group])
    db_session.commit()

    # Pull
    resp = client.get(
        "/api/pull",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["users"]) == 1
    assert data["users"][0]["username"] == "testuser"
    assert data["users"][0]["is_sudo"] is True
    assert "ssh-ed25519 AAAA" in data["users"][0]["ssh_keys"]
    assert data["ssh_policy"]["pubkey_auth"] is True
    assert data["ssh_policy"]["password_auth"] is False


def test_pull_no_token(client):
    """GET /api/pull without token returns 401."""
    resp = client.get("/api/pull")
    assert resp.status_code == 401


def test_heartbeat(client, db_session):
    """POST /api/heartbeat updates last_heartbeat."""
    # Register and approve
    resp = client.post(
        "/api/register",
        json={"hostname": "web05", "ip_address": "10.0.0.5"},
    )
    token = resp.get_json()["agent_token"]
    server = Server.query.filter_by(agent_token=token).first()
    server.status = "approved"
    db_session.commit()

    assert server.last_heartbeat is None

    resp = client.post(
        "/api/heartbeat",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200

    db_session.refresh(server)
    assert server.last_heartbeat is not None


def test_pull_direct_user(client, db_session):
    """GET /api/pull returns users assigned directly to server (without groups)."""
    resp = client.post(
        "/api/register",
        json={"hostname": "web-direct", "ip_address": "10.0.0.20"},
    )
    token = resp.get_json()["agent_token"]
    server = Server.query.filter_by(agent_token=token).first()
    server.status = "approved"

    user = User(username="directuser", ssh_public_keys="ssh-ed25519 DIRECT", password="secret123")
    server.direct_users.append(user)
    db_session.add(user)
    db_session.commit()

    resp = client.get(
        "/api/pull",
        headers={"Authorization": f"Bearer {token}"},
    )
    data = resp.get_json()
    assert len(data["users"]) == 1
    assert data["users"][0]["username"] == "directuser"
    assert data["users"][0]["password"] == "secret123"
    assert "ssh-ed25519 DIRECT" in data["users"][0]["ssh_keys"]


def test_pull_discovered_users_after_register(client, db_session):
    """Discovered users appear in pull after server is approved."""
    resp = client.post(
        "/api/register",
        json={
            "hostname": "web-discovered",
            "ip_address": "10.0.0.21",
            "existing_users": [
                {"username": "existing_user", "ssh_keys": ["ssh-rsa KEY1"], "shell": "/bin/bash"},
            ],
        },
    )
    token = resp.get_json()["agent_token"]
    server = Server.query.filter_by(agent_token=token).first()
    server.status = "approved"
    db_session.commit()

    resp = client.get(
        "/api/pull",
        headers={"Authorization": f"Bearer {token}"},
    )
    data = resp.get_json()
    assert len(data["users"]) == 1
    assert data["users"][0]["username"] == "existing_user"
    assert "ssh-rsa KEY1" in data["users"][0]["ssh_keys"]


def test_deleted_user_removed_from_pull(client, db_session):
    """After deleting a user from DB, they disappear from pull (agent will remove them)."""
    resp = client.post(
        "/api/register",
        json={"hostname": "web-delete", "ip_address": "10.0.0.22"},
    )
    token = resp.get_json()["agent_token"]
    server = Server.query.filter_by(agent_token=token).first()
    server.status = "approved"

    user = User(username="tobedeleted")
    server.direct_users.append(user)
    db_session.add(user)
    db_session.commit()

    # Verify user appears in pull
    resp = client.get("/api/pull", headers={"Authorization": f"Bearer {token}"})
    assert len(resp.get_json()["users"]) == 1

    # Delete user
    db_session.delete(user)
    db_session.commit()

    # Verify user is gone from pull
    resp = client.get("/api/pull", headers={"Authorization": f"Bearer {token}"})
    assert len(resp.get_json()["users"]) == 0


def test_pull_blocked_user(client, db_session):
    """Blocked users are returned with is_blocked=True."""
    resp = client.post(
        "/api/register",
        json={"hostname": "web06", "ip_address": "10.0.0.6"},
    )
    token = resp.get_json()["agent_token"]
    server = Server.query.filter_by(agent_token=token).first()
    server.status = "approved"

    user = User(username="blocked_user", is_blocked=True)
    group = Group(name="grp_blocked")
    group.users.append(user)
    group.servers.append(server)
    db_session.add_all([user, group])
    db_session.commit()

    resp = client.get(
        "/api/pull",
        headers={"Authorization": f"Bearer {token}"},
    )
    data = resp.get_json()
    assert data["users"][0]["is_blocked"] is True


def test_removing_user_from_group_keeps_direct_access(client, db_session):
    """User removed from group retains direct server access."""
    resp = client.post(
        "/api/register",
        json={"hostname": "web-grp-rm", "ip_address": "10.0.0.30"},
    )
    token = resp.get_json()["agent_token"]
    server = Server.query.filter_by(agent_token=token).first()
    server.status = "approved"

    user = User(username="grptest_user", ssh_public_keys="ssh-ed25519 GRPKEY")
    # Direct access
    server.direct_users.append(user)
    # Group access (same server)
    group = Group(name="grp_temp")
    group.users.append(user)
    group.servers.append(server)
    db_session.add_all([user, group])
    db_session.commit()

    # Verify user in pull (via both paths)
    resp = client.get("/api/pull", headers={"Authorization": f"Bearer {token}"})
    assert len(resp.get_json()["users"]) == 1

    # Remove user from group
    group.users.remove(user)
    db_session.commit()

    # Direct access must persist
    resp = client.get("/api/pull", headers={"Authorization": f"Bearer {token}"})
    data = resp.get_json()
    assert len(data["users"]) == 1
    assert data["users"][0]["username"] == "grptest_user"


def test_removing_server_from_group_keeps_direct_users(client, db_session):
    """Server removed from group retains directly assigned users."""
    resp = client.post(
        "/api/register",
        json={"hostname": "web-srv-rm", "ip_address": "10.0.0.31"},
    )
    token = resp.get_json()["agent_token"]
    server = Server.query.filter_by(agent_token=token).first()
    server.status = "approved"

    user = User(username="srvtest_user", ssh_public_keys="ssh-ed25519 SRVKEY")
    # Direct access
    server.direct_users.append(user)
    # Also in group
    group = Group(name="grp_to_detach")
    group.users.append(user)
    group.servers.append(server)
    db_session.add_all([user, group])
    db_session.commit()

    # Remove server from group
    group.servers.remove(server)
    db_session.commit()

    # Direct access must persist
    resp = client.get("/api/pull", headers={"Authorization": f"Bearer {token}"})
    data = resp.get_json()
    assert len(data["users"]) == 1
    assert data["users"][0]["username"] == "srvtest_user"


def test_discovered_user_keeps_access_after_group_changes(client, db_session):
    """Discovered user retains direct access even after group is added then removed."""
    # Register with existing user (creates direct link)
    resp = client.post(
        "/api/register",
        json={
            "hostname": "web-disc-grp",
            "ip_address": "10.0.0.32",
            "existing_users": [
                {"username": "disc_user", "ssh_keys": ["ssh-rsa DISC1"], "shell": "/bin/bash"},
            ],
        },
    )
    token = resp.get_json()["agent_token"]
    server = Server.query.filter_by(agent_token=token).first()
    server.status = "approved"
    db_session.commit()

    disc_user = User.query.filter_by(username="disc_user").first()

    # Add server and user to a group
    group = Group(name="grp_disc_test")
    group.users.append(disc_user)
    group.servers.append(server)
    db_session.add(group)
    db_session.commit()

    # Pull should show user
    resp = client.get("/api/pull", headers={"Authorization": f"Bearer {token}"})
    assert len(resp.get_json()["users"]) == 1

    # Remove user from group
    group.users.remove(disc_user)
    db_session.commit()

    # Direct (discovered) access must remain
    resp = client.get("/api/pull", headers={"Authorization": f"Bearer {token}"})
    data = resp.get_json()
    assert len(data["users"]) == 1
    assert data["users"][0]["username"] == "disc_user"
    assert "ssh-rsa DISC1" in data["users"][0]["ssh_keys"]

    # Even remove server from group entirely
    group.servers.remove(server)
    db_session.commit()

    # Still has access via direct link
    resp = client.get("/api/pull", headers={"Authorization": f"Bearer {token}"})
    data = resp.get_json()
    assert len(data["users"]) == 1
    assert data["users"][0]["username"] == "disc_user"
