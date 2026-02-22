from server.models import AuditLog, Group, Server, User


def test_create_server(db_session):
    server = Server(hostname="test01", ip_address="10.0.0.1", agent_token="tok-123")
    db_session.add(server)
    db_session.commit()

    assert server.id is not None
    assert server.status == "pending"
    assert server.registered_at is not None


def test_create_user(db_session):
    user = User(username="john", ssh_public_keys="ssh-ed25519 AAAA\nssh-rsa BBBB")
    db_session.add(user)
    db_session.commit()

    assert user.id is not None
    assert user.source == "manual"
    assert len(user.ssh_public_keys.split("\n")) == 2


def test_group_user_server_relationship(db_session):
    user = User(username="jane")
    server = Server(hostname="srv01", ip_address="10.0.0.10", agent_token="tok-456")
    group = Group(name="devteam")

    group.users.append(user)
    group.servers.append(server)
    db_session.add(group)
    db_session.commit()

    assert user in group.users
    assert server in group.servers
    assert group in user.groups
    assert group in server.groups


def test_audit_log(db_session):
    log = AuditLog(
        actor="admin",
        action="user.create",
        target="user:john",
        details="Created via UI",
    )
    db_session.add(log)
    db_session.commit()

    assert log.id is not None
    assert log.timestamp is not None
