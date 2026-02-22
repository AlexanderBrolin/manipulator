from datetime import datetime, timezone
from server.app import db

# --- Association tables ---

group_users = db.Table(
    "group_users",
    db.Column("group_id", db.Integer, db.ForeignKey("groups.id"), primary_key=True),
    db.Column("user_id", db.Integer, db.ForeignKey("users.id"), primary_key=True),
)

group_servers = db.Table(
    "group_servers",
    db.Column("group_id", db.Integer, db.ForeignKey("groups.id"), primary_key=True),
    db.Column("server_id", db.Integer, db.ForeignKey("servers.id"), primary_key=True),
)


# --- Models ---


class Server(db.Model):
    __tablename__ = "servers"

    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    os_info = db.Column(db.String(255), default="")
    agent_token = db.Column(db.String(255), unique=True, nullable=False)
    status = db.Column(db.String(20), default="pending")  # pending|approved|rejected
    last_heartbeat = db.Column(db.DateTime)
    registered_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )

    groups = db.relationship("Group", secondary=group_servers, back_populates="servers")

    def __repr__(self):
        return f"<Server {self.hostname} [{self.status}]>"


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    ssh_public_keys = db.Column(db.Text, default="")  # newline-separated
    password = db.Column(db.String(256), default="")  # plaintext for chpasswd on servers
    is_sudo = db.Column(db.Boolean, default=False)
    is_blocked = db.Column(db.Boolean, default=False)
    shell = db.Column(db.String(128), default="/bin/bash")
    source = db.Column(db.String(20), default="manual")  # manual|discovered
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )

    groups = db.relationship("Group", secondary=group_users, back_populates="users")

    def __repr__(self):
        return f"<User {self.username} [{self.source}]>"


class Group(db.Model):
    __tablename__ = "groups"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    password_auth = db.Column(db.Boolean, default=False)
    pubkey_auth = db.Column(db.Boolean, default=True)
    description = db.Column(db.Text, default="")

    users = db.relationship("User", secondary=group_users, back_populates="groups")
    servers = db.relationship(
        "Server", secondary=group_servers, back_populates="groups"
    )

    def __repr__(self):
        return f"<Group {self.name}>"


class AdminUser(db.Model):
    __tablename__ = "admin_users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )

    def __repr__(self):
        return f"<AdminUser {self.username}>"


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )
    actor = db.Column(db.String(128), default="")
    action = db.Column(db.String(64), default="")
    target = db.Column(db.String(128), default="")
    details = db.Column(db.Text, default="")

    def __repr__(self):
        return f"<AuditLog {self.action} by {self.actor}>"
