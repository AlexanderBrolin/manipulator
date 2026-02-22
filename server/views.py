from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from server.app import db
from server.auth import audit_log
from server.models import AuditLog, Group, Server, User

views_bp = Blueprint("views", __name__)


def login_required(f):
    from functools import wraps

    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("auth.login_page"))
        return f(*args, **kwargs)

    return wrapper


# --- Dashboard ---


@views_bp.route("/")
@login_required
def dashboard():
    stats = {
        "total_servers": Server.query.count(),
        "approved_servers": Server.query.filter_by(status="approved").count(),
        "pending_servers": Server.query.filter_by(status="pending").count(),
        "total_users": User.query.count(),
        "manual_users": User.query.filter_by(source="manual").count(),
        "discovered_users": User.query.filter_by(source="discovered").count(),
        "blocked_users": User.query.filter_by(is_blocked=True).count(),
        "total_groups": Group.query.count(),
    }
    recent_servers = Server.query.order_by(Server.registered_at.desc()).limit(5).all()
    recent_audit = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    return render_template(
        "dashboard.html",
        stats=stats,
        recent_servers=recent_servers,
        recent_audit=recent_audit,
    )


# --- Servers ---


@views_bp.route("/servers")
@login_required
def servers():
    all_servers = Server.query.order_by(Server.registered_at.desc()).all()
    return render_template("servers.html", servers=all_servers)


@views_bp.route("/servers/<int:id>/action", methods=["POST"])
@login_required
def server_action(id):
    server = Server.query.get_or_404(id)
    action = request.form.get("action")
    admin = session.get("admin_username", "admin")

    if action == "approve":
        server.status = "approved"
        db.session.commit()
        audit_log(admin, "server.approve", f"server:{server.hostname}")
        flash(f"Server {server.hostname} approved.", "success")
    elif action == "reject":
        server.status = "rejected"
        db.session.commit()
        audit_log(admin, "server.reject", f"server:{server.hostname}")
        flash(f"Server {server.hostname} rejected.", "success")
    elif action == "delete":
        hostname = server.hostname
        db.session.delete(server)
        db.session.commit()
        audit_log(admin, "server.delete", f"server:{hostname}")
        flash(f"Server {hostname} deleted.", "success")

    return redirect(url_for("views.servers"))


# --- Users ---


@views_bp.route("/users")
@login_required
def users():
    all_users = User.query.order_by(User.username).all()
    return render_template("users.html", users=all_users)


@views_bp.route("/users/edit", methods=["GET", "POST"])
@views_bp.route("/users/<int:id>/edit", methods=["GET", "POST"])
@login_required
def user_edit(id=None):
    user = User.query.get(id) if id else None
    all_groups = Group.query.order_by(Group.name).all()

    if request.method == "POST":
        admin = session.get("admin_username", "admin")

        if user is None:
            username = request.form.get("username", "").strip()
            if not username:
                flash("Username is required.", "error")
                return render_template("user_edit.html", user=None, all_groups=all_groups)
            if User.query.filter_by(username=username).first():
                flash(f"User '{username}' already exists.", "error")
                return render_template("user_edit.html", user=None, all_groups=all_groups)
            user = User(username=username, source="manual")
            db.session.add(user)
            action_name = "user.create"
        else:
            action_name = "user.update"

        user.ssh_public_keys = request.form.get("ssh_public_keys", "")
        password = request.form.get("password", "").strip()
        if password:
            user.password = password
        user.shell = request.form.get("shell", "/bin/bash")
        user.is_sudo = "is_sudo" in request.form
        user.is_blocked = "is_blocked" in request.form

        # Update group membership
        selected_group_ids = request.form.getlist("groups", type=int)
        user.groups = Group.query.filter(Group.id.in_(selected_group_ids)).all()

        db.session.commit()
        audit_log(admin, action_name, f"user:{user.username}")
        flash(f"User {user.username} saved.", "success")
        return redirect(url_for("views.users"))

    return render_template("user_edit.html", user=user, all_groups=all_groups)


@views_bp.route("/users/<int:id>/action", methods=["POST"])
@login_required
def user_action(id):
    user = User.query.get_or_404(id)
    action = request.form.get("action")
    admin = session.get("admin_username", "admin")

    if action == "block":
        user.is_blocked = True
        db.session.commit()
        audit_log(admin, "user.block", f"user:{user.username}")
        flash(f"User {user.username} blocked.", "success")
    elif action == "unblock":
        user.is_blocked = False
        db.session.commit()
        audit_log(admin, "user.unblock", f"user:{user.username}")
        flash(f"User {user.username} unblocked.", "success")
    elif action == "delete":
        username = user.username
        db.session.delete(user)
        db.session.commit()
        audit_log(admin, "user.delete", f"user:{username}")
        flash(f"User {username} deleted.", "success")

    return redirect(url_for("views.users"))


# --- Groups ---


@views_bp.route("/groups")
@login_required
def groups():
    all_groups = Group.query.order_by(Group.name).all()
    return render_template("groups.html", groups=all_groups)


@views_bp.route("/groups/edit", methods=["GET", "POST"])
@views_bp.route("/groups/<int:id>/edit", methods=["GET", "POST"])
@login_required
def group_edit(id=None):
    group = Group.query.get(id) if id else None
    all_servers = Server.query.filter_by(status="approved").order_by(Server.hostname).all()
    all_users = User.query.order_by(User.username).all()

    if request.method == "POST":
        admin = session.get("admin_username", "admin")

        if group is None:
            name = request.form.get("name", "").strip()
            if not name:
                flash("Group name is required.", "error")
                return render_template(
                    "group_edit.html", group=None, all_servers=all_servers, all_users=all_users
                )
            if Group.query.filter_by(name=name).first():
                flash(f"Group '{name}' already exists.", "error")
                return render_template(
                    "group_edit.html", group=None, all_servers=all_servers, all_users=all_users
                )
            group = Group(name=name)
            db.session.add(group)
            action_name = "group.create"
        else:
            group.name = request.form.get("name", group.name).strip()
            action_name = "group.update"

        group.description = request.form.get("description", "")
        group.pubkey_auth = "pubkey_auth" in request.form
        group.password_auth = "password_auth" in request.form

        # Update membership
        selected_server_ids = request.form.getlist("servers", type=int)
        group.servers = Server.query.filter(Server.id.in_(selected_server_ids)).all()

        selected_user_ids = request.form.getlist("users", type=int)
        group.users = User.query.filter(User.id.in_(selected_user_ids)).all()

        db.session.commit()
        audit_log(admin, action_name, f"group:{group.name}")
        flash(f"Group {group.name} saved.", "success")
        return redirect(url_for("views.groups"))

    return render_template(
        "group_edit.html", group=group, all_servers=all_servers, all_users=all_users
    )


@views_bp.route("/groups/<int:id>/action", methods=["POST"])
@login_required
def group_action(id):
    group = Group.query.get_or_404(id)
    action = request.form.get("action")
    admin = session.get("admin_username", "admin")

    if action == "delete":
        name = group.name
        db.session.delete(group)
        db.session.commit()
        audit_log(admin, "group.delete", f"group:{name}")
        flash(f"Group {name} deleted.", "success")

    return redirect(url_for("views.groups"))


# --- Audit ---


@views_bp.route("/audit")
@login_required
def audit():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(200).all()
    return render_template("audit.html", logs=logs)
