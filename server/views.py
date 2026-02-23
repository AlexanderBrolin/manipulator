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
    sort = request.args.get("sort", "registered")
    order = request.args.get("order", "desc")
    group_id = request.args.get("group", type=int)
    status_filter = request.args.get("status", "")

    query = Server.query

    # Filter by group
    if group_id:
        query = query.filter(Server.groups.any(Group.id == group_id))

    # Filter by status
    if status_filter in ("pending", "approved", "rejected"):
        query = query.filter_by(status=status_filter)

    # Sorting
    sort_map = {
        "hostname": Server.hostname,
        "ip": Server.ip_address,
        "status": Server.status,
        "registered": Server.registered_at,
        "heartbeat": Server.last_heartbeat,
    }
    sort_col = sort_map.get(sort, Server.registered_at)
    query = query.order_by(sort_col.desc() if order == "desc" else sort_col.asc())

    all_groups = Group.query.order_by(Group.name).all()
    return render_template(
        "servers.html",
        servers=query.all(),
        all_groups=all_groups,
        current_sort=sort,
        current_order=order,
        current_group=group_id,
        current_status=status_filter,
    )


@views_bp.route("/servers/<int:id>")
@login_required
def server_detail(id):
    server = Server.query.get_or_404(id)
    all_users = User.query.order_by(User.username).all()

    # Build list of (user, access_type_list) tuples
    users_access = {}
    for u in server.direct_users:
        users_access.setdefault(u.id, [u, []])
        users_access[u.id][1].append("direct")
    for group in server.groups:
        for u in group.users:
            users_access.setdefault(u.id, [u, []])
            users_access[u.id][1].append(group.name)

    all_server_users = [(v[0], v[1]) for v in users_access.values()]

    return render_template(
        "server_detail.html",
        server=server,
        all_users=all_users,
        all_server_users=all_server_users,
    )


@views_bp.route("/servers/<int:id>/update", methods=["POST"])
@login_required
def server_update(id):
    server = Server.query.get_or_404(id)
    admin = session.get("admin_username", "admin")

    old_hostname = server.hostname
    server.hostname = request.form.get("hostname", server.hostname).strip()
    server.ip_address = request.form.get("ip_address", server.ip_address).strip()
    server.os_info = request.form.get("os_info", "").strip()
    db.session.commit()

    details = f"hostname: {old_hostname} -> {server.hostname}" if old_hostname != server.hostname else ""
    audit_log(admin, "server.update", f"server:{server.hostname}", details)
    flash(f"Server {server.hostname} updated.", "success")
    return redirect(url_for("views.server_detail", id=server.id))


@views_bp.route("/servers/<int:id>/assign", methods=["POST"])
@login_required
def server_assign_users(id):
    server = Server.query.get_or_404(id)
    admin = session.get("admin_username", "admin")

    selected_user_ids = request.form.getlist("users", type=int)
    server.direct_users = User.query.filter(User.id.in_(selected_user_ids)).all()
    db.session.commit()
    audit_log(admin, "server.assign_users", f"server:{server.hostname}", f"Assigned {len(selected_user_ids)} users")
    flash(f"Users assigned to {server.hostname}.", "success")
    return redirect(url_for("views.server_detail", id=server.id))


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
    sort = request.args.get("sort", "username")
    order = request.args.get("order", "asc")
    source_filter = request.args.get("source", "")
    status_filter = request.args.get("status", "")

    query = User.query

    if source_filter in ("manual", "discovered"):
        query = query.filter_by(source=source_filter)
    if status_filter == "blocked":
        query = query.filter_by(is_blocked=True)
    elif status_filter == "active":
        query = query.filter_by(is_blocked=False)
    if status_filter == "sudo":
        query = query.filter_by(is_sudo=True)

    sort_map = {
        "username": User.username,
        "source": User.source,
        "created": User.created_at,
    }
    sort_col = sort_map.get(sort, User.username)
    query = query.order_by(sort_col.desc() if order == "desc" else sort_col.asc())

    return render_template(
        "users.html",
        users=query.all(),
        current_sort=sort,
        current_order=order,
        current_source=source_filter,
        current_status=status_filter,
    )


@views_bp.route("/users/edit", methods=["GET", "POST"])
@views_bp.route("/users/<int:id>/edit", methods=["GET", "POST"])
@login_required
def user_edit(id=None):
    user = User.query.get(id) if id else None
    all_groups = Group.query.order_by(Group.name).all()
    all_servers = Server.query.filter_by(status="approved").order_by(Server.hostname).all()

    if request.method == "POST":
        admin = session.get("admin_username", "admin")

        if user is None:
            username = request.form.get("username", "").strip()
            if not username:
                flash("Username is required.", "error")
                return render_template("user_edit.html", user=None, all_groups=all_groups, all_servers=all_servers)
            if User.query.filter_by(username=username).first():
                flash(f"User '{username}' already exists.", "error")
                return render_template("user_edit.html", user=None, all_groups=all_groups, all_servers=all_servers)
            user = User(username=username, source="manual")
            db.session.add(user)
            action_name = "user.create"
        else:
            action_name = "user.update"

        user.ssh_public_keys = request.form.get("ssh_public_keys", "")
        # Password: set if provided, clear if explicitly emptied
        user.password = request.form.get("password", "").strip()
        user.shell = request.form.get("shell", "/bin/bash")
        user.is_sudo = "is_sudo" in request.form
        user.is_blocked = "is_blocked" in request.form

        # Update group membership
        selected_group_ids = request.form.getlist("groups", type=int)
        user.groups = Group.query.filter(Group.id.in_(selected_group_ids)).all()

        # Update direct server assignment
        selected_server_ids = request.form.getlist("servers", type=int)
        user.direct_servers = Server.query.filter(Server.id.in_(selected_server_ids)).all()

        db.session.commit()
        audit_log(admin, action_name, f"user:{user.username}")
        flash(f"User {user.username} saved.", "success")
        return redirect(url_for("views.users"))

    return render_template("user_edit.html", user=user, all_groups=all_groups, all_servers=all_servers)


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
