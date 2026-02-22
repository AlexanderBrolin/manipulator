from functools import wraps

import click
from flask import Blueprint, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from server.app import db
from server.models import AdminUser, AuditLog, Server

auth_bp = Blueprint("auth", __name__)

# --- Login page template ---

LOGIN_TEMPLATE = """
<!doctype html>
<html>
<head>
    <title>SSHADmin — Login</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
</head>
<body class="bg-light">
<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-4">
            <div class="card">
                <div class="card-body">
                    <h4 class="card-title text-center mb-4">SSHADmin</h4>
                    {% if error %}
                    <div class="alert alert-danger">{{ error }}</div>
                    {% endif %}
                    <form method="POST">
                        <div class="form-group">
                            <input type="text" name="username" class="form-control"
                                   placeholder="Username" required autofocus>
                        </div>
                        <div class="form-group">
                            <input type="password" name="password" class="form-control"
                                   placeholder="Password" required>
                        </div>
                        <button type="submit" class="btn btn-primary btn-block">Login</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
</body>
</html>
"""


@auth_bp.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        admin = AdminUser.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password_hash, password):
            session["admin_logged_in"] = True
            session["admin_username"] = username
            return redirect(url_for("admin.index"))
        return render_template_string(LOGIN_TEMPLATE, error="Bad credentials")
    return render_template_string(LOGIN_TEMPLATE, error=None)


@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login_page"))


# --- Agent token auth decorator ---


def agent_auth_required(f):
    """Validate agent Bearer token from the Server table."""

    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return {"msg": "Missing token"}, 401
        token = auth_header.split(" ", 1)[1]
        server = Server.query.filter_by(agent_token=token, status="approved").first()
        if not server:
            return {"msg": "Invalid or unapproved token"}, 403
        request.server = server
        return f(*args, **kwargs)

    return wrapper


# --- Audit helper ---


def audit_log(actor, action, target, details=""):
    entry = AuditLog(actor=actor, action=action, target=target, details=details)
    db.session.add(entry)
    db.session.commit()


# --- CLI command to create admin ---


@auth_bp.cli.command("create-admin")
@click.argument("username")
@click.password_option()
def create_admin_cmd(username, password):
    """Create an admin user for the web UI."""
    existing = AdminUser.query.filter_by(username=username).first()
    if existing:
        click.echo(f"Admin '{username}' already exists.")
        return
    admin = AdminUser(
        username=username,
        password_hash=generate_password_hash(password),
    )
    db.session.add(admin)
    db.session.commit()
    click.echo(f"Admin '{username}' created.")
