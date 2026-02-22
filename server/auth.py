from functools import wraps

import click
from flask import Blueprint, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from server.app import db
from server.models import AdminUser, AuditLog, Server

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login_page():
    if session.get("admin_logged_in"):
        return redirect(url_for("views.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        admin = AdminUser.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password_hash, password):
            session["admin_logged_in"] = True
            session["admin_username"] = username
            return redirect(url_for("views.dashboard"))
        return render_template("login.html", error="Bad credentials")
    return render_template("login.html", error=None)


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
