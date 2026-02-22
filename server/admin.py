from flask import redirect, session, url_for
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView

from server.app import db
from server.models import AuditLog, Group, Server, User


class AuthMixin:
    """Protect all admin views behind session login."""

    def is_accessible(self):
        return session.get("admin_logged_in", False)

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for("auth.login_page"))


class SecureIndexView(AuthMixin, AdminIndexView):
    @expose("/")
    def index(self):
        return super().index()


class ServerView(AuthMixin, ModelView):
    column_list = [
        "id",
        "hostname",
        "ip_address",
        "os_info",
        "status",
        "last_heartbeat",
        "registered_at",
    ]
    column_filters = ["status", "hostname"]
    column_editable_list = ["status"]
    form_choices = {
        "status": [
            ("pending", "Pending"),
            ("approved", "Approved"),
            ("rejected", "Rejected"),
        ]
    }
    column_default_sort = ("registered_at", True)
    column_labels = {
        "os_info": "OS",
        "ip_address": "IP",
        "last_heartbeat": "Last Seen",
    }
    # Hide agent_token from forms for security
    form_excluded_columns = ["agent_token"]


class UserView(AuthMixin, ModelView):
    column_list = [
        "id",
        "username",
        "is_sudo",
        "is_blocked",
        "source",
        "shell",
        "groups",
        "created_at",
    ]
    column_filters = ["is_blocked", "is_sudo", "source"]
    column_editable_list = ["is_blocked", "is_sudo"]
    form_excluded_columns = ["created_at"]
    column_labels = {
        "ssh_public_keys": "SSH Keys",
        "is_sudo": "Sudo",
        "is_blocked": "Blocked",
    }
    form_widget_args = {
        "ssh_public_keys": {"rows": 6},
    }


class GroupView(AuthMixin, ModelView):
    column_list = [
        "id",
        "name",
        "password_auth",
        "pubkey_auth",
        "description",
        "users",
        "servers",
    ]
    column_labels = {
        "password_auth": "Password Auth",
        "pubkey_auth": "PubKey Auth",
    }


class AuditLogView(AuthMixin, ModelView):
    can_create = False
    can_edit = False
    can_delete = False
    column_list = ["id", "timestamp", "actor", "action", "target", "details"]
    column_filters = ["actor", "action", "target"]
    column_default_sort = ("timestamp", True)


def init_admin(app):
    admin = Admin(
        app,
        name="SSHADmin",
        template_mode="bootstrap4",
        index_view=SecureIndexView(),
    )
    admin.add_view(ServerView(Server, db.session, name="Servers"))
    admin.add_view(UserView(User, db.session, name="Users"))
    admin.add_view(GroupView(Group, db.session, name="Groups"))
    admin.add_view(AuditLogView(AuditLog, db.session, name="Audit Log"))
