"""Create initial admin user and sample data for development."""
from werkzeug.security import generate_password_hash

from server.app import create_app, db
from server.models import AdminUser, Group


def seed():
    app = create_app()
    with app.app_context():
        db.create_all()

        if not AdminUser.query.first():
            admin = AdminUser(
                username="admin",
                password_hash=generate_password_hash("admin"),
            )
            db.session.add(admin)
            print("Created admin user: admin / admin")
        else:
            print("Admin user already exists.")

        if not Group.query.first():
            db.session.add(
                Group(name="default", pubkey_auth=True, password_auth=False)
            )
            print("Created default group.")

        db.session.commit()
        print("Seed complete.")


if __name__ == "__main__":
    seed()
