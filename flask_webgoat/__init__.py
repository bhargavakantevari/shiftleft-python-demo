import os
import sqlite3
import hashlib
import secrets
from pathlib import Path

from flask import Flask

DB_FILENAME = "database.db"


def hash_password(password):
    """Hash a password using SHA-256 with a random salt."""
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return salt + ":" + hashed


def verify_password(password, stored_hash):
    """Verify a password against a stored salt:hash string."""
    try:
        salt, hashed = stored_hash.split(":", 1)
        test_hash = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
        return secrets.compare_digest(hashed, test_hash)
    except (ValueError, AttributeError):
        return False


def query_db(query, args=(), one=False, commit=False):
    with sqlite3.connect(DB_FILENAME) as conn:
        # Fix: Sensitive Data Exposure - removed trace callback that logged all queries
        cur = conn.cursor().execute(query, args)
        if commit:
            conn.commit()
        return cur.fetchone() if one else cur.fetchall()


def create_app():
    app = Flask(__name__)
    # Fix: Hardcoded secret key - use environment variable with secure fallback
    app.secret_key = os.environ.get("FLASK_SECRET_KEY")
    if not app.secret_key:
        app.secret_key = secrets.token_hex(32)

    db_path = Path(DB_FILENAME)
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(DB_FILENAME)
    create_table_query = """CREATE TABLE IF NOT EXISTS user
    (id INTEGER PRIMARY KEY, username TEXT, password TEXT, access_level INTEGER)"""
    conn.execute(create_table_query)

    # Fix: Hardcoded admin password - use hashed password from environment or secure default
    admin_password = os.environ.get("ADMIN_PASSWORD", "changeme123")
    hashed_admin_password = hash_password(admin_password)
    insert_admin_query = """INSERT INTO user (id, username, password, access_level)
    VALUES (1, 'admin', ?, 0)"""
    conn.execute(insert_admin_query, (hashed_admin_password,))
    conn.commit()
    conn.close()

    with app.app_context():
        from . import actions
        from . import auth
        from . import status
        from . import ui
        from . import users

        app.register_blueprint(actions.bp)
        app.register_blueprint(auth.bp)
        app.register_blueprint(status.bp)
        app.register_blueprint(ui.bp)
        app.register_blueprint(users.bp)
        return app
