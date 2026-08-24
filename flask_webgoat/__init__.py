import os
import hashlib
import hmac
import sqlite3
from pathlib import Path

from flask import Flask

DB_FILENAME = "database.db"


def hash_password(password: str) -> str:
    """Hash a password using PBKDF2-HMAC-SHA256 with a random salt."""
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return salt.hex() + ":" + key.hex()


def verify_password(password: str, stored: str) -> bool:
    """Verify a password against a stored hash."""
    try:
        salt_hex, key_hex = stored.split(":")
        salt = bytes.fromhex(salt_hex)
        stored_key = bytes.fromhex(key_hex)
        new_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
        return hmac.compare_digest(stored_key, new_key)
    except (ValueError, AttributeError):
        return False


def query_db(query, args=(), one=False, commit=False):
    with sqlite3.connect(DB_FILENAME) as conn:
        cur = conn.cursor().execute(query, args)
        if commit:
            conn.commit()
        return cur.fetchone() if one else cur.fetchall()


def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET_KEY")
    if not app.secret_key:
        raise RuntimeError(
            "FLASK_SECRET_KEY environment variable must be set to a secure random value"
        )

    db_path = Path(DB_FILENAME)
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(DB_FILENAME)
    create_table_query = """CREATE TABLE IF NOT EXISTS user
    (id INTEGER PRIMARY KEY, username TEXT, password TEXT, access_level INTEGER)"""
    conn.execute(create_table_query)

    insert_admin_query = """INSERT INTO user (id, username, password, access_level)
    VALUES (1, 'admin', ?, 0)"""
    conn.execute(insert_admin_query, (hash_password("changeme-on-first-login"),))
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
