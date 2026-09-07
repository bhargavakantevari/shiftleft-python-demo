from urllib.parse import urlparse, urljoin

from flask import Blueprint, request, jsonify, session, redirect
from . import query_db, verify_password

bp = Blueprint("auth", __name__)


def is_safe_url(target):
    """Validate that a redirect URL is safe (same host only)."""
    if not target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return (
        test_url.scheme in ("http", "https")
        and ref_url.netloc == test_url.netloc
    )


@bp.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    if username is None or password is None:
        return (
            jsonify({"error": "username and password parameter have to be provided"}),
            400,
        )

    # Fix: SQL Injection - use parameterized query instead of string formatting
    query = (
        "SELECT id, username, password, access_level FROM user "
        "WHERE username = ?"
    )
    result = query_db(query, (username,), True)
    if result is None:
        return jsonify({"bad_login": True}), 400

    # Fix: Plaintext password - verify against stored hash
    stored_password = result[2]
    if not verify_password(password, stored_password):
        return jsonify({"bad_login": True}), 400

    session["user_info"] = (result[0], result[1], result[3])
    return jsonify({"success": True})


@bp.route("/login_and_redirect")
def login_and_redirect():
    username = request.args.get("username")
    password = request.args.get("password")
    url = request.args.get("url")
    if username is None or password is None or url is None:
        return (
            jsonify(
                {"error": "username, password, and url parameters have to be provided"}
            ),
            400,
        )

    query = "SELECT id, username, password, access_level FROM user WHERE username = ?"
    result = query_db(query, (username,), True)
    if result is None:
        # Fix: Open Redirect - only redirect to safe (same-origin) URLs
        if is_safe_url(url):
            return redirect(url)
        return jsonify({"error": "invalid redirect URL"}), 400

    # Fix: Plaintext password - verify against stored hash
    stored_password = result[2]
    if not verify_password(password, stored_password):
        return jsonify({"bad_login": True}), 400

    session["user_info"] = (result[0], result[1], result[3])
    return jsonify({"success": True})
