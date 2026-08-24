from urllib.parse import urlparse

from flask import Blueprint, request, jsonify, session, redirect
from . import query_db, verify_password

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    if username is None or password is None:
        return (
            jsonify({"error": "username and password parameter have to be provided"}),
            400,
        )

    query = "SELECT id, username, password, access_level FROM user WHERE username = ?"
    result = query_db(query, (username,), True)
    if result is None or not verify_password(password, result[2]):
        return jsonify({"bad_login": True}), 400
    session["user_info"] = (result[0], result[1], result[3])
    return jsonify({"success": True})


def is_safe_redirect_url(target, host_url):
    """Validate that a redirect URL is safe (same-origin, no open redirect)."""
    if not target:
        return False
    parsed = urlparse(target)
    # Only allow relative URLs (no netloc, no scheme)
    if parsed.scheme or parsed.netloc:
        return False
    if not target.startswith("/") or target.startswith("//"):
        return False
    return True


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
    if result is None or not verify_password(password, result[2]):
        return jsonify({"bad_login": True}), 400
    session["user_info"] = (result[0], result[1], result[3])

    if is_safe_redirect_url(url, request.host_url):
        return redirect(url)
    return jsonify({"success": True})
