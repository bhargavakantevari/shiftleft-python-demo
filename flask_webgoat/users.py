import sqlite3

from flask import Blueprint, jsonify, session, request

from . import query_db, hash_password

bp = Blueprint("users", __name__)


@bp.route("/create_user", methods=["POST"])
def create_user():
    user_info = session.get("user_info", None)
    if user_info is None:
        return jsonify({"error": "no user_info found in session"})

    access_level = user_info[2]
    if access_level != 0:
        return jsonify({"error": "access level of 0 is required for this action"})
    username = request.form.get("username")
    password = request.form.get("password")
    access_level = request.form.get("access_level")
    if username is None or password is None or access_level is None:
        return (
            jsonify(
                {
                    "error": "username, password and access_level parameters have to be provided"
                }
            ),
            400,
        )
    if len(password) < 3:
        return (
            jsonify({"error": "the password needs to be at least 3 characters long"}),
            402,
        )

    # Fix: SQL Injection - use parameterized query instead of string formatting
    # Fix: Plaintext password - store hashed password
    hashed_password = hash_password(password)
    try:
        access_level_int = int(access_level)
    except (ValueError, TypeError):
        return jsonify({"error": "access_level must be an integer"}), 400

    query = (
        "INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)"
    )

    try:
        query_db(query, (username, hashed_password, access_level_int), False, True)
        return jsonify({"success": True})
    except sqlite3.Error as err:
        return jsonify({"error": "could not create user: " + str(err)})
