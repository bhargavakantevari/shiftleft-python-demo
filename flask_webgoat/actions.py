import json
import base64
import re
import subprocess
from pathlib import Path

from flask import Blueprint, request, jsonify, session

bp = Blueprint("actions", __name__)

SAFE_FILENAME_RE = re.compile(r"^[a-zA-Z0-9_\-]+$")


@bp.route("/message", methods=["POST"])
def log_entry():
    user_info = session.get("user_info", None)
    if user_info is None:
        return jsonify({"error": "no user_info found in session"})
    access_level = user_info[2]
    if access_level > 2:
        return jsonify({"error": "access level < 2 is required for this action"})
    filename_param = request.form.get("filename")
    if filename_param is None:
        return jsonify({"error": "filename parameter is required"})
    if not SAFE_FILENAME_RE.match(filename_param):
        return jsonify({"error": "filename must contain only alphanumeric characters, hyphens, and underscores"})
    text_param = request.form.get("text")
    if text_param is None:
        return jsonify({"error": "text parameter is required"})

    user_id = user_info[0]
    user_dir = Path("data") / str(user_id)
    if not user_dir.exists():
        user_dir.mkdir(parents=True)

    filename = filename_param + ".txt"
    path = user_dir / filename
    # Resolve and verify the final path is still inside the user's directory
    resolved = path.resolve()
    if not str(resolved).startswith(str(user_dir.resolve())):
        return jsonify({"error": "invalid file path"})
    with resolved.open("w", encoding="utf-8") as open_file:
        open_file.write(text_param)
    return jsonify({"success": True})


@bp.route("/grep_processes")
def grep_processes():
    name = request.args.get("name")
    if name is None:
        return jsonify({"error": "name parameter is required"})
    # Validate input to prevent command injection
    if not re.match(r"^[a-zA-Z0-9_\-.]+$", name):
        return jsonify({"error": "name must contain only alphanumeric characters, hyphens, underscores, and dots"})
    res = subprocess.run(
        ["ps", "aux"], capture_output=True
    )
    if res.stdout is None:
        return jsonify({"error": "no stdout returned"})
    out = res.stdout.decode("utf-8")
    names = [
        line.split()[10] if len(line.split()) > 10 else ""
        for line in out.split("\n")
        if name in line
    ]
    return jsonify({"success": True, "names": names})


@bp.route("/deserialized_descr", methods=["POST"])
def deserialized_descr():
    encoded = request.form.get('pickled')
    if encoded is None:
        return jsonify({"error": "pickled parameter is required"})
    try:
        data = base64.urlsafe_b64decode(encoded)
        deserialized = json.loads(data)
    except (json.JSONDecodeError, Exception):
        return jsonify({"error": "invalid data format"})
    return jsonify({"success": True, "description": str(deserialized)})
