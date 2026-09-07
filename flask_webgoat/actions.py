import json
import base64
from pathlib import Path
import subprocess

from flask import Blueprint, request, jsonify, session

bp = Blueprint("actions", __name__)


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
    text_param = request.form.get("text")
    if text_param is None:
        return jsonify({"error": "text parameter is required"})

    user_id = user_info[0]
    user_dir = "data/" + str(user_id)
    user_dir_path = Path(user_dir)
    if not user_dir_path.exists():
        user_dir_path.mkdir()

    # Fix: Directory Traversal - sanitize filename to prevent path traversal
    safe_filename = Path(filename_param).name
    if not safe_filename or safe_filename.startswith("."):
        return jsonify({"error": "invalid filename"}), 400
    filename = safe_filename + ".txt"

    # Ensure resolved path stays within user directory
    path = (user_dir_path / filename).resolve()
    if not str(path).startswith(str(user_dir_path.resolve())):
        return jsonify({"error": "invalid file path"}), 400

    with path.open("w", encoding="utf-8") as open_file:
        open_file.write(text_param)
    return jsonify({"success": True})


@bp.route("/grep_processes")
def grep_processes():
    name = request.args.get("name")
    if name is None:
        return jsonify({"error": "name parameter is required"}), 400

    # Fix: Remote Code Execution - avoid shell=True, use subprocess with argument list
    # and validate input to prevent command injection
    import re
    if not re.match(r'^[a-zA-Z0-9._-]+$', name):
        return jsonify({"error": "invalid name parameter"}), 400

    res = subprocess.run(
        ["ps", "aux"],
        capture_output=True,
        text=True,
    )
    if res.stdout is None:
        return jsonify({"error": "no stdout returned"})

    # Filter process names in Python instead of shell piping
    names = []
    for line in res.stdout.split("\n"):
        parts = line.split()
        if len(parts) >= 11:
            process_name = parts[10]
            if name.lower() in process_name.lower():
                names.append(process_name)
    return jsonify({"success": True, "names": names})


@bp.route("/deserialized_descr", methods=["POST"])
def deserialized_descr():
    pickled = request.form.get('pickled')
    if pickled is None:
        return jsonify({"error": "pickled parameter is required"}), 400

    # Fix: Insecure Deserialization - use JSON instead of pickle
    try:
        data = base64.urlsafe_b64decode(pickled)
        deserialized = json.loads(data)
    except (json.JSONDecodeError, ValueError, Exception) as e:
        return jsonify({"error": "invalid data: " + str(e)}), 400
    return jsonify({"success": True, "description": str(deserialized)})
