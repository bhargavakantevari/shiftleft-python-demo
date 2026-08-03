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

    safe_name = Path(filename_param).name
    filename = safe_name + ".txt"
    path = (user_dir_path / filename).resolve()
    if not str(path).startswith(str(user_dir_path.resolve())):
        return jsonify({"error": "invalid filename"}), 400
    with path.open("w", encoding="utf-8") as open_file:
        open_file.write(text_param)
    return jsonify({"success": True})


@bp.route("/grep_processes")
def grep_processes():
    name = request.args.get("name")
    if name is None:
        return jsonify({"error": "name parameter is required"})
    res = subprocess.run(
        ["ps", "aux"], capture_output=True,
    )
    if res.stdout is None:
        return jsonify({"error": "no stdout returned"})
    out = res.stdout.decode("utf-8")
    names = [line.split()[10] for line in out.splitlines() if name in line and len(line.split()) > 10]
    return jsonify({"success": True, "names": names})


@bp.route("/deserialized_descr", methods=["POST"])
def deserialized_descr():
    pickled = request.form.get('pickled')
    if pickled is None:
        return jsonify({"error": "pickled parameter is required"}), 400
    data = base64.urlsafe_b64decode(pickled)
    deserialized = json.loads(data)
    return jsonify({"success": True, "description": str(deserialized)})
