import os
import sys

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from flask import Flask, jsonify, make_response, request
from secaudit_v2_api import run_audit

app = Flask(__name__)


def _with_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "OPTIONS"])
@app.route("/<path:path>", methods=["GET", "POST", "OPTIONS"])
def handler(path):
    if request.method == "OPTIONS":
        return _with_cors(make_response("", 204))

    if request.method == "GET":
        return _with_cors(jsonify({"status": "ok", "engine": "3.1", "endpoint": "/api/check-web"}))

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _with_cors(make_response(jsonify({"error": "JSON invalido no corpo da requisicao."}), 400))

    code, data = run_audit(payload)
    return _with_cors(make_response(jsonify(data), code))
