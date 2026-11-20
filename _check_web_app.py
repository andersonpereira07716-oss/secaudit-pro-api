import os, sys
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
from flask import Flask, request
from secaudit_v2_api import check_web as _check_web

app = Flask(__name__)

@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "OPTIONS"])
@app.route("/<path:path>", methods=["GET", "POST", "OPTIONS"])
def handler(path):
    with app.test_request_context(
        path="/api/check-web",
        query_string=request.query_string,
        method=request.method,
        data=request.get_data(),
        headers=dict(request.headers),
    ):
        resp = _check_web()
        if isinstance(resp, tuple):
            return resp
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return resp
