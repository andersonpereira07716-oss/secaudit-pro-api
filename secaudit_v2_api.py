import os
import ssl
import socket
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone
from flask import Flask, request, jsonify

app = Flask(__name__)

SENSITIVE_PATHS = ["/.env", "/.git/config", "/phpinfo.php", "/wp-config.php", "/backup.zip", "/config.json"]
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def check_tls(host: str, port: int = 443):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                return {
                    "tls_valid": True,
                    "protocol": ssock.version(),
                    "not_after": cert.get("notAfter"),
                    "issuer": issuer.get("organizationName") or issuer.get("commonName") or "Desconhecido",
                }
    except Exception as exc:
        return {"tls_valid": False, "error": str(exc)}


def fetch_url(url: str, follow_redirects: bool = True):
    req = urllib.request.Request(url, headers={"User-Agent": "SecAudit-PRO/2.0 (Authorized Audit)"})

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener() if follow_redirects else urllib.request.build_opener(NoRedirect())
    with opener.open(req, timeout=6) as resp:
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return resp.status, getattr(resp, "url", url), headers


@app.after_request
def add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


@app.route("/", methods=["GET"])
@app.route("/api/check-web", methods=["GET", "POST", "OPTIONS"])
def check_web():
    if request.method == "OPTIONS":
        return ("", 204)
    if request.method == "GET" and not request.args.get("target"):
        return jsonify({"endpoint": "/api/check-web", "service": "SecAudit PRO API", "status": "online", "version": "2.0"})

    payload = request.get_json(silent=True) or {}
    target = (payload.get("target") or payload.get("url") or request.args.get("target") or "").strip()
    authorized = bool(payload.get("authorized", True))
    client_name = (payload.get("client_name") or "Cliente nao informado").strip()

    if not target:
        return jsonify({"error": "Alvo (URL ou dominio) obrigatorio."}), 400
    if not authorized:
        return jsonify({"error": "Autorizacao de auditoria obrigatoria antes da checagem."}), 403

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    parsed = urllib.parse.urlparse(target)
    host = parsed.hostname or target
    findings = []
    score = 100

    http_url = f"http://{host}"
    https_url = f"https://{host}" if parsed.scheme != "http" else target

    try:
        st_http, loc_http, _ = fetch_url(http_url, follow_redirects=False)
        if st_http not in (301, 302, 307, 308) or not (loc_http or "").startswith("https://"):
            score -= 15
            findings.append({"severity": "ALTO", "title": "HTTP nao redireciona obrigatoriamente para HTTPS", "action": "Configure redirecionamento 301 de HTTP para HTTPS no servidor ou CDN."})
    except Exception:
        pass

    tls_info = check_tls(host, 443)
    if not tls_info.get("tls_valid"):
        score -= 20
        findings.append({"severity": "CRITICO", "title": "Falha ou certificado TLS/SSL invalido em HTTPS", "action": "Verifique cadeia de certificados, validade e configuracao TLS 1.2/1.3."})

    headers = {}
    status_code = 0
    try:
        status_code, _, headers = fetch_url(https_url if target.startswith("https://") else target, follow_redirects=True)
    except Exception as exc:
        score -= 15
        findings.append({"severity": "MEDIO", "title": f"Falha ao consultar alvo: {exc}", "action": "Confirme se o alvo esta online e acessivel."})

    for h in SECURITY_HEADERS:
        if h.lower() not in headers:
            score -= 6
            findings.append({"severity": "MEDIO", "title": f"Cabecalho de seguranca ausente: {h}", "action": f"Adicione o cabecalho {h} na resposta HTTP."})

    server_banner = headers.get("server", "")
    if server_banner and any(ch.isdigit() for ch in server_banner):
        score -= 5
        findings.append({"severity": "MEDIO", "title": f"Banner Server expoe versao ({server_banner})", "action": "Oculte ou reduza versoes detalhadas do servidor web."})

    exposed_files = []
    for path in SENSITIVE_PATHS:
        try:
            st, _, _ = fetch_url(f"https://{host}{path}", follow_redirects=False)
            if st == 200:
                exposed_files.append(path)
        except Exception:
            continue
    if exposed_files:
        score -= 20
        findings.append({"severity": "CRITICO", "title": f"Arquivos sensiveis acessiveis: {', '.join(exposed_files)}", "action": "Bloqueie acesso externo a arquivos de configuracao, backups e repositorios."})

    score = max(0, min(100, score))
    return jsonify({
        "version": "2.0",
        "client_name": client_name,
        "target": target,
        "host": host,
        "http_status": status_code,
        "score": score,
        "tls": tls_info,
        "findings": findings,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
