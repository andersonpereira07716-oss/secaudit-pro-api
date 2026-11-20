import datetime
import json
import re
import socket
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "MEDIO", "Adicione o cabecalho Strict-Transport-Security na resposta HTTP."),
    ("Content-Security-Policy", "MEDIO", "Adicione o cabecalho Content-Security-Policy na resposta HTTP."),
    ("X-Frame-Options", "MEDIO", "Adicione o cabecalho X-Frame-Options na resposta HTTP."),
    ("X-Content-Type-Options", "MEDIO", "Adicione o cabecalho X-Content-Type-Options na resposta HTTP."),
    ("Referrer-Policy", "MEDIO", "Adicione o cabecalho Referrer-Policy na resposta HTTP."),
    ("Permissions-Policy", "MEDIO", "Adicione o cabecalho Permissions-Policy na resposta HTTP."),
]

SEVERITY_PENALTY = {
    "CRITICO": 25,
    "ALTO": 15,
    "MEDIO": 6,
    "BAIXO": 3,
}


def _normalize_target(raw_target: str) -> tuple[str, str, int]:
    value = (raw_target or "").strip()
    if not value:
        raise ValueError("Alvo nao informado.")
    if not re.match(r"^https?://", value, re.IGNORECASE):
        value = "https://" + value
    parsed = urllib.parse.urlparse(value)
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise ValueError("Hostname invalido no alvo.")
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    normalized_url = urllib.parse.urlunparse((
        parsed.scheme.lower() or "https",
        f"{host}:{port}" if parsed.port else host,
        parsed.path or "/",
        parsed.params,
        parsed.query,
        "",
    ))
    return normalized_url, host, port


def _dig_records(host: str, rtype: str) -> list[str]:
    try:
        proc = subprocess.run(
            ["dig", "+short", rtype, host],
            capture_output=True,
            text=True,
            timeout=4,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return [line.strip().strip('"') for line in proc.stdout.strip().splitlines() if line.strip()]
    except Exception:
        pass
    return []


def _check_dns_and_email(host: str) -> dict:
    parts = host.split(".")
    base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else host

    a_records = []
    aaaa_records = []
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if family == socket.AF_INET and ip not in a_records:
                a_records.append(ip)
            elif family == socket.AF_INET6 and ip not in aaaa_records:
                aaaa_records.append(ip)
    except Exception:
        pass

    if not a_records:
        a_records = _dig_records(host, "A")
    if not aaaa_records:
        aaaa_records = _dig_records(host, "AAAA")

    mx_records = _dig_records(base_domain, "MX")
    ns_records = _dig_records(base_domain, "NS")
    caa_records = _dig_records(base_domain, "CAA")
    txt_records = _dig_records(base_domain, "TXT")
    dmarc_records = _dig_records(f"_dmarc.{base_domain}", "TXT")

    spf_records = [t for t in txt_records if "v=spf1" in t.lower()]
    has_spf = len(spf_records) > 0
    has_dmarc = any("v=dmarc1" in d.lower() for d in dmarc_records)
    has_caa = len(caa_records) > 0

    return {
        "domain": base_domain,
        "a": a_records[:6],
        "aaaa": aaaa_records[:6],
        "mx": mx_records[:6],
        "ns": ns_records[:6],
        "caa": caa_records[:6],
        "spf": spf_records[:3],
        "dmarc": dmarc_records[:3],
        "has_spf": has_spf,
        "has_dmarc": has_dmarc,
        "has_caa": has_caa,
    }


def _check_tls(host: str, port: int = 443) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                issuer_parts = cert.get("issuer", ())
                issuer = "Desconhecido"
                for tup in issuer_parts:
                    for k, v in tup:
                        if k == "organizationName":
                            issuer = v
                            break
                    if issuer != "Desconhecido":
                        break
                not_after = cert.get("notAfter", "")
                days_remaining = None
                if not_after:
                    try:
                        exp_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                            tzinfo=datetime.timezone.utc
                        )
                        now_dt = datetime.datetime.now(datetime.timezone.utc)
                        days_remaining = int((exp_dt - now_dt).total_seconds() // 86400)
                    except Exception:
                        days_remaining = None
                return {
                    "tls_valid": True,
                    "protocol": protocol,
                    "issuer": issuer,
                    "not_after": not_after,
                    "days_remaining": days_remaining,
                }
    except Exception as exc:
        return {
            "tls_valid": False,
            "protocol": None,
            "issuer": None,
            "not_after": None,
            "days_remaining": None,
            "error": str(exc),
        }


def _check_http_redirect(host: str) -> bool:
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(NoRedirect())
    req = urllib.request.Request(f"http://{host}/", headers={"User-Agent": "SecAuditPRO/2.1"})
    try:
        with opener.open(req, timeout=5) as resp:
            loc = (resp.headers.get("Location") or "").lower()
            return resp.status in (301, 302, 307, 308) and loc.startswith("https://")
    except urllib.error.HTTPError as err:
        loc = (err.headers.get("Location") or "").lower() if err.headers else ""
        return err.code in (301, 302, 307, 308) and loc.startswith("https://")
    except Exception:
        return False


def _fetch_target_headers(url: str) -> tuple[int, dict[str, str], list[str]]:
    req = urllib.request.Request(url, headers={"User-Agent": "SecAuditPRO/2.1"})
    set_cookies: list[str] = []
    try:
        with urllib.request.urlopen(req, timeout=7) as resp:
            status = getattr(resp, "status", 200)
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            if hasattr(resp.headers, "get_all"):
                set_cookies = resp.headers.get_all("Set-Cookie") or []
            elif "set-cookie" in hdrs:
                set_cookies = [hdrs["set-cookie"]]
            return status, hdrs, set_cookies
    except urllib.error.HTTPError as err:
        hdrs = {k.lower(): v for k, v in err.headers.items()} if err.headers else {}
        if err.headers and hasattr(err.headers, "get_all"):
            set_cookies = err.headers.get_all("Set-Cookie") or []
        return err.code, hdrs, set_cookies


def run_audit(payload: dict) -> tuple[int, dict]:
    if not isinstance(payload, dict) or payload.get("authorized") is not True:
        return 403, {
            "error": "Auditoria nao autorizada. Defina \"authorized\": true para executar o diagnostico.",
            "code": "AUTHORIZATION_REQUIRED",
        }

    raw_target = payload.get("target") or payload.get("url") or ""
    client_name = (payload.get("client_name") or "Cliente Nao Informado").strip() or "Cliente Nao Informado"

    try:
        target_url, host, port = _normalize_target(raw_target)
    except ValueError as exc:
        return 400, {"error": str(exc)}

    findings: list[dict] = []
    passed_checks: list[str] = []

    tls_info = _check_tls(host, port if port != 80 else 443)
    if tls_info.get("tls_valid"):
        passed_checks.append(f"Certificado TLS valido ({tls_info.get('protocol')})")
        days_rem = tls_info.get("days_remaining")
        if isinstance(days_rem, int):
            if days_rem <= 7:
                findings.append({
                    "title": f"Certificado TLS expira em {days_rem} dia(s)",
                    "severity": "CRITICO",
                    "action": "Renove imediatamente o certificado TLS/SSL para evitar indisponibilidade.",
                })
            elif days_rem <= 30:
                findings.append({
                    "title": f"Certificado TLS expira em {days_rem} dias",
                    "severity": "ALTO",
                    "action": "Agende a renovacao automatica ou manual do certificado TLS/SSL.",
                })
            else:
                passed_checks.append(f"Validade TLS saudavel ({days_rem} dias restantes)")
    else:
        findings.append({
            "title": "Falha na validacao TLS/SSL do alvo",
            "severity": "CRITICO",
            "action": "Verifique cadeia de certificados, dominio e configuracao TLS no servidor.",
        })

    enforces_https = _check_http_redirect(host)
    if enforces_https:
        passed_checks.append("Redirecionamento HTTP para HTTPS ativo")
    else:
        findings.append({
            "title": "HTTP nao redireciona obrigatoriamente para HTTPS",
            "severity": "ALTO",
            "action": "Configure redirecionamento 301 de HTTP para HTTPS no servidor ou CDN.",
        })

    try:
        http_status, headers, cookies = _fetch_target_headers(target_url)
    except Exception as exc:
        return 502, {
            "error": f"Falha ao conectar no alvo {target_url}: {exc}",
            "target": target_url,
            "host": host,
        }

    for header_name, severity, action in SECURITY_HEADERS:
        if headers.get(header_name.lower()):
            passed_checks.append(f"Cabecalho {header_name} presente")
        else:
            findings.append({
                "title": f"Cabecalho de seguranca ausente: {header_name}",
                "severity": severity,
                "action": action,
            })

    server_banner = headers.get("server", "")
    if re.search(r"[/]\s*\d+(\.\d+)+", server_banner):
        findings.append({
            "title": f"Versao explicita do servidor exposta ({server_banner})",
            "severity": "BAIXO",
            "action": "Oculte versoes exatas de software no cabecalho Server.",
        })

    aco = (headers.get("access-control-allow-origin") or "").strip()
    if aco == "*":
        findings.append({
            "title": "CORS permissivo irrestrito (Access-Control-Allow-Origin: *)",
            "severity": "MEDIO",
            "action": "Restrinja Access-Control-Allow-Origin apenas as origens confiaveis.",
        })

    for raw_cookie in cookies:
        c_low = raw_cookie.lower()
        c_name = raw_cookie.split("=", 1)[0].strip() or "cookie"
        if "httponly" not in c_low:
            findings.append({
                "title": f"Cookie sem flag HttpOnly: {c_name}",
                "severity": "MEDIO",
                "action": f"Adicione HttpOnly ao cookie {c_name} para reduzir risco de roubo via XSS.",
            })
        if target_url.startswith("https://") and "secure" not in c_low:
            findings.append({
                "title": f"Cookie sem flag Secure em HTTPS: {c_name}",
                "severity": "MEDIO",
                "action": f"Adicione Secure ao cookie {c_name} para envio apenas sobre HTTPS.",
            })

    dns_info = _check_dns_and_email(host)
    if dns_info.get("has_spf"):
        passed_checks.append("Registro SPF configurado no dominio")
    else:
        findings.append({
            "title": f"Registro SPF ausente em {dns_info.get('domain')}",
            "severity": "MEDIO",
            "action": "Publique um registro TXT v=spf1 para autorizar remetentes de e-mail.",
        })

    if dns_info.get("has_dmarc"):
        passed_checks.append("Registro DMARC configurado no dominio")
    else:
        findings.append({
            "title": f"Registro DMARC ausente em _dmarc.{dns_info.get('domain')}",
            "severity": "MEDIO",
            "action": "Configure registro TXT em _dmarc com politica de monitoramento ou rejeicao.",
        })

    if dns_info.get("has_caa"):
        passed_checks.append("Registro CAA configurado para emissao de certificados")

    total_penalty = sum(SEVERITY_PENALTY.get(f.get("severity", "MEDIO"), 6) for f in findings)
    score = max(0, min(100, 100 - total_penalty))

    result = {
        "version": "2.1",
        "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "client_name": client_name,
        "target": target_url,
        "host": host,
        "http_status": http_status,
        "enforces_https": enforces_https,
        "score": score,
        "tls": tls_info,
        "dns": dns_info,
        "findings": findings,
        "passed_checks": passed_checks,
    }
    return 200, result


class handler(BaseHTTPRequestHandler):
    def _send_json(self, status_code: int, body: dict):
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        self._send_json(200, {
            "service": "SecAudit PRO API",
            "status": "online",
            "version": "2.1",
            "endpoint": path or "/api/check-web",
        })

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or "0")
        raw_body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            payload = json.loads(raw_body.decode("utf-8") or "{}")
        except Exception:
            self._send_json(400, {"error": "JSON invalido no corpo da requisicao."})
            return

        status_code, response_body = run_audit(payload)
        self._send_json(status_code, response_body)
