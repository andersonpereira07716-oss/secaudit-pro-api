import datetime
import json
import re
import socket
import ssl
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

_DNS_TYPE_MAP = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "CAA": 257,
}

DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1")


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


def _encode_dns_name(name: str) -> bytes:
    parts = [part.encode("ascii", errors="ignore") for part in name.strip(".").split(".") if part]
    return b"".join(bytes([len(part)]) + part for part in parts) + b"\x00"


def _decode_dns_name(buf: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    next_offset = offset
    seen_jumps = 0
    while offset < len(buf) and seen_jumps < 10:
        length = buf[offset]
        if length == 0:
            if not jumped:
                next_offset = offset + 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(buf):
                break
            pointer = ((length & 0x3F) << 8) | buf[offset + 1]
            if not jumped:
                next_offset = offset + 2
            offset = pointer
            jumped = True
            seen_jumps += 1
            continue
        offset += 1
        labels.append(buf[offset:offset + length].decode("latin1", errors="ignore"))
        offset += length
    return ".".join(labels), next_offset


def _query_udp_dns(host: str, rtype: str, server: str = "1.1.1.1") -> list[str]:
    qtype = _DNS_TYPE_MAP.get(rtype.upper())
    if not qtype:
        return []
    txid = (sum(ord(ch) for ch in host) + qtype) & 0xFFFF
    header = txid.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    question = _encode_dns_name(host) + qtype.to_bytes(2, "big") + (1).to_bytes(2, "big")
    packet = header + question

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2.5)
        sock.sendto(packet, (server, 53))
        resp, _ = sock.recvfrom(2048)

    if len(resp) < 12:
        return []
    qdcount = int.from_bytes(resp[4:6], "big")
    ancount = int.from_bytes(resp[6:8], "big")
    idx = 12
    for _ in range(qdcount):
        _, idx = _decode_dns_name(resp, idx)
        idx += 4

    results: list[str] = []
    for _ in range(ancount):
        if idx + 10 > len(resp):
            break
        _, idx = _decode_dns_name(resp, idx)
        if idx + 10 > len(resp):
            break
        rtype_num = int.from_bytes(resp[idx:idx + 2], "big")
        rdlen = int.from_bytes(resp[idx + 8:idx + 10], "big")
        idx += 10
        rdata = resp[idx:idx + rdlen]
        idx += rdlen
        if len(rdata) < rdlen:
            break

        if rtype_num == 1 and rdlen == 4:
            results.append(".".join(str(b) for b in rdata))
        elif rtype_num == 28 and rdlen == 16:
            groups = [rdata[i:i + 2].hex() for i in range(0, 16, 2)]
            results.append(":".join(groups))
        elif rtype_num in (2, 5):
            target_name, _ = _decode_dns_name(resp, idx - rdlen)
            if target_name:
                results.append(target_name)
        elif rtype_num == 15 and rdlen >= 3:
            pref = int.from_bytes(rdata[0:2], "big")
            mx_name, _ = _decode_dns_name(resp, idx - rdlen + 2)
            if mx_name:
                results.append(f"{pref} {mx_name}")
        elif rtype_num == 16 and rdlen >= 1:
            chunks: list[str] = []
            pos = 0
            while pos < rdlen:
                slen = rdata[pos]
                pos += 1
                chunks.append(rdata[pos:pos + slen].decode("utf-8", errors="ignore"))
                pos += slen
            joined = "".join(chunks).strip()
            if joined:
                results.append(joined)
        elif rtype_num == 257 and rdlen >= 2:
            flags = rdata[0]
            tlen = rdata[1]
            tag = rdata[2:2 + tlen].decode("ascii", errors="ignore")
            val = rdata[2 + tlen:].decode("utf-8", errors="ignore")
            results.append(f'{flags} {tag} "{val}"')

    return results


def _dig_records(host: str, rtype: str) -> list[str]:
    for srv in ("1.1.1.1", "8.8.8.8"):
        try:
            records = _query_udp_dns(host, rtype, srv)
            if records:
                return records
        except Exception:
            continue
    try:
        qtype = _DNS_TYPE_MAP.get(rtype.upper())
        if qtype:
            url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(host)}&type={qtype}"
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/dns-json", "User-Agent": "SecAuditPRO/2.2"},
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                out: list[str] = []
                for ans in data.get("Answer") or []:
                    val = str(ans.get("data") or "").strip().strip('"')
                    if val:
                        out.append(val)
                if out:
                    return out
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
    spf_strict = any(re.search(r"[-~]all\b", s.lower()) for s in spf_records)

    dmarc_valid = [d for d in dmarc_records if "v=dmarc1" in d.lower()]
    has_dmarc = len(dmarc_valid) > 0
    dmarc_policy = None
    if has_dmarc:
        m = re.search(r"\bp=([a-zA-Z]+)", dmarc_valid[0], re.IGNORECASE)
        if m:
            dmarc_policy = m.group(1).lower()

    dkim_found: list[str] = []
    for sel in DKIM_SELECTORS:
        qname = f"{sel}._domainkey.{base_domain}"
        txts = _dig_records(qname, "TXT")
        cnames = _dig_records(qname, "CNAME") if not txts else []
        if any("v=dkim1" in t.lower() or "p=" in t.lower() for t in txts) or cnames:
            dkim_found.append(sel)

    has_caa = len(caa_records) > 0

    return {
        "domain": base_domain,
        "a": a_records[:6],
        "aaaa": aaaa_records[:6],
        "mx": mx_records[:6],
        "ns": ns_records[:6],
        "caa": caa_records[:6],
        "spf": spf_records[:3],
        "dmarc": dmarc_valid[:3],
        "dkim_selectors": dkim_found,
        "has_spf": has_spf,
        "spf_strict": spf_strict,
        "has_dmarc": has_dmarc,
        "dmarc_policy": dmarc_policy,
        "has_dkim": len(dkim_found) > 0,
        "has_caa": has_caa,
    }


def _probe_tls_version(host: str, port: int, tls_ver) -> bool:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.minimum_version = tls_ver
        ctx.maximum_version = tls_ver
        with socket.create_connection((host, port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def _check_tls(host: str, port: int = 443) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher_info = ssock.cipher()
                cipher_name = cipher_info[0] if cipher_info else None
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

                supports_tls12 = _probe_tls_version(host, port, ssl.TLSVersion.TLSv1_2)
                supports_tls13 = _probe_tls_version(host, port, ssl.TLSVersion.TLSv1_3)

                return {
                    "tls_valid": True,
                    "protocol": protocol,
                    "cipher": cipher_name,
                    "issuer": issuer,
                    "not_after": not_after,
                    "days_remaining": days_remaining,
                    "supports_tls12": supports_tls12,
                    "supports_tls13": supports_tls13,
                }
    except Exception as exc:
        return {
            "tls_valid": False,
            "protocol": None,
            "cipher": None,
            "issuer": None,
            "not_after": None,
            "days_remaining": None,
            "supports_tls12": False,
            "supports_tls13": False,
            "error": str(exc),
        }


def _check_http_redirect(host: str) -> bool:
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(NoRedirect())
    req = urllib.request.Request(f"http://{host}/", headers={"User-Agent": "SecAuditPRO/2.2"})
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
    req = urllib.request.Request(url, headers={"User-Agent": "SecAuditPRO/2.2"})
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


def _calc_subscore(items: list[dict]) -> int:
    pen = sum(SEVERITY_PENALTY.get(i.get("severity", "MEDIO"), 6) for i in items)
    return max(0, min(100, 100 - pen))


def run_audit(payload: dict) -> tuple[int, dict]:
    if not isinstance(payload, dict) or payload.get("authorized") is not True:
        return 403, {
            "error": 'Auditoria nao autorizada. Defina "authorized": true para executar o diagnostico.',
            "code": "AUTHORIZATION_REQUIRED",
        }

    raw_target = payload.get("target") or payload.get("url") or ""
    client_name = (payload.get("client_name") or "Cliente Nao Informado").strip() or "Cliente Nao Informado"

    try:
        target_url, host, port = _normalize_target(raw_target)
    except ValueError as exc:
        return 400, {"error": str(exc)}

    tls_findings: list[dict] = []
    web_findings: list[dict] = []
    dns_findings: list[dict] = []
    passed_checks: list[str] = []

    # 1. TLS / SSL
    tls_info = _check_tls(host, port if port != 80 else 443)
    if tls_info.get("tls_valid"):
        passed_checks.append(f"Certificado TLS valido ({tls_info.get('protocol')})")
        if tls_info.get("supports_tls13"):
            passed_checks.append("Suporte a TLSv1.3 confirmado")
        days_rem = tls_info.get("days_remaining")
        if isinstance(days_rem, int):
            if days_rem <= 7:
                tls_findings.append({
                    "category": "TLS",
                    "title": f"Certificado TLS expira em {days_rem} dia(s)",
                    "severity": "CRITICO",
                    "action": "Renove imediatamente o certificado TLS/SSL para evitar indisponibilidade.",
                })
            elif days_rem <= 30:
                tls_findings.append({
                    "category": "TLS",
                    "title": f"Certificado TLS expira em {days_rem} dias",
                    "severity": "ALTO",
                    "action": "Agende a renovacao automatica ou manual do certificado TLS/SSL.",
                })
            else:
                passed_checks.append(f"Validade TLS saudavel ({days_rem} dias restantes)")
    else:
        tls_findings.append({
            "category": "TLS",
            "title": "Falha na validacao TLS/SSL do alvo",
            "severity": "CRITICO",
            "action": "Verifique cadeia de certificados, dominio e configuracao TLS no servidor.",
        })

    enforces_https = _check_http_redirect(host)
    if enforces_https:
        passed_checks.append("Redirecionamento HTTP para HTTPS ativo")
    else:
        tls_findings.append({
            "category": "TLS",
            "title": "HTTP nao redireciona obrigatoriamente para HTTPS",
            "severity": "ALTO",
            "action": "Configure redirecionamento 301 de HTTP para HTTPS no servidor ou CDN.",
        })

    # 2. HTTP Headers & Cookies
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
            web_findings.append({
                "category": "HEADERS",
                "title": f"Cabecalho de seguranca ausente: {header_name}",
                "severity": severity,
                "action": action,
            })

    # Qualidade do HSTS
    hsts_val = headers.get("strict-transport-security", "")
    if hsts_val:
        m_age = re.search(r"max-age\s*=\s*(\d+)", hsts_val, re.IGNORECASE)
        if m_age and int(m_age.group(1)) < 15552000:
            web_findings.append({
                "category": "HEADERS",
                "title": f"HSTS com max-age curto ({m_age.group(1)}s)",
                "severity": "BAIXO",
                "action": "Aumente max-age para pelo menos 15552000 (180 dias) ou 31536000 (1 ano).",
            })
        elif m_age:
            passed_checks.append("HSTS configurado com max-age robusto")

    # Qualidade do CSP
    csp_val = headers.get("content-security-policy", "")
    if csp_val:
        csp_low = csp_val.lower()
        if "'unsafe-inline'" in csp_low or "'unsafe-eval'" in csp_low:
            web_findings.append({
                "category": "HEADERS",
                "title": "Content-Security-Policy permite unsafe-inline ou unsafe-eval",
                "severity": "BAIXO",
                "action": "Substitua unsafe-inline/unsafe-eval por nonces ou hashes quando possivel.",
            })
        else:
            passed_checks.append("CSP sem diretivas unsafe-inline/unsafe-eval")

    server_banner = headers.get("server", "")
    if re.search(r"[/]\s*\d+(\.\d+)+", server_banner):
        web_findings.append({
            "category": "HEADERS",
            "title": f"Versao explicita do servidor exposta ({server_banner})",
            "severity": "BAIXO",
            "action": "Oculte versoes exatas de software no cabecalho Server.",
        })

    powered_by = headers.get("x-powered-by", "")
    if powered_by:
        web_findings.append({
            "category": "HEADERS",
            "title": f"Tecnologia interna exposta em X-Powered-By ({powered_by})",
            "severity": "BAIXO",
            "action": "Remova o cabecalho X-Powered-By na configuracao do servidor ou framework.",
        })

    aco = (headers.get("access-control-allow-origin") or "").strip()
    if aco == "*":
        web_findings.append({
            "category": "HEADERS",
            "title": "CORS permissivo irrestrito (Access-Control-Allow-Origin: *)",
            "severity": "MEDIO",
            "action": "Restrinja Access-Control-Allow-Origin apenas as origens confiaveis.",
        })

    for raw_cookie in cookies:
        c_low = raw_cookie.lower()
        c_name = raw_cookie.split("=", 1)[0].strip() or "cookie"
        if "httponly" not in c_low:
            web_findings.append({
                "category": "COOKIES",
                "title": f"Cookie sem flag HttpOnly: {c_name}",
                "severity": "MEDIO",
                "action": f"Adicione HttpOnly ao cookie {c_name} para reduzir risco de roubo via XSS.",
            })
        if target_url.startswith("https://") and "secure" not in c_low:
            web_findings.append({
                "category": "COOKIES",
                "title": f"Cookie sem flag Secure em HTTPS: {c_name}",
                "severity": "MEDIO",
                "action": f"Adicione Secure ao cookie {c_name} para envio apenas sobre HTTPS.",
            })
        if "samesite=" not in c_low:
            web_findings.append({
                "category": "COOKIES",
                "title": f"Cookie sem atributo SameSite: {c_name}",
                "severity": "BAIXO",
                "action": f"Defina SameSite=Lax ou SameSite=Strict no cookie {c_name} contra CSRF.",
            })

    # 3. DNS & Postura de E-mail
    dns_info = _check_dns_and_email(host)
    if dns_info.get("has_spf"):
        passed_checks.append("Registro SPF configurado no dominio")
        if not dns_info.get("spf_strict"):
            dns_findings.append({
                "category": "DNS",
                "title": "Politica SPF sem fechamento restritivo (~all ou -all)",
                "severity": "BAIXO",
                "action": "Finalize o registro SPF com ~all ou -all para evitar autorizacao aberta.",
            })
    else:
        dns_findings.append({
            "category": "DNS",
            "title": f"Registro SPF ausente em {dns_info.get('domain')}",
            "severity": "MEDIO",
            "action": "Publique um registro TXT v=spf1 para autorizar remetentes de e-mail.",
        })

    if dns_info.get("has_dmarc"):
        pol = dns_info.get("dmarc_policy") or "desconhecida"
        if pol == "none":
            dns_findings.append({
                "category": "DNS",
                "title": "DMARC em modo apenas monitoramento (p=none)",
                "severity": "BAIXO",
                "action": "Evolua a politica DMARC para p=quarantine ou p=reject apos validar os relatorios.",
            })
        else:
            passed_checks.append(f"DMARC ativo com politica restritiva (p={pol})")
    else:
        dns_findings.append({
            "category": "DNS",
            "title": f"Registro DMARC ausente em _dmarc.{dns_info.get('domain')}",
            "severity": "MEDIO",
            "action": "Configure registro TXT em _dmarc com politica de monitoramento ou rejeicao.",
        })

    if dns_info.get("has_dkim"):
        passed_checks.append(f"DKIM detectado ({', '.join(dns_info.get('dkim_selectors') or [])})")

    if dns_info.get("has_caa"):
        passed_checks.append("Registro CAA configurado para emissao de certificados")

    findings = tls_findings + web_findings + dns_findings
    total_penalty = sum(SEVERITY_PENALTY.get(f.get("severity", "MEDIO"), 6) for f in findings)
    score = max(0, min(100, 100 - total_penalty))

    result = {
        "version": "2.2",
        "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "client_name": client_name,
        "target": target_url,
        "host": host,
        "http_status": http_status,
        "enforces_https": enforces_https,
        "score": score,
        "sub_scores": {
            "tls": _calc_subscore(tls_findings),
            "headers_cookies": _calc_subscore(web_findings),
            "dns_email": _calc_subscore(dns_findings),
        },
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
            "version": "2.2",
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

        try:
            status_code, response_body = run_audit(payload)
        except Exception as exc:
            status_code = 500
            response_body = {"error": f"Erro interno na auditoria: {exc}", "type": type(exc).__name__}
        self._send_json(status_code, response_body)


def app(environ, start_response):
    method = (environ.get("REQUEST_METHOD") or "GET").upper()
    path = environ.get("PATH_INFO") or "/api/check-web"
    if method == "OPTIONS":
        start_response("204 No Content", [
            ("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
            ("Access-Control-Allow-Headers", "Content-Type, Authorization"),
        ])
        return [b""]
    if method == "GET":
        body = json.dumps({
            "service": "SecAudit PRO API",
            "status": "online",
            "version": "2.2",
            "endpoint": path,
        }, ensure_ascii=False).encode("utf-8")
        start_response("200 OK", [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Access-Control-Allow-Origin", "*"),
            ("Content-Length", str(len(body))),
        ])
        return [body]
    if method == "POST":
        try:
            length = int(environ.get("CONTENT_LENGTH") or "0")
        except ValueError:
            length = 0
        raw_body = environ["wsgi.input"].read(length) if length > 0 else b"{}"
        try:
            payload = json.loads(raw_body.decode("utf-8") or "{}")
        except Exception:
            body = json.dumps({"error": "JSON invalido no corpo da requisicao."}, ensure_ascii=False).encode("utf-8")
            start_response("400 Bad Request", [
                ("Content-Type", "application/json; charset=utf-8"),
                ("Access-Control-Allow-Origin", "*"),
                ("Content-Length", str(len(body))),
            ])
            return [body]
        try:
            status_code, response_body = run_audit(payload)
        except Exception as exc:
            status_code = 500
            response_body = {"error": f"Erro interno na auditoria: {exc}", "type": type(exc).__name__}
        status_map = {
            200: "200 OK",
            400: "400 Bad Request",
            403: "403 Forbidden",
            500: "500 Internal Server Error",
            502: "502 Bad Gateway",
        }
        body = json.dumps(response_body, ensure_ascii=False).encode("utf-8")
        start_response(status_map.get(status_code, f"{status_code} OK"), [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Access-Control-Allow-Origin", "*"),
            ("Content-Length", str(len(body))),
        ])
        return [body]
    body = json.dumps({"error": "Metodo nao suportado."}, ensure_ascii=False).encode("utf-8")
    start_response("405 Method Not Allowed", [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Access-Control-Allow-Origin", "*"),
        ("Content-Length", str(len(body))),
    ])
    return [body]
