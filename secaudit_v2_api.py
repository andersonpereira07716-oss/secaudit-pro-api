import datetime, json, re, socket, ssl, urllib.error, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "MEDIO", "Adicione o cabecalho Strict-Transport-Security na resposta HTTP."),
    ("Content-Security-Policy", "MEDIO", "Adicione o cabecalho Content-Security-Policy na resposta HTTP."),
    ("X-Frame-Options", "MEDIO", "Adicione o cabecalho X-Frame-Options na resposta HTTP."),
    ("X-Content-Type-Options", "MEDIO", "Adicione o cabecalho X-Content-Type-Options na resposta HTTP."),
    ("Referrer-Policy", "MEDIO", "Adicione o cabecalho Referrer-Policy na resposta HTTP."),
    ("Permissions-Policy", "MEDIO", "Adicione o cabecalho Permissions-Policy na resposta HTTP."),
]
SEVERITY_PENALTY = {"CRITICO": 25, "ALTO": 15, "MEDIO": 6, "BAIXO": 3}
_DNS_TYPE_MAP = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28, "DS": 43, "DNSKEY": 48, "CAA": 257}
DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1")

def _normalize_target(raw_target: str) -> tuple[str, str, int]:
    v = (raw_target or "").strip()
    if not v:
        raise ValueError("Alvo nao informado.")
    if not re.match(r"^https?://", v, re.IGNORECASE):
        v = "https://" + v
    p = urllib.parse.urlparse(v)
    host = (p.hostname or "").strip().lower()
    if not host:
        raise ValueError("Hostname invalido no alvo.")
    port = p.port or (443 if p.scheme.lower() == "https" else 80)
    url = urllib.parse.urlunparse((p.scheme.lower() or "https", f"{host}:{port}" if p.port else host, p.path or "/", p.params, p.query, ""))
    return url, host, port

def _enc_name(name: str) -> bytes:
    parts = [x.encode("ascii", errors="ignore") for x in name.strip(".").split(".") if x]
    return b"".join(bytes([len(x)]) + x for x in parts) + b"\x00"

def _dec_name(buf: bytes, off: int) -> tuple[str, int]:
    labels, jumped, nxt, jumps = [], False, off, 0
    while off < len(buf) and jumps < 10:
        ln = buf[off]
        if ln == 0:
            if not jumped:
                nxt = off + 1
            break
        if (ln & 0xC0) == 0xC0:
            if off + 1 >= len(buf):
                break
            ptr = ((ln & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                nxt = off + 2
            off, jumped, jumps = ptr, True, jumps + 1
            continue
        off += 1
        labels.append(buf[off:off + ln].decode("latin1", errors="ignore"))
        off += ln
    return ".".join(labels), nxt

def _udp_dns(host: str, rtype: str, srv: str = "1.1.1.1") -> tuple[list[str], bool]:
    qt = _DNS_TYPE_MAP.get(rtype.upper())
    if not qt:
        return [], False
    txid = (sum(ord(c) for c in host) + qt) & 0xFFFF
    pkt = txid.to_bytes(2, "big") + b"\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" + _enc_name(host) + qt.to_bytes(2, "big") + (1).to_bytes(2, "big")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(2.5)
        s.sendto(pkt, (srv, 53))
        resp, _ = s.recvfrom(4096)
    if len(resp) < 12:
        return [], False
    ad = bool(int.from_bytes(resp[2:4], "big") & 0x0020)
    qd, an, idx = int.from_bytes(resp[4:6], "big"), int.from_bytes(resp[6:8], "big"), 12
    for _ in range(qd):
        _, idx = _dec_name(resp, idx)
        idx += 4
    out = []
    for _ in range(an):
        if idx + 10 > len(resp):
            break
        _, idx = _dec_name(resp, idx)
        if idx + 10 > len(resp):
            break
        rt = int.from_bytes(resp[idx:idx + 2], "big")
        rdl = int.from_bytes(resp[idx + 8:idx + 10], "big")
        idx += 10
        rd = resp[idx:idx + rdl]
        idx += rdl
        if len(rd) < rdl:
            break
        if rt == 1 and rdl == 4:
            out.append(".".join(str(b) for b in rd))
        elif rt == 28 and rdl == 16:
            out.append(":".join(rd[i:i + 2].hex() for i in range(0, 16, 2)))
        elif rt in (2, 5):
            nm, _ = _dec_name(resp, idx - rdl)
            if nm:
                out.append(nm)
        elif rt == 15 and rdl >= 3:
            pref = int.from_bytes(rd[0:2], "big")
            mxn, _ = _dec_name(resp, idx - rdl + 2)
            if mxn:
                out.append(f"{pref} {mxn}")
        elif rt == 16 and rdl >= 1:
            chunks, pos = [], 0
            while pos < rdl:
                sl = rd[pos]
                pos += 1
                chunks.append(rd[pos:pos + sl].decode("utf-8", errors="ignore"))
                pos += sl
            j = "".join(chunks).strip()
            if j:
                out.append(j)
        elif rt == 257 and rdl >= 2:
            fl, tl = rd[0], rd[1]
            tag = rd[2:2 + tl].decode("ascii", errors="ignore")
            val = rd[2 + tl:].decode("utf-8", errors="ignore")
            out.append(f"{fl} {tag} \"{val}\"")
        elif rt in (43, 48) and rdl >= 4:
            out.append(f"type={rt} len={rdl}")
    return out, ad

def _dig_meta(host: str, rtype: str) -> tuple[list[str], bool]:
    ad_seen = False
    for srv in ("1.1.1.1", "8.8.8.8"):
        try:
            recs, ad = _udp_dns(host, rtype, srv)
            ad_seen = ad_seen or ad
            if recs:
                return recs, ad_seen
        except Exception:
            continue
    try:
        qt = _DNS_TYPE_MAP.get(rtype.upper())
        if qt:
            u = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(host)}&type={qt}"
            req = urllib.request.Request(u, headers={"Accept": "application/dns-json", "User-Agent": "SecAuditPRO/2.3"})
            with urllib.request.urlopen(req, timeout=3) as r:
                d = json.loads(r.read().decode("utf-8"))
                ad_seen = ad_seen or bool(d.get("AD"))
                vals = [str(a.get("data") or "").strip().strip('"') for a in (d.get("Answer") or []) if str(a.get("data") or "").strip()]
                if vals:
                    return vals, ad_seen
    except Exception:
        pass
    return [], ad_seen

def _dig(host: str, rtype: str) -> list[str]:
    return _dig_meta(host, rtype)[0]

def _spf_lookups(spf_recs: list[str]) -> int:
    if not spf_recs:
        return 0
    cnt = 0
    for tok in " ".join(spf_recs).lower().split():
        c = re.sub(r"^[+\-~?]", "", tok)
        if c.startswith(("include:", "exists:", "redirect=")) or c in ("a", "mx", "ptr") or c.startswith(("a:", "a/", "mx:", "mx/", "ptr:")):
            cnt += 1
    return cnt

def _mta_sts(base_domain: str) -> dict:
    txts = _dig(f"_mta-sts.{base_domain}", "TXT")
    has_dns = any("v=stsv1" in x.lower() for x in txts)
    ok, mode = False, None
    if has_dns:
        try:
            req = urllib.request.Request(f"https://mta-sts.{base_domain}/.well-known/mta-sts.txt", headers={"User-Agent": "SecAuditPRO/2.3"})
            with urllib.request.urlopen(req, timeout=4) as r:
                if getattr(r, "status", 200) == 200:
                    b = r.read().decode("utf-8", errors="ignore")
                    if "version: stsv1" in b.lower():
                        ok = True
                        m = re.search(r"^\s*mode\s*:\s*([a-zA-Z]+)", b, re.M | re.I)
                        if m:
                            mode = m.group(1).lower()
        except Exception:
            ok = False
    return {"has_dns_record": has_dns, "dns_records": txts[:3], "policy_accessible": ok, "mode": mode}

def _dns_email(host: str) -> dict:
    parts = host.split(".")
    base = ".".join(parts[-2:]) if len(parts) >= 2 else host
    a, aaaa = [], []
    try:
        for fam, _, _, _, sa in socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM):
            ip = sa[0]
            if fam == socket.AF_INET and ip not in a:
                a.append(ip)
            elif fam == socket.AF_INET6 and ip not in aaaa:
                aaaa.append(ip)
    except Exception:
        pass
    if not a:
        a = _dig(host, "A")
    if not aaaa:
        aaaa = _dig(host, "AAAA")
    mx, ad_mx = _dig_meta(base, "MX")
    ns, ad_ns = _dig_meta(base, "NS")
    caa = _dig(base, "CAA")
    txt = _dig(base, "TXT")
    dmarc_r = _dig(f"_dmarc.{base}", "TXT")
    dnskey, _ = _dig_meta(base, "DNSKEY")

    spf = [t for t in txt if "v=spf1" in t.lower()]
    has_spf = len(spf) > 0
    spf_strict = any(re.search(r"[-~]all\b", s.lower()) for s in spf)
    lookups = _spf_lookups(spf)

    dmarc_v = [d for d in dmarc_r if "v=dmarc1" in d.lower()]
    has_dmarc = len(dmarc_v) > 0
    pol = None
    if has_dmarc:
        m = re.search(r"\bp=([a-zA-Z]+)", dmarc_v[0], re.I)
        if m:
            pol = m.group(1).lower()

    dkim = []
    for sel in DKIM_SELECTORS:
        qn = f"{sel}._domainkey.{base}"
        tx = _dig(qn, "TXT")
        cn = _dig(qn, "CNAME") if not tx else []
        if any("v=dkim1" in x.lower() or "p=" in x.lower() for x in tx) or cn:
            dkim.append(sel)

    return {
        "domain": base, "a": a[:6], "aaaa": aaaa[:6], "mx": mx[:6], "ns": ns[:6], "caa": caa[:6],
        "spf": spf[:3], "dmarc": dmarc_v[:3], "dkim_selectors": dkim, "mta_sts": _mta_sts(base),
        "has_spf": has_spf, "spf_strict": spf_strict, "spf_lookups": lookups,
        "has_dmarc": has_dmarc, "dmarc_policy": pol, "has_dkim": len(dkim) > 0,
        "has_caa": len(caa) > 0, "dnssec_enabled": bool(ad_mx or ad_ns or dnskey),
    }

def _parse_csp(csp_val: str) -> dict[str, list[str]]:
    dirs = {}
    for part in (csp_val or "").split(";"):
        toks = [t.strip() for t in part.strip().split() if t.strip()]
        if toks:
            dirs[toks[0].lower()] = [t.lower() for t in toks[1:]]
    return dirs

def _probe_tls(host: str, port: int, ver) -> bool:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.minimum_version = ver
        ctx.maximum_version = ver
        with socket.create_connection((host, port), timeout=3) as s:
            with ctx.wrap_socket(s, server_hostname=host):
                return True
    except Exception:
        return False

def _tls(host: str, port: int = 443) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert()
                issuer = "Desconhecido"
                for tup in cert.get("issuer", ()):
                    for k, v in tup:
                        if k == "organizationName":
                            issuer = v
                            break
                    if issuer != "Desconhecido":
                        break
                na = cert.get("notAfter", "")
                days = None
                if na:
                    try:
                        exp = datetime.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                        days = int((exp - datetime.datetime.now(datetime.timezone.utc)).total_seconds() // 86400)
                    except Exception:
                        days = None
                return {
                    "tls_valid": True, "protocol": ss.version(),
                    "cipher": ss.cipher()[0] if ss.cipher() else None,
                    "issuer": issuer, "not_after": na, "days_remaining": days,
                    "supports_tls12": _probe_tls(host, port, ssl.TLSVersion.TLSv1_2),
                    "supports_tls13": _probe_tls(host, port, ssl.TLSVersion.TLSv1_3),
                }
    except Exception as e:
        return {"tls_valid": False, "protocol": None, "cipher": None, "issuer": None, "not_after": None, "days_remaining": None, "supports_tls12": False, "supports_tls13": False, "error": str(e)}

def _https_redirect(host: str) -> bool:
    class NoRedir(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    op = urllib.request.build_opener(NoRedir())
    req = urllib.request.Request(f"http://{host}/", headers={"User-Agent": "SecAuditPRO/2.3"})
    try:
        with op.open(req, timeout=5) as r:
            loc = (r.headers.get("Location") or "").lower()
            return r.status in (301, 302, 307, 308) and loc.startswith("https://")
    except urllib.error.HTTPError as e:
        loc = (e.headers.get("Location") or "").lower() if e.headers else ""
        return e.code in (301, 302, 307, 308) and loc.startswith("https://")
    except Exception:
        return False

def _fetch_hdrs(url: str) -> tuple[int, dict[str, str], list[str]]:
    req = urllib.request.Request(url, headers={"User-Agent": "SecAuditPRO/2.3"})
    cookies = []
    try:
        with urllib.request.urlopen(req, timeout=7) as r:
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            if hasattr(r.headers, "get_all"):
                cookies = r.headers.get_all("Set-Cookie") or []
            elif "set-cookie" in hdrs:
                cookies = [hdrs["set-cookie"]]
            return getattr(r, "status", 200), hdrs, cookies
    except urllib.error.HTTPError as e:
        hdrs = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        if e.headers and hasattr(e.headers, "get_all"):
            cookies = e.headers.get_all("Set-Cookie") or []
        return e.code, hdrs, cookies


def _detect_hosting_context(host: str, hdrs: dict, dns_info: dict) -> dict:
    h = (host or "").lower()
    srv = (hdrs.get("server") or "").lower()
    via = (hdrs.get("via") or "").lower()
    x_ver = (hdrs.get("x-vercel-id") or "").strip()
    cf_ray = (hdrs.get("cf-ray") or "").strip()
    ns_join = " ".join(dns_info.get("ns") or []).lower()

    provider = "custom/unknown"
    is_static_host = False
    can_set_custom_headers = True
    notes = []

    if h.endswith(".surge.sh") or "surge" in srv or "surge.sh" in ns_join:
        provider = "surge.sh"
        is_static_host = True
        can_set_custom_headers = False
        notes.append("Hospedagem estática Surge.sh: headers HTTP customizados e CAA nativo do host não são configuráveis diretamente no provedor.")
    elif x_ver or "vercel" in srv:
        provider = "vercel"
    elif cf_ray or "cloudflare" in srv or "cloudflare" in ns_join:
        provider = "cloudflare"

    if not is_static_host and ("github.io" in h or "pages.dev" in h or "netlify.app" in h):
        provider = h.split(".")[-2] + "." + h.split(".")[-1] if len(h.split(".")) >= 2 else h
        is_static_host = True
        can_set_custom_headers = False
        notes.append("Hospedagem estática/CDN gerenciada: alguns headers ou registros dependem da configuração da plataforma.")

    return {
        "provider": provider,
        "is_static_host": is_static_host,
        "can_set_custom_headers": can_set_custom_headers,
        "notes": notes,
    }

def _subscore(items: list[dict]) -> int:
    return max(0, min(100, 100 - sum(SEVERITY_PENALTY.get(i.get("severity", "MEDIO"), 6) for i in items)))

def run_audit(payload: dict) -> tuple[int, dict]:
    if not isinstance(payload, dict) or payload.get("authorized") is not True:
        return 403, {"error": 'Auditoria nao autorizada. Defina "authorized": true para executar o diagnostico.', "code": "AUTHORIZATION_REQUIRED"}
    client = (payload.get("client_name") or "Cliente Nao Informado").strip() or "Cliente Nao Informado"
    try:
        url, host, port = _normalize_target(payload.get("target") or payload.get("url") or "")
    except ValueError as err:
        return 400, {"error": str(err)}
    tls_f, web_f, dns_f, passed = [], [], [], []
    tls_info = _tls(host, port if port != 80 else 443)
    if tls_info.get("tls_valid"):
        passed.append(f"Certificado TLS valido ({tls_info.get('protocol')})")
        if tls_info.get("supports_tls13"):
            passed.append("Suporte a TLSv1.3 confirmado")
        d = tls_info.get("days_remaining")
        if isinstance(d, int):
            if d <= 7:
                tls_f.append({"category": "TLS", "title": f"Certificado TLS expira em {d} dia(s)", "severity": "CRITICO", "action": "Renove imediatamente o certificado TLS/SSL."})
            elif d <= 30:
                tls_f.append({"category": "TLS", "title": f"Certificado TLS expira em {d} dias", "severity": "ALTO", "action": "Agende a renovacao do certificado TLS/SSL."})
            else:
                passed.append(f"Validade TLS saudavel ({d} dias restantes)")
    else:
        tls_f.append({"category": "TLS", "title": "Falha na validacao TLS/SSL do alvo", "severity": "CRITICO", "action": "Verifique certificados, dominio e TLS no servidor."})
    redir = _https_redirect(host)
    if redir:
        passed.append("Redirecionamento HTTP para HTTPS ativo")
    else:
        tls_f.append({"category": "TLS", "title": "HTTP nao redireciona obrigatoriamente para HTTPS", "severity": "ALTO", "action": "Configure redirecionamento 301 de HTTP para HTTPS."})
    try:
        status, hdrs, cookies = _fetch_hdrs(url)
    except Exception as err:
        return 502, {"error": f"Falha ao conectar no alvo {url}: {err}", "target": url, "host": host}
    dns_info = _dns_email(host)
    hosting_ctx = _detect_hosting_context(host, hdrs, dns_info)
    static_host = hosting_ctx.get("is_static_host", False)
    for hname, sev, act in SECURITY_HEADERS:
        if hdrs.get(hname.lower()):
            passed.append(f"Cabecalho {hname} presente")
        else:
            eff_sev = "BAIXO" if (static_host and sev in ("ALTO", "MEDIO")) else sev
            eff_act = f"{act} (Host estatico {hosting_ctx.get('provider')}: avalie proxy/CDN como Cloudflare.)" if static_host else act
            web_f.append({"category": "HEADERS", "title": f"Cabecalho de seguranca ausente: {hname}", "severity": eff_sev, "action": eff_act})
    hsts_raw = hdrs.get("strict-transport-security", "")
    hsts_meta = {"present": bool(hsts_raw), "max_age": None, "include_subdomains": False, "preload": False}
    if hsts_raw:
        hsts_meta["include_subdomains"] = "includesubdomains" in hsts_raw.lower()
        hsts_meta["preload"] = "preload" in hsts_raw.lower()
        ma = re.search(r"max-age\s*=\s*(\d+)", hsts_raw, re.I)
        if ma:
            age = int(ma.group(1))
            hsts_meta["max_age"] = age
            if age < 15552000:
                web_f.append({"category": "HEADERS", "title": f"HSTS com max-age curto ({age}s)", "severity": "BAIXO", "action": "Use max-age >= 31536000 (1 ano) ou >= 15552000 (180 dias)."})
            else:
                passed.append("HSTS configurado com max-age robusto")
    csp_raw = hdrs.get("content-security-policy", "")
    csp_meta = {"present": bool(csp_raw), "directives_count": 0, "has_unsafe_inline_or_eval": False, "has_wildcard_script_or_default": False, "has_object_src_none": False, "has_frame_ancestors": False, "has_base_uri": False, "has_form_action": False}
    if csp_raw:
        ds = _parse_csp(csp_raw)
        csp_meta["directives_count"] = len(ds)
        csp_meta["has_base_uri"] = "base-uri" in ds
        csp_meta["has_form_action"] = "form-action" in ds
        stoks = [t.lower() for t in (ds.get("script-src") or ds.get("default-src") or [])]
        ytoks = [t.lower() for t in (ds.get("style-src") or [])]
        has_eval = "'unsafe-eval'" in csp_raw.lower()
        has_s_inl = "'unsafe-inline'" in stoks
        has_y_inl = "'unsafe-inline'" in ytoks
        if has_eval or has_s_inl:
            csp_meta["has_unsafe_inline_or_eval"] = True
            web_f.append({"category": "HEADERS", "title": "CSP permite unsafe-eval ou unsafe-inline em scripts", "severity": "ALTO" if has_eval else "MEDIO", "action": "Remova unsafe-eval e use nonce/hash em script-src."})
        elif has_y_inl:
            csp_meta["has_unsafe_inline_or_eval"] = True
            web_f.append({"category": "HEADERS", "title": "CSP permite unsafe-inline apenas em estilos", "severity": "BAIXO", "action": "Restrinja estilos inline ou use nonce/hash em style-src."})
        else:
            passed.append("CSP sem diretivas unsafe-inline/unsafe-eval")
        if "*" in stoks or "data:" in stoks:
            csp_meta["has_wildcard_script_or_default"] = True
            web_f.append({"category": "HEADERS", "title": "CSP com fonte ampla (* ou data:) em script-src/default-src", "severity": "MEDIO", "action": "Restrinja origens de scripts a dominios confiaveis."})
        otoks = [t.lower() for t in (ds.get("object-src") or [])]
        if "'none'" in otoks:
            csp_meta["has_object_src_none"] = True
            passed.append("CSP bloqueia plugins via object-src 'none'")
        elif "object-src" not in ds and "'none'" not in [t.lower() for t in (ds.get("default-src") or [])]:
            web_f.append({"category": "HEADERS", "title": "CSP sem object-src 'none' explicito", "severity": "BAIXO", "action": "Adicione object-src 'none' na CSP."})
        if "frame-ancestors" in ds:
            csp_meta["has_frame_ancestors"] = True
            passed.append("CSP define frame-ancestors contra clickjacking")
    for h_iso, label in (("cross-origin-opener-policy", "Cross-Origin-Opener-Policy"), ("cross-origin-resource-policy", "Cross-Origin-Resource-Policy")):
        if (hdrs.get(h_iso) or "").strip():
            passed.append(f"Cabecalho {label} presente ({hdrs.get(h_iso).strip()})")
    srv = hdrs.get("server", "")
    if re.search(r"[/]\s*\d+(\.\d+)+", srv):
        web_f.append({"category": "HEADERS", "title": f"Versao explicita do servidor exposta ({srv})", "severity": "BAIXO", "action": "Oculte versoes exatas no cabecalho Server."})
    if hdrs.get("x-powered-by", ""):
        web_f.append({"category": "HEADERS", "title": f"Tecnologia interna exposta em X-Powered-By ({hdrs.get('x-powered-by', '')})", "severity": "BAIXO", "action": "Remova X-Powered-By na resposta HTTP."})
    if (hdrs.get("access-control-allow-origin") or "").strip() == "*":
        web_f.append({"category": "HEADERS", "title": "CORS permissivo irrestrito (Access-Control-Allow-Origin: *)", "severity": "MEDIO", "action": "Restrinja Access-Control-Allow-Origin as origens confiaveis."})
    for rc in cookies:
        cl = rc.lower()
        cn = (rc.split("=", 1)[0] or "cookie").strip()
        if "httponly" not in cl:
            web_f.append({"category": "COOKIES", "title": f"Cookie sem flag HttpOnly: {cn}", "severity": "MEDIO", "action": f"Adicione HttpOnly ao cookie {cn} se nao precisar ser lido por JS."})
        if url.startswith("https://") and "secure" not in cl:
            web_f.append({"category": "COOKIES", "title": f"Cookie sem flag Secure em HTTPS: {cn}", "severity": "MEDIO", "action": f"Adicione Secure ao cookie {cn}."})
        if "samesite=" not in cl:
            web_f.append({"category": "COOKIES", "title": f"Cookie sem atributo SameSite: {cn}", "severity": "BAIXO", "action": f"Defina SameSite=Lax ou Strict no cookie {cn}."})
        if cn.startswith("__Host-") and ("secure" not in cl or "path=/" not in cl.replace(" ", "") or "domain=" in cl):
            web_f.append({"category": "COOKIES", "title": f"Cookie com prefixo __Host- fora do padrao: {cn}", "severity": "MEDIO", "action": "Cookies __Host- exigem Secure, Path=/ e sem Domain."})
        if cn.startswith("__Secure-") and "secure" not in cl:
            web_f.append({"category": "COOKIES", "title": f"Cookie com prefixo __Secure- sem Secure: {cn}", "severity": "MEDIO", "action": "Cookies __Secure- exigem Secure."})
    if dns_info.get("has_spf"):
        lk = dns_info.get("spf_lookups", 0)
        passed.append(f"Registro SPF configurado ({lk} DNS lookup(s) estimados)")
        if lk > 10:
            dns_f.append({"category": "DNS", "title": f"SPF excede limite de 10 DNS lookups ({lk} estimados)", "severity": "MEDIO", "action": "Consolide includes ou aplique flattening no SPF."})
        elif lk >= 8:
            dns_f.append({"category": "DNS", "title": f"SPF proximo do limite de 10 DNS lookups ({lk} estimados)", "severity": "BAIXO", "action": "Monitore os includes do SPF para ficar <= 10 lookups."})
        if not dns_info.get("spf_strict"):
            dns_f.append({"category": "DNS", "title": "Politica SPF sem fechamento restritivo (~all ou -all)", "severity": "BAIXO", "action": "Finalize o SPF com ~all ou -all."})
    else:
        dns_f.append({"category": "DNS", "title": f"Registro SPF ausente em {dns_info.get('domain')}", "severity": "MEDIO", "action": "Publique registro TXT v=spf1."})
    if dns_info.get("has_dmarc"):
        pol = dns_info.get("dmarc_policy") or "desconhecida"
        if pol == "none":
            dns_f.append({"category": "DNS", "title": "DMARC em modo apenas monitoramento (p=none)", "severity": "BAIXO", "action": "Evolua DMARC para p=quarantine ou p=reject."})
        else:
            passed.append(f"DMARC ativo com politica restritiva (p={pol})")
    else:
        dns_f.append({"category": "DNS", "title": f"Registro DMARC ausente em _dmarc.{dns_info.get('domain')}", "severity": "MEDIO", "action": "Configure registro TXT em _dmarc."})
    if dns_info.get("has_dkim"):
        passed.append(f"DKIM detectado ({ ', '.join(dns_info.get('dkim_selectors') or []) })")
    if dns_info.get("has_caa"):
        passed.append("Registro CAA configurado para emissao de certificados")
    elif not static_host:
        dns_f.append({"category": "DNS", "title": f"Registro CAA ausente em {dns_info.get('domain')}", "severity": "BAIXO", "action": "Publique registro CAA autorizando as CAs emissoras de certificados."})
    if dns_info.get("dnssec_enabled"):
        passed.append("DNSSEC autenticado no dominio")
    else:
        dns_f.append({"category": "DNS", "title": f"DNSSEC nao autenticado em {dns_info.get('domain')}", "severity": "BAIXO", "action": "Habilite DNSSEC no DNS/registrador."})
    mta = dns_info.get("mta_sts") or {}
    if mta.get("has_dns_record") and mta.get("policy_accessible"):
        passed.append(f"MTA-STS ativo (modo: {mta.get('mode') or 'detectado'})")
    elif mta.get("has_dns_record"):
        dns_f.append({"category": "DNS", "title": "Registro _mta-sts presente, mas politica /.well-known/mta-sts.txt inacessivel", "severity": "BAIXO", "action": "Publique mta-sts.txt em https://mta-sts.<dominio>/.well-known/mta-sts.txt."})
    elif dns_info.get("mx"):
        dns_f.append({"category": "DNS", "title": "MTA-STS nao configurado para dominio com registros MX", "severity": "BAIXO", "action": "Configure _mta-sts e mta-sts.txt."})
    if dns_info.get("domain") and _dig(f"_smtp._tls.{dns_info.get('domain')}", "TXT"):
        passed.append("TLS-RPT (_smtp._tls) configurado")
    findings = tls_f + web_f + dns_f
    score = max(0, min(100, 100 - sum(SEVERITY_PENALTY.get(f.get("severity", "MEDIO"), 6) for f in findings)))
    return 200, {
        "version": "3.1",
        "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "client_name": client,
        "target": url,
        "host": host,
        "http_status": status,
        "enforces_https": redir,
        "hosting_context": hosting_ctx,
        "score": score,
        "sub_scores": {"tls": _subscore(tls_f), "headers_cookies": _subscore(web_f), "dns_email": _subscore(dns_f)},
        "hsts": hsts_meta,
        "csp_analysis": csp_meta,
        "tls": tls_info,
        "dns": dns_info,
        "findings": findings,
        "passed_checks": passed,
    }

class handler(BaseHTTPRequestHandler):
    def _send_json(self, code: int, body: dict):
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_OPTIONS(self):
        self._send_json(204, {}) if False else (
            self.send_response(204),
            self.send_header("Access-Control-Allow-Origin", "*"),
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization"),
            self.end_headers(),
        )

    def do_GET(self):
        p = urllib.parse.urlparse(self.path).path
        self._send_json(200, {"service": "SecAudit PRO API", "status": "online", "version": "2.3", "endpoint": p or "/api/check-web"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or "0")
        raw = self.rfile.read(n) if n > 0 else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            self._send_json(400, {"error": "JSON invalido no corpo da requisicao."})
            return
        try:
            st, body = run_audit(payload)
        except Exception as e:
            st, body = 500, {"error": f"Erro interno na auditoria: {e}", "type": type(e).__name__}
        self._send_json(st, body)

def app(environ, start_response):
    m = (environ.get("REQUEST_METHOD") or "GET").upper()
    p = environ.get("PATH_INFO") or "/api/check-web"
    hdrs_cors = [("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"), ("Access-Control-Allow-Headers", "Content-Type, Authorization")]
    if m == "OPTIONS":
        start_response("204 No Content", hdrs_cors)
        return [b""]
    if m == "GET":
        b = json.dumps({"service": "SecAudit PRO API", "status": "online", "version": "2.3", "endpoint": p}, ensure_ascii=False).encode("utf-8")
        start_response("200 OK", [("Content-Type", "application/json; charset=utf-8"), ("Access-Control-Allow-Origin", "*"), ("Content-Length", str(len(b)))])
        return [b]
    if m == "POST":
        try:
            n = int(environ.get("CONTENT_LENGTH") or "0")
        except ValueError:
            n = 0
        raw = environ["wsgi.input"].read(n) if n > 0 else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            b = json.dumps({"error": "JSON invalido no corpo da requisicao."}, ensure_ascii=False).encode("utf-8")
            start_response("400 Bad Request", [("Content-Type", "application/json; charset=utf-8"), ("Access-Control-Allow-Origin", "*"), ("Content-Length", str(len(b)))])
            return [b]
        try:
            st, res = run_audit(payload)
        except Exception as e:
            st, res = 500, {"error": f"Erro interno na auditoria: {e}", "type": type(e).__name__}
        smap = {200: "200 OK", 400: "400 Bad Request", 403: "403 Forbidden", 500: "500 Internal Server Error", 502: "502 Bad Gateway"}
        b = json.dumps(res, ensure_ascii=False).encode("utf-8")
        start_response(smap.get(st, f"{st} OK"), [("Content-Type", "application/json; charset=utf-8"), ("Access-Control-Allow-Origin", "*"), ("Content-Length", str(len(b)))])
        return [b]
    b = json.dumps({"error": "Metodo nao suportado."}, ensure_ascii=False).encode("utf-8")
    start_response("405 Method Not Allowed", [("Content-Type", "application/json; charset=utf-8"), ("Access-Control-Allow-Origin", "*"), ("Content-Length", str(len(b)))])
    return [b]
