import json
import os
import urllib.parse
import urllib.request
from pathlib import Path

API_URL = os.getenv("SECAUDIT_API_URL", "https://auditoria-seguranca-mvp.vercel.app/api/check-web")
SB_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SB_KEY = os.getenv("SUPABASE_ANON_KEY", "")
SB_TABLE = os.getenv("SUPABASE_TABLE", "audits")
TG_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TG_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
DOMAINS_FILE = Path.home() / "secaudit_monitored_domains.json"


def http_json(method: str, url: str, payload=None, headers=None, timeout: int = 20):
    hdrs = {"Content-Type": "application/json", "User-Agent": "SecAuditPRO-Cron/3.0"}
    if headers:
        hdrs.update(headers)
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="ignore")
        return resp.status, json.loads(raw) if raw.strip() else {}


def sb_headers():
    return {
        "apikey": SB_KEY,
        "Authorization": f"Bearer {SB_KEY}",
        "Prefer": "return=representation",
    }


def load_targets():
    prev_by_host = {}
    if SB_URL and SB_KEY:
        q = urllib.parse.urlencode({"select": "host,target,client_name,score,sub_scores,findings,checked_at", "order": "checked_at.desc", "limit": "100"})
        try:
            _, rows = http_json("GET", f"{SB_URL}/rest/v1/{SB_TABLE}?{q}", headers=sb_headers())
            if isinstance(rows, list):
                for r in rows:
                    h = (r.get("host") or "").lower().strip()
                    if h and h not in prev_by_host:
                        prev_by_host[h] = r
        except Exception as exc:
            print("Aviso ao ler Supabase:", exc)

    if DOMAINS_FILE.exists():
        items = json.loads(DOMAINS_FILE.read_text(encoding="utf-8"))
        out = []
        for x in items:
            tgt = (x.get("target") or "").strip()
            if not tgt:
                continue
            host = urllib.parse.urlparse(tgt if "://" in tgt else "https://" + tgt).netloc.lower()
            out.append({
                "target": tgt if "://" in tgt else "https://" + tgt,
                "client_name": x.get("client_name") or host,
                "prev": prev_by_host.get(host),
            })
        return out
    if prev_by_host:
        return [
            {"target": r.get("target") or f"https://{h}", "client_name": r.get("client_name") or h, "prev": r}
            for h, r in prev_by_host.items()
        ]

    if DOMAINS_FILE.exists():
        items = json.loads(DOMAINS_FILE.read_text(encoding="utf-8"))
        return [{"target": x["target"], "client_name": x.get("client_name", x["target"]), "prev": None} for x in items]
    return []


def save_audit_sb(audit: dict):
    if not (SB_URL and SB_KEY):
        return
    row = {
        "client_name": audit.get("client_name"),
        "target": audit.get("target"),
        "host": audit.get("host"),
        "score": audit.get("score"),
        "sub_scores": audit.get("sub_scores"),
        "findings": audit.get("findings"),
        "payload": audit,
        "checked_at": audit.get("checked_at"),
    }
    try:
        http_json("POST", f"{SB_URL}/rest/v1/{SB_TABLE}", payload=row, headers=sb_headers())
    except Exception as exc:
        print("Erro ao salvar no Supabase:", exc)


def send_telegram(text: str):
    if not (TG_TOKEN and TG_CHAT_ID):
        print("[ALERTA SEM ENVIO - CONFIGURE TELEGRAM_BOT_TOKEN/CHAT_ID]\n" + text)
        return
    url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
    try:
        http_json("POST", url, payload={"chat_id": TG_CHAT_ID, "text": text, "parse_mode": "HTML"})
    except Exception as exc:
        print("Erro ao enviar Telegram:", exc)


def evaluate_alerts(curr: dict, prev: dict | None):
    alerts = []
    score = curr.get("score", 0)
    tls = curr.get("tls") or {}
    rc = curr.get("redirect_chain") or {}
    dns = curr.get("dns") or {}
    dmarc = dns.get("dmarc_details") or {}
    tls_rpt = dns.get("tls_rpt") or {}
    findings = curr.get("findings") or []

    high_crit = [f for f in findings if f.get("severity") in ("CRITICO", "ALTO")]
    if high_crit:
        titles = ", ".join(f.get("title", "") for f in high_crit[:3])
        alerts.append(f"Achados CRITICO/ALTO ({len(high_crit)}): {titles}")

    days = tls.get("days_remaining")
    if isinstance(days, int) and days < 30:
        alerts.append(f"Certificado TLS vence em {days} dia(s)")

    hops = rc.get("hops_count", 0)
    if hops >= 4 or not curr.get("enforces_https"):
        alerts.append(f"Redirecionamento: {hops} salto(s) | HTTPS forcado={curr.get('enforces_https')}")

    if not dns.get("has_dmarc") or dmarc.get("policy") == "none":
        alerts.append(f"DMARC: {dmarc.get('policy') or 'AUSENTE'} (pct={dmarc.get('pct')})")
    if not tls_rpt.get("enabled"):
        alerts.append("TLS-RPT desabilitado (_smtp._tls)")

    if prev and isinstance(prev.get("score"), int):
        delta = score - prev["score"]
        if delta < 0:
            alerts.append(f"Queda de score: {prev['score']} -> {score} ({delta:+d})")

    return alerts


def main():
    targets = load_targets()
    if not targets:
        print("Nenhum alvo encontrado. Crie ~/secaudit_monitored_domains.json ou configure SUPABASE_URL e SUPABASE_ANON_KEY.")
        return

    for item in targets:
        status, res = http_json(
            "POST",
            API_URL,
            payload={"target": item["target"], "client_name": item["client_name"], "authorized": True},
            timeout=25,
        )
        if status != 200 or "score" not in res:
            print(f"Falha em {item['target']} (HTTP {status}): {res}")
            continue

        save_audit_sb(res)
        alerts = evaluate_alerts(res, item.get("prev"))
        sub = res.get("sub_scores") or {}
        print(f"[{res.get('host')}] Score: {res.get('score')}/100 | TLS:{sub.get('tls')} HC:{sub.get('headers_cookies')} DNS:{sub.get('dns_email')} | Alertas: {len(alerts)}")

        if alerts:
            msg = (
                f"<b>SecAudit PRO v3.0 — Alerta de Monitoramento</b>\n"
                f"<b>Cliente:</b> {res.get('client_name')} (<code>{res.get('host')}</code>)\n"
                f"<b>Score:</b> <b>{res.get('score')}/100</b> (TLS {sub.get('tls')} | HC {sub.get('headers_cookies')} | DNS {sub.get('dns_email')})\n"
                f"<b>Ocorrencias:</b>\n• " + "\n• ".join(alerts)
            )
            send_telegram(msg)


if __name__ == "__main__":
    main()
