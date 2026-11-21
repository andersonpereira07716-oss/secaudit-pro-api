# SecAudit PRO v3.1 — Roteiro Completo para Nota 10

## 1. Resiliência e Automação (Termux + pm2 + GitHub Actions)
- **Local (Termux):** daemon `secaudit-monitor` gerenciado por `pm2` (`2592000`s / 30 dias), lendo `~/secaudit_monitored_domains.json`, consultando `https://auditoria-seguranca-mvp.vercel.app/api/check-web`, gravando em `public.audits` no Supabase e alertando no Telegram (`@TheMachineAlertsBot`).
- **Nuvem (GitHub Actions):** workflow criado em `/data/data/com.termux/files/home/auditoria-seguranca-mvp/.github/workflows/secaudit-monitor.yml` com `workflow_dispatch` e agendamento periódico usando secrets `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` e `SECAUDIT_DOMAINS_JSON`.

## 2. Score dos Domínios e Evolução Antes x Depois
- **Alvos ativos (2):** Quack Empório (https://quack-emporio-patos-pb.surge.sh), Vila Sertão (https://vila-sertao-patos.surge.sh).
- **Estado atual:** `76/100` (`TLS: 90` | `HC: 45` | `DNS: 95`), `8` achados, `25` dias restantes de TLS, `DMARC: quarantine`, `TLS-RPT: ativo`.
- **Como subir o score real:** em domínios próprios ou atrás de camada/proxy com controle de headers/DNS, aplicar `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` e registro `CAA`, rodando nova checagem e `python3 ~/secaudit_comparativo.py --resumo` para comprovar o ganho **Antes x Depois**.

## 3. Relatório Executivo e Diagnóstico
- `python3 ~/diagnostico_host.py <host>` detalha sub-scores, `redirect_chain`, `dmarc_details`, `tls_rpt` e os `8` achados.
- `python3 ~/secaudit_comparativo.py --resumo` gera o resumo **Antes x Depois** com achados ativos e plano de ação pronto para envio.

## 4. Estrutura Comercial (Express, Completa e Mensal)
1. **Diagnóstico Express:** auditoria pontual (`check-web`), leitura de achados (`diagnostico_host.py`) e resumo executivo inicial.
2. **Auditoria Completa:** diagnóstico aprofundado + plano de correção (headers HTTP, DNS/`CAA`/`DMARC`, TLS) + revalidação com comparativo **Antes x Depois** (`secaudit_comparativo.py --resumo`).
3. **Acompanhamento Mensal:** monitoramento recorrente (`secaudit-monitor` no `pm2` + GitHub Actions), histórico em `public.audits` (Supabase), alertas em `@TheMachineAlertsBot` e relatório mensal de evolução.
