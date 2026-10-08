"""Relatorio HTML autocontido.

Cada achado mostra, separados por cor, o que foi observado, o que a ferramenta
interpretou, qual hipotese esta em aberto e qual evidencia ainda falta.
"""


import html
from pathlib import Path
from typing import Optional

from .. import __authors__
from ..model import EvidenceBundle, Finding, Severity

SEV_ORDER = [Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
SEV_LABEL = { Severity.HIGH: "ALTA", Severity.MEDIUM: "MEDIA",
             Severity.LOW: "BAIXA", Severity.INFO: "INFO"}

CSS = """
:root{--bg:#0f1319;--bg2:#151b24;--card:#182029;--line:#243040;--fg:#e6edf3;--fg2:#9aa9bb;--fg3:#6b7c91;--accent:#4da3ff;--green:#3ecf8e;--yellow:#ffc857;--red:#ff6b6b;--magenta:#c792ea;--blue:#5ec8ff;--crit:#ff4d4d;--high:#ff6b6b;--med:#ffc857;--low:#5ec8ff;--info:#7d8ea3}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
code,pre,.mono{font-family:ui-monospace,SFMono-Regular,"JetBrains Mono",Menlo,Consolas,monospace}
.wrap{max-width:1180px;margin:0 auto;padding:28px 20px 70px}
header.top{border-bottom:1px solid var(--line);padding-bottom:20px;margin-bottom:24px}
h1{margin:0 0 4px;font-size:27px;letter-spacing:-.01em}
.sub{color:var(--fg2);font-size:13.5px}
.pipe{display:inline-block;margin-top:10px;padding:5px 11px;border:1px solid var(--line);border-radius:6px;background:var(--bg2);color:var(--blue);font-size:12px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(215px,1fr));gap:10px;margin:18px 0 6px}
.meta div{background:var(--bg2);border:1px solid var(--line);border-radius:8px;padding:10px 13px}
.meta .k{color:var(--fg3);font-size:11px;text-transform:uppercase;letter-spacing:.07em}
.meta .v{font-size:13.5px;margin-top:3px;word-break:break-all}
h2{scroll-margin-top:14px;font-size:17px;margin:34px 0 12px;padding-bottom:7px;border-bottom:1px solid var(--line);color:var(--accent);letter-spacing:.01em}
h2 .n{color:var(--fg3);font-weight:400;margin-right:8px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.stat{background:var(--bg2);border:1px solid var(--line);border-radius:8px;padding:13px}
.stat .num{font-size:24px;font-weight:600}
.stat .lbl{color:var(--fg3);font-size:11.5px;text-transform:uppercase;letter-spacing:.06em;margin-top:2px}
.sev-crit .num{color:var(--crit)}
.sev-high .num{color:var(--high)}
.sev-med .num{color:var(--med)}
.sev-low .num{color:var(--low)}
.sev-info .num{color:var(--info)}
.finding{background:var(--card);border:1px solid var(--line);border-left-width:4px;border-radius:9px;padding:17px 19px;margin:15px 0}
.finding.crit{border-left-color:var(--crit)}
.finding.high{border-left-color:var(--high)}
.finding.med{border-left-color:var(--med)}
.finding.low{border-left-color:var(--low)}
.finding.info{border-left-color:var(--info)}
.fhead{display:flex;flex-wrap:wrap;gap:9px;align-items:center;margin-bottom:9px}
.badge{font-size:10.5px;font-weight:700;letter-spacing:.09em;padding:3px 8px;border-radius:4px;text-transform:uppercase}
.b-crit{background:var(--crit);color:#160b0b}
.b-high{background:var(--high);color:#1b0c0c}
.b-med{background:var(--med);color:#1c1503}
.b-low{background:var(--low);color:#04141c}
.b-info{background:var(--info);color:#0d1116}
.rule{font-family:ui-monospace,monospace;font-size:12px;color:var(--fg3);border:1px solid var(--line);padding:2px 7px;border-radius:4px}
.ftitle{font-size:16px;font-weight:600;flex:1 1 100%;margin-top:3px}
.chips{display:flex;flex-wrap:wrap;gap:7px;margin:9px 0 13px}
.chip{font-size:11.5px;color:var(--fg2);background:var(--bg2);border:1px solid var(--line);border-radius:20px;padding:3px 11px}
.chip b{color:var(--fg)}
.chip.corr{border-color:#4a3a63;color:var(--magenta)}
.origem .mitre{color:var(--fg3);font-size:11.5px}
.block{border-left:3px solid var(--line);padding:2px 0 2px 13px;margin:13px 0}
.block .h{font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;margin-bottom:6px}
.b-evid{border-left-color:var(--green)}
.b-evid .h{color:var(--green)}
.b-interp{border-left-color:var(--yellow)}
.b-interp .h{color:var(--yellow)}
.b-hyp{border-left-color:var(--magenta)}
.b-hyp .h{color:var(--magenta)}
.b-miss{border-left-color:var(--red)}
.b-miss .h{color:var(--red)}
.b-fp{border-left-color:var(--fg3)}
.b-fp .h{color:var(--fg3)}
.b-path{border-left-color:var(--blue)}
.b-path .h{color:var(--blue)}
ul.tight{margin:0;padding-left:19px}
ul.tight li{margin:4px 0}
ul.none{margin:0;padding:0;list-style:none}
.evi{background:var(--bg2);border:1px solid var(--line);border-radius:7px;padding:9px 12px;margin:7px 0}
.evi .kind{display:inline-block;font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--bg);background:var(--green);border-radius:3px;padding:1px 6px;margin-right:7px;vertical-align:1px}
.evi .kind.k-file{background:var(--yellow)}
.evi .kind.k-service{background:var(--blue)}
.evi .kind.k-log{background:var(--magenta)}
.evi .kind.k-user{background:#e0a8ff}
.evi .kind.k-socket{background:#7fe0d0}
.evi .src{color:var(--fg3);font-size:11.5px;margin-top:5px;font-family:ui-monospace,monospace}
.evi .raw{color:var(--fg2);font-size:11.5px;margin-top:4px;font-family:ui-monospace,monospace;background:#0d1219;border:1px solid var(--line);border-radius:5px;padding:6px 8px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
.path{font-family:ui-monospace,monospace;font-size:12.5px;background:#0d1219;border:1px solid var(--line);border-radius:6px;padding:10px 12px;line-height:1.8}
.path .step:before{content:"-> ";color:var(--blue)}
.path .step:first-child:before{content:"   "}
.conf{color:var(--fg3);font-size:11.5px;margin-top:12px;padding-top:9px;border-top:1px dashed var(--line)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--fg3);font-size:11px;text-transform:uppercase;letter-spacing:.07em;font-weight:600}
td.mono{font-family:ui-monospace,monospace;font-size:12px}
.tl-log{color:var(--magenta)}
.tl-process{color:var(--green)}
.tl-file{color:var(--yellow)}
.note{background:var(--bg2);border:1px solid var(--line);border-radius:8px;padding:13px 16px;color:var(--fg2);font-size:13.5px;margin:11px 0}
.note.ai{border-color:#4a3a63;background:#1a1526}
.ai-head{color:var(--magenta);font-weight:600;margin-bottom:6px}
.ai-body{white-space:pre-wrap;color:var(--fg);font-size:13.5px;line-height:1.65}
footer{margin-top:44px;padding-top:18px;border-top:1px solid var(--line);color:var(--fg3);font-size:12.5px;font-style:italic}
.empty{color:var(--green);background:var(--bg2);border:1px solid var(--line);border-radius:8px;padding:15px}
@media(max-width:640px){.wrap{padding:16px}
h1{font-size:22px}
}
"""


def _e(text) -> str:
    return html.escape(str(text if text is not None else ""))


def render_html(bundle: EvidenceBundle, path: Optional[str | Path] = None) -> str:
    P: list[str] = []
    a = P.append
    s = bundle.summary()

    a("<!doctype html><html lang='pt-BR'><head><meta charset='utf-8'>")
    a("<meta name='viewport' content='width=device-width,initial-scale=1'>")
    a(f"<title>Endpoint Investigator - {_e(bundle.host)}</title>")
    a(f"<style>{CSS}</style></head><body><div class='wrap'>")

    # ---- cabecalho ----
    a("<header class='top'>")
    a("<h1>Endpoint Investigator</h1>")
    a(f"<div class='sub'>Resultado da investigacao &middot; host <b>{_e(bundle.host)}</b> "
      f"&middot; {_e(bundle.generated_at)}</div>")
    a(f"<div class='sub' style='margin-top:3px'>{_e(' e '.join(__authors__))} "
      "&middot; Tecnologias Hackers &middot; Insper</div>")
    a("<div class='pipe'>COLETA &rarr; NORMALIZACAO &rarr; CORRELACAO &rarr; EVIDENCIAS "
      "&rarr; HIPOTESES &rarr; RESULTADO</div>")
    a("<div class='pipe' style='margin-left:8px;color:var(--green);"
      "border-color:#2f5a44'>Modelo da Aula 2: OBSERVE &rarr; HIPOTESE &rarr; "
      "EVIDENCIAS &rarr; CONCLUSAO</div>")
    a("<div class='meta'>")
    for k, v in (("Coletor", bundle.collector), ("Origem", bundle.origin),
                 ("Ferramenta", f"{bundle.tool} v{bundle.tool_version}"),
                 ("Schema", bundle.schema_version)):
        a(f"<div><div class='k'>{_e(k)}</div><div class='v'>{_e(v)}</div></div>")
    a("</div></header>")

    # ---- inventario ----
    a("<h2 id='sec-inventario'><span class='n'>1</span>Inventario coletado</h2><div class='grid'>")
    labels = {"processes": "Processos", "files": "Permissoes",
              "services": "Servicos", "logs": "Eventos de log",
              "users": "Identidades"}
    for k, label in labels.items():
        a(f"<div class='stat'><div class='num'>{bundle.inventory.get(k, 0)}</div>"
          f"<div class='lbl'>{_e(label)}</div></div>")
    a("</div>")
    g = bundle.coverage.get("grafo", {})
    if g:
        rels = ", ".join(f"{k[5:]}={v}" for k, v in sorted(g.items()) if k.startswith("edge_"))
        a(f"<div class='note'><b>Grafo de correlacao:</b> {g.get('nodes', 0)} entidades e "
          f"{g.get('edges', 0)} relacoes.<br><span class='mono' style='font-size:12px'>"
          f"{_e(rels)}</span></div>")

    # ---- resumo ----
    a("<h2 id='sec-resumo'><span class='n'>2</span>Resumo dos achados</h2><div class='grid'>")
    css_sev = {Severity.HIGH: "high", Severity.MEDIUM: "med",
               Severity.LOW: "low", Severity.INFO: "info"}
    for sev in SEV_ORDER:
        a(f"<div class='stat sev-{css_sev[sev]}'><div class='num'>{s.get(sev.value, 0)}</div>"
          f"<div class='lbl'>{SEV_LABEL[sev]}</div></div>")
    a(f"<div class='stat'><div class='num'>{bundle.max_risk()}</div>"
      f"<div class='lbl'>Risco maximo</div></div>")
    a("</div>")

    # ---- achados ----
    a("<h2 id='sec-achados'><span class='n'>3</span>Achados &mdash; evidencia, interpretacao, hipotese e "
      "evidencia ausente</h2>")
    if not bundle.findings:
        a("<div class='empty'>Nenhum achado foi produzido pelas regras de correlacao sobre "
          "este snapshot. Isso nao significa ausencia de risco: significa que, com as fontes "
          "coletadas, nao houve correlacao suficiente para sustentar um achado.</div>")
    for f in bundle.findings:
        a(_finding_html(f, css_sev))

    # ---- linha do tempo ----
    if bundle.timeline:
        a("<h2 id='sec-linha-do-tempo'><span class='n'>4</span>Linha do tempo correlacionada</h2>")
        a("<table><thead><tr><th>Instante</th><th>Tipo</th><th>Entidade</th>"
          "<th>Detalhe</th><th>Fonte</th></tr></thead><tbody>")
        for e in bundle.timeline[:80]:
            ts = e.ts.strftime("%Y-%m-%d %H:%M:%S") if e.ts else "-"
            src = e.source.as_text() if e.source else "-"
            a(f"<tr><td class='mono'>{_e(ts)}</td>"
              f"<td class='tl-{_e(e.kind)}'>{_e(e.kind)}</td>"
              f"<td class='mono'>{_e(e.label)}</td><td>{_e(e.detail)}</td>"
              f"<td class='mono' style='color:var(--fg3)'>{_e(src)}</td></tr>")
        a("</tbody></table>")

    # ---- cobertura ----
    cov = bundle.coverage
    a("<h2 id='sec-cobertura'><span class='n'>5</span>Cobertura, notas e limitacoes</h2>")
    a(f"<div class='note'><b>Regras:</b> {cov.get('rules_total', 0)} registradas, "
      f"{len(cov.get('rules_executed', []))} executadas.<br>"
      f"<span class='mono' style='font-size:12px'>"
      f"{_e(', '.join(cov.get('rules_executed', [])))}</span></div>")
    if cov.get("rules_skipped"):
        a("<div class='note'><b>Regras nao executadas (dimensao ausente):</b><ul class='tight'>")
        for sk in cov["rules_skipped"]:
            a(f"<li><span class='mono'>{_e(sk['rule_id'])}</span> &mdash; {_e(sk['title'])}: "
              f"{_e(sk['reason'])}</li>")
        a("</ul></div>")
    if cov.get("engine_errors"):
        a("<div class='note'><b>Erros de execucao:</b><ul class='tight'>")
        for err in cov["engine_errors"]:
            a(f"<li>{_e(err)}</li>")
        a("</ul></div>")
    if bundle.notes:
        a("<div class='note'><b>Notas da coleta:</b><ul class='tight'>")
        for n in bundle.notes:
            a(f"<li>{_e(n)}</li>")
        a("</ul></div>")
    a("<div class='note'><b>Limitacoes declaradas do escopo:</b><ul class='tight'>")
    for lim in bundle.limitations:
        a(f"<li>{_e(lim)}</li>")
    a("</ul></div>")

    a("<footer>A ferramenta produz evidencias, interpretacoes e hipoteses. A conclusao "
      "sobre a existencia de um incidente e uma decisao do analista. "
      f"Bundle <span class='mono'>{_e(bundle.schema_version)}</span>.</footer>")
    a("</div></body></html>")

    text = "\n".join(P)
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(text, encoding="utf-8")
    return text


def _finding_html(f: Finding, css_sev) -> str:
    cls = css_sev[f.severity]
    P: list[str] = []
    a = P.append
    a(f"<div class='finding {cls}'>")
    a("<div class='fhead'>")
    a(f"<span class='badge b-{cls}'>{SEV_LABEL[f.severity]}</span>")
    a(f"<span class='rule'>{_e(f.rule_id)}</span>")
    a(f"<span class='rule'>risco {f.risk_score}/100</span>")
    a(f"<span class='rule'>confianca {_e(f.confidence.value)}</span>")
    a("<span class='rule' title='A ferramenta nunca afirma exploracao'>"
      "exploracao comprovada: nao</span>")
    a(f"<div class='ftitle'>{_e(f.title)}</div>")
    a("</div>")

    a("<div class='chips'>")
    a(f"<span class='chip corr'>correlacao: <b>{_e(f.correlation)}</b></span>")
    a(f"<span class='chip'>categoria: <b>{_e(f.category)}</b></span>")
    a(f"<span class='chip'>id: <b>{_e(f.fingerprint)}</b></span>")
    a(f"<span class='chip'>fontes: <b>{len(f.distinct_sources())}</b></span>")
    a("</div>")

    a("<div class='block b-evid'><div class='h'>Evidencia &mdash; o que foi observado</div>")
    for e in f.evidence:
        a("<div class='evi'>")
        a(f"<span class='kind k-{_e(e.kind)}'>{_e(e.kind)}</span>{_e(e.observed)}")
        a(f"<div class='src'>fonte: {_e(e.source.as_text())}</div>")
        if e.raw:
            a(f"<div class='raw'>{_e(e.raw)}</div>")
        a("</div>")
    a("</div>")

    a("<div class='block b-interp'><div class='h'>Interpretacao &mdash; significado tecnico"
      "</div>" + _e(f.interpretation) + "</div>")
    a("<div class='block b-hyp'><div class='h'>Hipotese &mdash; explicacao possivel, nao "
      "comprovada</div>" + _e(f.hypothesis) + "</div>")

    if f.attack_path:
        a("<div class='block b-path'><div class='h'>Cadeia reconstruida</div><div class='path'>")
        for step in f.attack_path:
            a(f"<div class='step'>{_e(step)}</div>")
        a("</div></div>")

    if f.missing_evidence:
        a("<div class='block b-miss'><div class='h'>Evidencia ausente &mdash; necessaria para "
          "confirmar ou rejeitar</div><ul class='tight'>")
        for m in f.missing_evidence:
            a(f"<li>{_e(m)}</li>")
        a("</ul></div>")

    if f.false_positives:
        a("<div class='block b-fp'><div class='h'>Possibilidade de falso positivo</div>"
          "<ul class='tight'>")
        for fp in f.false_positives:
            a(f"<li>{_e(fp)}</li>")
        a("</ul></div>")

    a(f"<div class='conf'>Base da confianca: {_e(f.confidence_reason)}</div>")
    a("</div>")
    return "".join(P)
