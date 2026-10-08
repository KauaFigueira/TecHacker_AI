"""Relatorio de terminal, so com a biblioteca padrao."""


import os
import shutil
import sys
from typing import List, Optional

from ..model import EvidenceBundle, Finding, Severity

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
ITALIC = "\033[3m"

SEV_COLOR = {
    Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m",
    Severity.LOW: "\033[96m",
    Severity.INFO: "\033[90m",
}
SEV_LABEL = {
    Severity.HIGH: "ALTA",
    Severity.MEDIUM: "MEDIA",
    Severity.LOW: "BAIXA",
    Severity.INFO: "INFO",
}
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
GREY = "\033[90m"


class Style:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def __call__(self, text: str, *codes: str) -> str:
        if not self.enabled or not codes:
            return text
        return "".join(codes) + text + RESET


def _width(default: int = 100) -> int:
    try:
        return min(shutil.get_terminal_size((default, 24)).columns, 118)
    except OSError:
        return default


def _wrap(text: str, width: int, indent: str = "", hang: bool = True) -> List[str]:
    """Quebra o texto; por padrao as linhas seguintes alinham sob a primeira
    (a marca de lista ``- `` / ``? `` nao e repetida)."""
    import textwrap
    subsequent = " " * len(indent) if hang else indent
    return textwrap.wrap(text, width=max(20, width), initial_indent=indent,
                         subsequent_indent=subsequent) or [indent.rstrip()]


def render_console(bundle: EvidenceBundle, stream=None, color: Optional[bool] = None,
                   verbose: bool = False, max_findings: int = 0) -> None:
    out = stream or sys.stdout
    if color is None:
        color = out.isatty() and os.environ.get("NO_COLOR") is None
    s = Style(color)
    w = _width()

    def line(ch: str = "-") -> None:
        out.write(s(ch * w, GREY) + "\n")

    # ---------------- cabecalho ---------------- #
    out.write("\n" + s("=" * w, CYAN) + "\n")
    out.write(s("  ENDPOINT INVESTIGATOR", BOLD, CYAN)
              + s(f"  v{bundle.tool_version}", GREY) + "\n")
    out.write(s("  Pipeline: COLETA -> NORMALIZACAO -> CORRELACAO -> EVIDENCIAS -> "
                "HIPOTESES -> RESULTADO", GREY) + "\n")
    out.write(s("  Modelo (Aula 2): OBSERVE -> HIPOTESE -> EVIDENCIAS -> CONCLUSAO", GREY)
              + "\n")
    out.write(s("=" * w, CYAN) + "\n\n")

    out.write(f"  {s('Host', BOLD):<28} {bundle.host}\n")
    out.write(f"  {s('Coletor', BOLD):<28} {bundle.collector}\n")
    out.write(f"  {s('Origem', BOLD):<28} {bundle.origin}\n")
    out.write(f"  {s('Gerado em', BOLD):<28} {bundle.generated_at}\n")

    inv = bundle.inventory
    out.write(f"\n  {s('INVENTARIO COLETADO', BOLD, BLUE)}\n")
    labels = {"processes": "processos", "files": "arquivos/permissoes",
              "services": "servicos", "logs": "eventos de log",
              "users": "identidades observadas"}
    for k, label in labels.items():
        val = inv.get(k, 0)
        mark = s("ok", GREEN) if val else s("--", GREY)
        out.write(f"    [{mark}] {label:<24} {val}\n")

    g = bundle.coverage.get("grafo", {})
    if g:
        out.write(f"\n  {s('GRAFO DE CORRELACAO', BOLD, BLUE)}\n")
        out.write(f"    {g.get('nodes', 0)} entidades, {g.get('edges', 0)} relacoes\n")
        rels = [(k[5:], v) for k, v in sorted(g.items()) if k.startswith("edge_")]
        if rels:
            out.write("    " + s(", ".join(f"{k}={v}" for k, v in rels), GREY) + "\n")

    # ---------------- resumo ---------------- #
    summary = bundle.summary()
    out.write(f"\n  {s('RESUMO DOS ACHADOS', BOLD, BLUE)}\n")
    parts = []
    for sev in (Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        n = summary.get(sev.value, 0)
        if n:
            parts.append(s(f"{SEV_LABEL[sev]}: {n}", SEV_COLOR[sev], BOLD))
    out.write("    " + ("   ".join(parts) if parts else s("nenhum achado", GREEN)) + "\n")
    out.write(f"    total: {summary['total']}   risco maximo: {bundle.max_risk()}/100\n")

    # ---------------- achados ---------------- #
    findings = bundle.findings[:max_findings] if max_findings else bundle.findings
    if findings:
        out.write("\n")
        line("=")
        out.write(s("  ACHADOS - EVIDENCIA / INTERPRETACAO / HIPOTESE / EVIDENCIA AUSENTE",
                    BOLD, CYAN) + "\n")
        line("=")
    for i, f in enumerate(findings, start=1):
        _render_finding(out, s, f, i, w, verbose)

    # ---------------- linha do tempo ---------------- #
    if bundle.timeline:
        out.write("\n")
        line("=")
        out.write(s("  LINHA DO TEMPO CORRELACIONADA", BOLD, CYAN) + "\n")
        line("=")
        shown = bundle.timeline if verbose else bundle.timeline[:14]
        for e in shown:
            ts = e.ts.strftime("%Y-%m-%d %H:%M:%S") if e.ts else "sem timestamp"
            kind_color = {"log": MAGENTA, "process": GREEN, "file": YELLOW}.get(e.kind, GREY)
            out.write(f"  {s(ts, GREY)}  {s(e.kind[:4].upper(), kind_color)}  "
                      f"{s(e.label, BOLD)}  {e.detail[:w - 52]}\n")
        if not verbose and len(bundle.timeline) > 14:
            out.write(s(f"  ... mais {len(bundle.timeline) - 14} eventos "
                        f"(use --verbose ou o relatorio HTML)\n", GREY))

    # ---------------- cobertura e limitacoes ---------------- #
    cov = bundle.coverage
    out.write("\n")
    line("=")
    out.write(s("  COBERTURA DA ANALISE", BOLD, CYAN) + "\n")
    line("=")
    out.write(f"  regras registradas: {cov.get('rules_total', 0)}   "
              f"executadas: {len(cov.get('rules_executed', []))}\n")
    for sk in cov.get("rules_skipped", []):
        out.write(s(f"  [pulada] {sk['rule_id']}: {sk['reason']}\n", GREY))
    for err in cov.get("engine_errors", []):
        out.write(s(f"  [erro]   {err}\n", RED))
    if cov.get("dimensoes_ausentes"):
        out.write(s(f"  dimensoes ausentes: {', '.join(cov['dimensoes_ausentes'])}\n", YELLOW))

    if bundle.notes:
        out.write(f"\n  {s('NOTAS DA COLETA', BOLD, BLUE)}\n")
        for n in bundle.notes:
            for ln in _wrap(n, w - 6, "    - "):
                out.write(s(ln, GREY) + "\n")

    out.write(f"\n  {s('LIMITACOES DECLARADAS DO ESCOPO', BOLD, BLUE)}\n")
    for lim in bundle.limitations:
        for ln in _wrap(lim, w - 6, "    - "):
            out.write(s(ln, GREY) + "\n")

    out.write("\n" + s("=" * w, CYAN) + "\n")
    out.write(s("  Esta ferramenta produz evidencias e hipoteses. A conclusao sobre a "
                "existencia de um\n  incidente e uma decisao do analista.", ITALIC, GREY) + "\n")
    out.write(s("=" * w, CYAN) + "\n\n")


def _render_finding(out, s: Style, f: Finding, idx: int, w: int, verbose: bool) -> None:
    sev = f.severity
    tag = f" {SEV_LABEL[sev]} "
    out.write("\n")
    out.write(s(tag, SEV_COLOR[sev], BOLD)
              + s(f" [{f.rule_id}] ", BOLD)
              + s(f.title, BOLD) + "\n")
    out.write(f"  {s('risco', GREY)} {f.risk_score}/100   "
              f"{s('confianca', GREY)} {f.confidence.value}   "
              f"{s('categoria', GREY)} {f.category}\n")
    out.write(f"  {s('correlacao', GREY)} {s(f.correlation, MAGENTA)}   "
              f"{s('id', GREY)} {f.fingerprint}\n")
    out.write("\n  " + s("EVIDENCIA (observado)", BOLD, GREEN) + "\n")
    for e in f.evidence:
        for ln in _wrap(f"[{e.kind}] {e.observed}", w - 8, "    - "):
            out.write(ln + "\n")
        out.write(s(f"      fonte: {e.source.as_text()}\n", GREY))
        if verbose and e.raw:
            for ln in _wrap(f"bruto: {e.raw}", w - 12, "      "):
                out.write(s(ln, DIM) + "\n")

    out.write("\n  " + s("INTERPRETACAO (significado tecnico)", BOLD, YELLOW) + "\n")
    for ln in _wrap(f.interpretation, w - 6, "    "):
        out.write(ln + "\n")

    out.write("\n  " + s("HIPOTESE (explicacao possivel, nao comprovada)", BOLD, MAGENTA) + "\n")
    for ln in _wrap(f.hypothesis, w - 6, "    "):
        out.write(ln + "\n")

    if f.attack_path:
        out.write("\n  " + s("CADEIA RECONSTRUIDA", BOLD, BLUE) + "\n")
        for i, step in enumerate(f.attack_path):
            arrow = "    " if i == 0 else "     -> "
            for ln in _wrap(step, w - 12, arrow):
                out.write(ln + "\n")

    if f.missing_evidence:
        out.write("\n  " + s("EVIDENCIA AUSENTE (necessaria para concluir)", BOLD, RED) + "\n")
        for m in f.missing_evidence:
            for ln in _wrap(m, w - 8, "    ? "):
                out.write(ln + "\n")

    if f.false_positives:
        out.write("\n  " + s("POSSIBILIDADE DE FALSO POSITIVO", BOLD, GREY) + "\n")
        for fp in f.false_positives:
            for ln in _wrap(fp, w - 8, "    ! "):
                out.write(s(ln, GREY) + "\n")

    out.write(s(f"\n  base da confianca: {f.confidence_reason}\n", DIM, GREY))
    out.write(s("  " + "." * (w - 4) + "\n", GREY))
