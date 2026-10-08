"""Interface de linha de comando.

    python3 -m endpoint_investigator --live
    python3 -m endpoint_investigator --dataset datasets/04-inter-correlacao
    python3 -m endpoint_investigator --dataset DIR --out saida --all-formats
    python3 -m endpoint_investigator --list-rules
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __authors__, __version__
from .collectors import DatasetCollector, LiveLinuxCollector
from .correlation import ALL_RULES, CorrelationEngine
from .model import Severity
from .pipeline import investigate
from .reporting import render_console, render_html, render_json

EXIT_OK = 0
EXIT_FINDINGS = 1        # achados de severidade >= limiar
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="endpoint-investigator",
        description="Investigacao de endpoints GNU/Linux por correlacao de "
                    "evidencias entre processos, permissoes, servicos e logs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)

    src = p.add_argument_group("fonte de dados")
    g = src.add_mutually_exclusive_group()
    g.add_argument("--live", action="store_true",
                   help="coleta o estado real desta maquina Linux")
    g.add_argument("--dataset", metavar="DIR",
                   help="diretorio de dataset (processes.csv, permissions.csv, "
                        "services.txt, journal.log)")

    col = p.add_argument_group("opcoes de coleta (--live)")
    col.add_argument("--log-window", type=int, default=120, metavar="MIN",
                     help="janela de logs em minutos (padrao: 120)")
    col.add_argument("--max-processes", type=int, default=4000, metavar="N",
                     help="limite de processos lidos de /proc (padrao: 4000)")
    col.add_argument("--path", action="append", default=[], metavar="CAMINHO",
                     help="acrescenta um caminho de interesse a coleta de permissoes "
                          "(repetivel); a coleta continua orientada por contexto")

    out = p.add_argument_group("saida")
    out.add_argument("--out", metavar="DIR", help="diretorio para gravar relatorios")
    out.add_argument("--json", metavar="ARQ", help="grava o bundle estruturado em JSON")
    out.add_argument("--html", metavar="ARQ", help="grava o relatorio HTML")
    out.add_argument("--all-formats", action="store_true",
                     help="com --out, grava json + html + txt")
    out.add_argument("--quiet", action="store_true", help="nao imprime no terminal")
    out.add_argument("--verbose", "-v", action="store_true",
                     help="mostra o dado bruto de cada evidencia e a linha do tempo completa")
    out.add_argument("--no-color", action="store_true", help="desativa cores ANSI")
    out.add_argument("--min-severity", choices=[s.value for s in Severity],
                     default="info", help="filtra achados abaixo da severidade indicada")
    out.add_argument("--rule", action="append", default=[], metavar="ID",
                     help="mostra apenas os achados da regra indicada (repetivel)")

    misc = p.add_argument_group("diversos")
    misc.add_argument("--list-rules", action="store_true",
                      help="lista as regras de correlacao registradas e encerra")
    misc.add_argument("--fail-on", choices=[s.value for s in Severity], default=None,
                      help="retorna codigo 1 se houver achado >= severidade indicada")
    misc.add_argument("--version", action="version",
                      version=f"%(prog)s {__version__}  ({' e '.join(__authors__)})")
    return p


def list_rules() -> int:
    print(f"\nEndpoint Investigator {__version__} - regras de correlacao registradas")
    print(f"{' e '.join(__authors__)} - Tecnologias Hackers\n")
    print(f"  {'ID':<9} {'CORRELACAO':<52} TITULO")
    print("  " + "-" * 128)
    for r in ALL_RULES:
        print(f"  {r.id:<9} {r.correlation:<52} {r.title}")
    print(f"\n{len(ALL_RULES)} regras. Cada uma cruza pelo menos duas dimensoes e "
          f"declara evidencia,\ninterpretacao, hipotese e evidencia ausente.\n")
    return EXIT_OK


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_rules:
        return list_rules()
    if not args.live and not args.dataset:
        print("erro: informe --live (analisar esta maquina) ou --dataset DIR "
              "(analisar um dataset). Use --help para os detalhes.", file=sys.stderr)
        return EXIT_ERROR

    try:
        collector = (LiveLinuxCollector(max_processes=args.max_processes,
                                        log_window_min=args.log_window,
                                        extra_paths=args.path)
                     if args.live else DatasetCollector(args.dataset))
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return EXIT_ERROR

    def progress(etapa: str, msg: str) -> None:
        if not args.quiet:
            print(f"  [{etapa:<13}] {msg}", file=sys.stderr)

    if not args.quiet:
        print(f"\nEndpoint Investigator {__version__}", file=sys.stderr)

    bundle, _snap, _graph = investigate(collector, CorrelationEngine(),
                                        progress=progress)

    if args.min_severity != "info":
        piso = Severity(args.min_severity).rank
        bundle.findings = [f for f in bundle.findings if f.severity.rank >= piso]
    if args.rule:
        alvo = {r.strip().upper() for r in args.rule}
        bundle.findings = [f for f in bundle.findings if f.rule_id.upper() in alvo]

    if not args.quiet:
        render_console(bundle, color=not args.no_color, verbose=args.verbose)

    out_dir = Path(args.out) if args.out else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    alvos = []
    if args.json:
        alvos.append(("json", Path(args.json)))
    if args.html:
        alvos.append(("html", Path(args.html)))
    if out_dir and (args.all_formats or not alvos):
        alvos += [("json", out_dir / "report.json"), ("html", out_dir / "report.html")]
        if args.all_formats:
            alvos.append(("txt", out_dir / "report.txt"))

    for tipo, caminho in alvos:
        caminho.parent.mkdir(parents=True, exist_ok=True)
        if tipo == "json":
            render_json(bundle, caminho)
        elif tipo == "html":
            render_html(bundle, caminho)
        elif tipo == "txt":
            with caminho.open("w", encoding="utf-8") as fh:
                render_console(bundle, stream=fh, color=False, verbose=True)
        if not args.quiet:
            print(f"  [SAIDA        ] {caminho}", file=sys.stderr)

    if args.fail_on:
        piso = Severity(args.fail_on).rank
        if any(f.severity.rank >= piso for f in bundle.findings):
            return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
