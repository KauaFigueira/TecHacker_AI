"""Orquestrador do pipeline.

COLETA -> NORMALIZACAO -> CORRELACAO -> EVIDENCIAS -> HIPOTESES -> RESULTADO.
``investigate`` executa as cinco primeiras etapas e devolve um ``EvidenceBundle``.
A camada de IA e aplicada depois, sobre esse bundle.
"""


import platform
from datetime import datetime
from typing import Callable, Dict, Optional

from . import __version__
from .collectors.base import Collector
from .correlation.engine import CorrelationEngine
from .graph import EntityGraph
from .model import EvidenceBundle, Snapshot
from .normalize import normalize_snapshot
from .timeline import build_timeline

# Limitacoes declaradas de escopo (exigencia do enunciado).
SCOPE_LIMITATIONS = [
    "Analise baseada em um snapshot pontual: comportamento anterior ou posterior "
    "a coleta nao e observado, e PIDs podem ser reaproveitados.",
    "A ferramenta nao inspeciona o conteudo dos arquivos nem executa analise de "
    "binarios; decide a partir de metadados e das relacoes entre eles.",
    "Escopo adotado: processos, permissoes, servicos e logs do sistema. Conexoes "
    "de rede, contas do sistema e arquivos abertos nao sao coletados - uma URL em "
    "linha de comando nao prova que houve conexao.",
    "ACLs POSIX estendidas, atributos, capabilities e politicas MAC "
    "(SELinux/AppArmor) nao sao lidos: um recurso pode estar mais protegido do que "
    "o modo octal sugere.",
    "Sem privilegio de root, cmdline e executavel de processos de outros usuarios "
    "ficam incompletos; a coleta registra isso nas notas.",
    "Namespaces de containers nao sao percorridos.",
    "A ferramenta nao conclui a existencia de comprometimento: todo achado carrega "
    "'exploracao_comprovada: false'.",
]


def investigate(
    collector: Collector,
    engine: Optional[CorrelationEngine] = None,
    options: Optional[Dict[str, object]] = None,
    progress: Optional[Callable[[str, str], None]] = None,
) -> tuple[EvidenceBundle, Snapshot, EntityGraph]:
    """Executa o pipeline deterministico completo."""
    say = progress or (lambda stage, msg: None)
    engine = engine or CorrelationEngine()

    say("COLETA", f"coletando via {collector.describe()}")
    snap = collector.collect()

    say("NORMALIZACAO", "padronizando entidades e construindo indices")
    snap = normalize_snapshot(snap)

    say("CORRELACAO", "montando grafo de entidades e relacoes")
    graph = EntityGraph(snap)

    say("EVIDENCIAS", f"aplicando {len(engine.rules)} regras de correlacao")
    findings = engine.run(snap, graph, options)

    say("HIPOTESES", "consolidando linha do tempo e bundle estruturado")
    timeline = build_timeline(snap)

    bundle = EvidenceBundle(
        tool_version=__version__,
        host=snap.host,
        generated_at=datetime.now().astimezone().isoformat(timespec="seconds"),
        collector=snap.collector,
        origin=snap.origin,
        inventory=snap.counters(),
        findings=findings,
        timeline=timeline,
        graph=graph.to_dict(),
        coverage=_coverage(snap, engine, graph),
        limitations=list(SCOPE_LIMITATIONS),
        notes=list(snap.notes),
    )
    return bundle, snap, graph


def _coverage(snap: Snapshot, engine: CorrelationEngine, graph: EntityGraph) -> Dict[str, object]:
    dims = {
        "processos": len(snap.processes),
        "permissoes": len(snap.files),
        "servicos": len(snap.services),
        "logs": len(snap.logs),
        "identidades": len(snap.users),
    }
    cov = engine.coverage()
    cov.update({
        "dimensoes_coletadas": dims,
        "dimensoes_ausentes": [k for k, v in dims.items() if v == 0],
        "grafo": graph.stats(),
        "plataforma": platform.platform(),
    })
    return cov
