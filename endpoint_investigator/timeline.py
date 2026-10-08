"""Linha do tempo unificada.

Junta logs, inicio de processos e mtime de recursos privilegiados em uma unica
sequencia ordenada (Aula 3: reconstrucao temporal).
"""


from typing import List

from .model import Snapshot, TimelineEvent
from .normalize import basename, parse_dt, to_naive


def build_timeline(snap: Snapshot, limit: int = 120) -> List[TimelineEvent]:
    events: List[TimelineEvent] = []

    for l in snap.logs:
        prog = f"{l.program}[{l.pid}]" if l.pid else (l.program or "log")
        events.append(TimelineEvent(
            ts=to_naive(l.ts), label=prog, detail=l.message, kind="log", source=l.source,
        ))

    for p in snap.processes:
        ts = to_naive(parse_dt(p.started_at or p.timestamp))
        if not ts:
            continue
        events.append(TimelineEvent(
            ts=ts, label=f"pid {p.pid} ({p.user})",
            detail=f"processo observado: {p.short_cmd}",
            kind="process", source=p.source,
        ))

    # Apenas recursos ligados a servicos privilegiados entram na linha do tempo:
    # o objetivo e contexto de investigacao, nao um inventario de mtimes.
    privileged_paths = set()
    for s in snap.services:
        if s.is_privileged:
            privileged_paths.update(s.resources)
    for f in snap.files:
        if f.path not in privileged_paths:
            continue
        ts = to_naive(parse_dt(f.mtime))
        if not ts:
            continue
        events.append(TimelineEvent(
            ts=ts, label=f"mtime {basename(f.path)}",
            detail=f"'{f.path}' modificado (modo {f.mode}, {f.owner}:{f.group})",
            kind="file", source=f.source,
        ))

    events.sort(key=lambda e: (e.ts is None, e.ts))
    return events[:limit]
