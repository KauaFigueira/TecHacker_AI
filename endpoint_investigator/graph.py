"""Grafo de entidades - nucleo da CORRELACAO.

Processos, permissoes e servicos deixam de ser listas independentes e viram
vertices de um grafo dirigido (pai-de, executa-como, executa, gerencia,
contido-em, refere-pid, pertence-a). As regras consultam o grafo, nao os
arquivos de origem.
"""


import os
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple

from .model import Snapshot
from .normalize import basename

# Relacoes usadas pelas regras.
REL_PARENT = "pai-de"
REL_RUNS_AS = "executa-como"
REL_EXECUTES = "executa"
REL_USES_SCRIPT = "usa-script"
REL_MANAGES = "gerencia"
REL_CONTAINED = "contido-em"
REL_LOG_PID = "refere-pid"
REL_LOG_UNIT = "emitido-por"


class Edge:
    __slots__ = ("src", "rel", "dst", "why")

    def __init__(self, src: str, rel: str, dst: str, why: str = ""):
        self.src, self.rel, self.dst, self.why = src, rel, dst, why

    def to_dict(self) -> Dict[str, str]:
        return {"src": self.src, "rel": self.rel, "dst": self.dst, "why": self.why}

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{self.src} -{self.rel}-> {self.dst}>"


class EntityGraph:
    def __init__(self, snap: Snapshot):
        self.snap = snap
        self.nodes: Dict[str, Dict[str, str]] = {}
        self.edges: List[Edge] = []
        self._out: Dict[str, List[Edge]] = defaultdict(list)
        self._in: Dict[str, List[Edge]] = defaultdict(list)
        self._build()

    # ------------------------------------------------------------------ #
    def add_node(self, key: str, kind: str, label: str) -> None:
        if key not in self.nodes:
            self.nodes[key] = {"key": key, "kind": kind, "label": label}

    def add_edge(self, src: str, rel: str, dst: str, why: str = "") -> None:
        if src not in self.nodes or dst not in self.nodes:
            return
        e = Edge(src, rel, dst, why)
        self.edges.append(e)
        self._out[src].append(e)
        self._in[dst].append(e)

    # ------------------------------------------------------------------ #
    def _build(self) -> None:
        snap = self.snap

        for u in snap.users:
            self.add_node(f"user:{u.name}", "user", u.name)
        for p in snap.processes:
            self.add_node(p.key, "process", f"pid {p.pid} {basename(p.exe or p.argv[0] if p.argv else '')}".strip())
        for f in snap.files:
            self.add_node(f.key, "file", f.path)
        for s in snap.services:
            self.add_node(s.key, "service", s.unit)

        # processo -> usuario, pai
        for p in snap.processes:
            if f"user:{p.user}" in self.nodes:
                self.add_edge(p.key, REL_RUNS_AS, f"user:{p.user}", f"campo user={p.user}")
            parent = snap.by_pid.get(p.ppid)
            if parent and parent.pid != p.pid:
                self.add_edge(parent.key, REL_PARENT, p.key, f"ppid={p.ppid}")

        # processo -> arquivo (binario e script)
        for p in snap.processes:
            for path, rel in ((p.exe, REL_EXECUTES), (p.script, REL_USES_SCRIPT)):
                if not path:
                    continue
                node = self._file_node(path)
                if node:
                    self.add_edge(p.key, rel, node, f"cmdline: {p.short_cmd}")

        # servico -> usuario / arquivo / processo
        for s in snap.services:
            if f"user:{s.user}" in self.nodes:
                self.add_edge(s.key, REL_RUNS_AS, f"user:{s.user}", f"User={s.user}")
            else:
                self.add_node(f"user:{s.user}", "user", s.user)
                self.add_edge(s.key, REL_RUNS_AS, f"user:{s.user}", f"User={s.user}")
            for path, rel in ((s.exec_path, REL_EXECUTES), (s.exec_script, REL_USES_SCRIPT),
                              (s.fragment_path, REL_CONTAINED)):
                if not path:
                    continue
                node = self._file_node(path)
                if node:
                    self.add_edge(s.key, rel, node, f"ExecStart: {s.exec_start}")
            for proc in self.processes_of_service(s.unit):
                self.add_edge(s.key, REL_MANAGES, proc.key,
                              f"ExecStart casa com cmdline do pid {proc.pid}")

        # arquivo -> diretorio-pai
        for f in snap.files:
            parent = self._file_node(f.parent)
            if parent and parent != f.key:
                self.add_edge(f.key, REL_CONTAINED, parent, "diretorio-pai")

        # logs
        for i, log in enumerate(snap.logs):
            key = f"log:{i}"
            self.add_node(key, "log", log.message[:60])
            if log.pid is not None and log.pid in snap.by_pid:
                self.add_edge(key, REL_LOG_PID, snap.by_pid[log.pid].key, f"pid={log.pid}")
            unit = self._unit_for_program(log.program)
            if unit:
                self.add_edge(key, REL_LOG_UNIT, f"service:{unit}", f"programa={log.program}")

    # ------------------------------------------------------------------ #
    def _file_node(self, path: Optional[str]) -> Optional[str]:
        if not path:
            return None
        norm = os.path.normpath(path)
        for candidate in (f"file:{path}", f"file:{norm}"):
            if candidate in self.nodes:
                return candidate
        return None

    def _unit_for_program(self, program: str) -> Optional[str]:
        """Liga o nome do programa de um log a uma unidade systemd."""
        if not program:
            return None
        prog = program.split("@")[0].strip()
        for unit in self.snap.by_unit:
            stem = unit.rsplit(".", 1)[0]
            if prog == stem or prog == stem.replace("-", "") or stem.startswith(prog):
                return unit
        return None

    # ------------------------------------------------------------------ #
    # Consultas
    # ------------------------------------------------------------------ #
    def out_edges(self, key: str, rel: Optional[str] = None) -> List[Edge]:
        edges = self._out.get(key, [])
        return [e for e in edges if rel is None or e.rel == rel]

    def neighbors(self, key: str, rel: Optional[str] = None) -> List[str]:
        return [e.dst for e in self.out_edges(key, rel)]

    def paths_between(self, src: str, dst: str, max_depth: int = 4) -> List[List[Edge]]:
        """Todos os caminhos dirigidos de ``src`` a ``dst`` ate ``max_depth`` arestas."""
        results: List[List[Edge]] = []
        queue: deque[Tuple[str, List[Edge], Set[str]]] = deque([(src, [], {src})])
        while queue:
            node, path, seen = queue.popleft()
            if len(path) >= max_depth:
                continue
            for e in self.out_edges(node):
                if e.dst in seen:
                    continue
                new_path = path + [e]
                if e.dst == dst:
                    results.append(new_path)
                    continue
                queue.append((e.dst, new_path, seen | {e.dst}))
        return results

    def processes_of_service(self, unit: str, loose: bool = False) -> List:
        """Processos cuja linha de comando corresponde ao ExecStart da unidade.

        A correspondencia e conservadora de proposito. Um servico que executa
        ``/bin/bash /opt/x.sh`` nao deve capturar todo processo ``/bin/bash`` do
        sistema: quando a unidade invoca um interpretador com script, so o
        script identifica o processo.
        """
        svc = self.snap.by_unit.get(unit)
        if not svc or not svc.exec_argv:
            return []
        matches = []
        svc_exe = svc.exec_path or ""
        svc_script = svc.exec_script or ""
        exec_start = (svc.exec_start or "").strip()
        for p in self.snap.processes:
            cmd = (p.cmdline or "").strip()
            if not cmd:
                continue
            if exec_start and cmd == exec_start:
                matches.append(p)
                continue
            if svc_script:
                # Unidade com interpretador + script: apenas o script identifica.
                if svc_script in cmd:
                    matches.append(p)
                continue
            if not svc_exe:
                continue
            # Script com shebang: o kernel pode registrar o interpretador na
            # frente (ex.: "python3 /usr/bin/networkd-dispatcher --flag" para uma
            # unidade cujo ExecStart e "/usr/bin/networkd-dispatcher --flag").
            # A comparacao e por token exato, nao por substring.
            if svc_exe in p.argv:
                matches.append(p)
                continue
            argv0 = p.argv[0] if p.argv else ""
            # Mesmo binario, argumentos possivelmente expandidos pelo systemd
            # ($OPTIONS, $ARGS): o executavel e o que identifica o processo.
            if p.exe == svc_exe or argv0 == svc_exe:
                matches.append(p)

        if not matches and loose:
            # Correspondencia fraca por nome: unidades cujo ExecStart aponta para
            # um wrapper (apache2.service -> apachectl -> apache2) nao casam de
            # forma estrita. Usada apenas para EVITAR falso positivo, nunca para
            # sustentar um achado de risco.
            stem = unit.rsplit(".", 1)[0]
            for p in self.snap.processes:
                name = basename(p.exe or (p.argv[0] if p.argv else ""))
                # Exato, ou a unidade nomeia um wrapper do binario
                # (apache2.service <-> apache2). Nunca por prefixo do processo,
                # que pareia snapd.service com snapd-desktop-integration.
                if name and (name == stem or stem.startswith(name + "-") or stem == name):
                    matches.append(p)

        # Remove duplicatas preservando a ordem.
        seen, out = set(), []
        for p in matches:
            if p.pid not in seen:
                seen.add(p.pid)
                out.append(p)
        return out

    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, int]:
        by_kind: Dict[str, int] = defaultdict(int)
        for n in self.nodes.values():
            by_kind[n["kind"]] += 1
        by_rel: Dict[str, int] = defaultdict(int)
        for e in self.edges:
            by_rel[e.rel] += 1
        return {"nodes": len(self.nodes), "edges": len(self.edges),
                **{f"node_{k}": v for k, v in sorted(by_kind.items())},
                **{f"edge_{k}": v for k, v in sorted(by_rel.items())}}

    def to_dict(self, max_edges: int = 400) -> Dict[str, object]:
        return {
            "stats": self.stats(),
            "nodes": list(self.nodes.values()),
            "edges": [e.to_dict() for e in self.edges[:max_edges]],
            "edges_truncated": max(0, len(self.edges) - max_edges),
        }
