"""Modelo de dados canonico.

Todas as camadas trocam informacao por estas estruturas. Elas tornam a
proveniencia de cada dado rastreavel (``SourceRef``) e separam, em todo achado,
evidencia / interpretacao / hipotese / evidencia ausente (``Finding``).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = "ei-evidence-bundle/1.0"


# --------------------------------------------------------------------------- #
# Proveniencia
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class SourceRef:
    """De onde um dado observado veio: coletor, artefato e posicao."""

    collector: str
    artifact: str
    locator: str = ""

    def as_text(self) -> str:
        loc = f":{self.locator}" if self.locator else ""
        return f"{self.collector}::{self.artifact}{loc}"

    def to_dict(self) -> Dict[str, str]:
        return {"collector": self.collector, "artifact": self.artifact,
                "locator": self.locator}


# --------------------------------------------------------------------------- #
# Entidades observadas: as tres dimensoes obrigatorias + logs
# --------------------------------------------------------------------------- #
@dataclass
class ProcessRecord:
    pid: int
    ppid: int
    user: str
    cmdline: str
    state: str = ""
    uid: Optional[int] = None
    gid: Optional[int] = None
    exe: Optional[str] = None
    argv: List[str] = field(default_factory=list)
    cwd: Optional[str] = None
    started_at: Optional[str] = None
    timestamp: Optional[str] = None
    source: Optional[SourceRef] = None

    # Derivados na normalizacao
    interpreter: Optional[str] = None       # bash / python3 / perl ...
    script: Optional[str] = None            # caminho do script executado
    network_targets: List[str] = field(default_factory=list)
    is_privileged: bool = False
    exe_deleted: bool = False

    @property
    def key(self) -> str:
        return f"process:{self.pid}"

    @property
    def short_cmd(self) -> str:
        return self.cmdline if len(self.cmdline) <= 72 else self.cmdline[:69] + "..."


@dataclass
class FileRecord:
    path: str
    ftype: str = "file"
    owner: str = "?"
    group: str = "?"
    mode: str = "0000"
    mtime: Optional[str] = None
    size: Optional[int] = None
    link_target: Optional[str] = None
    source: Optional[SourceRef] = None

    # Derivados na normalizacao
    mode_int: int = 0
    world_writable: bool = False
    group_writable: bool = False
    world_readable: bool = False
    setuid: bool = False
    setgid: bool = False
    sticky: bool = False
    owner_privileged: bool = False

    @property
    def key(self) -> str:
        return f"file:{self.path}"

    @property
    def parent(self) -> str:
        if self.path in ("/", ""):
            return "/"
        return self.path.rsplit("/", 1)[0] or "/"


@dataclass
class ServiceRecord:
    unit: str
    active: str = "unknown"
    user: str = "root"
    exec_start: str = ""
    fragment_path: Optional[str] = None
    source: Optional[SourceRef] = None

    # Derivados na normalizacao
    exec_argv: List[str] = field(default_factory=list)
    exec_path: Optional[str] = None     # binario efetivamente invocado
    exec_script: Optional[str] = None   # script passado a um interpretador
    is_privileged: bool = False

    @property
    def key(self) -> str:
        return f"service:{self.unit}"

    @property
    def resources(self) -> List[str]:
        """Caminhos de filesystem de que o servico depende para executar."""
        out = []
        for c in (self.exec_path, self.exec_script, self.fragment_path):
            if c and c.startswith("/") and c not in out:
                out.append(c)
        return out


@dataclass
class LogRecord:
    ts: Optional[datetime]
    message: str
    raw: str
    host: str = ""
    program: str = ""
    pid: Optional[int] = None
    source: Optional[SourceRef] = None

    @property
    def ts_text(self) -> str:
        return self.ts.isoformat() if self.ts else "?"


@dataclass
class UserRecord:
    """Identidade sob a qual processos e servicos executam.

    Derivada dos proprios processos e servicos: o enunciado pede a correlacao
    "processo + PPID + usuario", e esse usuario e o campo observado no snapshot,
    nao um inventario de contas do sistema.
    """

    name: str
    uid: Optional[int] = None
    source: Optional[SourceRef] = None

    @property
    def is_privileged(self) -> bool:
        return self.uid == 0 or self.name == "root"


# --------------------------------------------------------------------------- #
# Snapshot normalizado
# --------------------------------------------------------------------------- #
@dataclass
class Snapshot:
    """Estado do endpoint apos COLETA + NORMALIZACAO."""

    host: str = "unknown"
    collected_at: str = ""
    collector: str = ""
    origin: str = ""
    processes: List[ProcessRecord] = field(default_factory=list)
    files: List[FileRecord] = field(default_factory=list)
    services: List[ServiceRecord] = field(default_factory=list)
    logs: List[LogRecord] = field(default_factory=list)
    users: List[UserRecord] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    # Indices construidos pela normalizacao
    by_pid: Dict[int, ProcessRecord] = field(default_factory=dict)
    by_path: Dict[str, FileRecord] = field(default_factory=dict)
    by_unit: Dict[str, ServiceRecord] = field(default_factory=dict)
    by_user: Dict[str, UserRecord] = field(default_factory=dict)

    def counters(self) -> Dict[str, int]:
        return {"processes": len(self.processes), "files": len(self.files),
                "services": len(self.services), "logs": len(self.logs),
                "users": len(self.users)}

    def children_of(self, pid: int) -> List[ProcessRecord]:
        return [p for p in self.processes if p.ppid == pid and p.pid != pid]

    def ancestry(self, proc: ProcessRecord, limit: int = 12) -> List[ProcessRecord]:
        """Cadeia de ancestrais, do pai direto ate a raiz."""
        chain, seen = [], {proc.pid}
        cur = self.by_pid.get(proc.ppid)
        while cur and cur.pid not in seen and len(chain) < limit:
            chain.append(cur)
            seen.add(cur.pid)
            cur = self.by_pid.get(cur.ppid)
        return chain

    def file_for(self, path: Optional[str], depth: int = 4) -> Optional[FileRecord]:
        """Recupera o arquivo de ``path``, seguindo links simbolicos coletados.

        O modo de um link simbolico nao e aplicado pelo kernel (e sempre 0777);
        quem manda e o alvo. Toda analise de permissao usa este metodo.
        """
        seen = set()
        while path and depth > 0:
            rec = self.by_path.get(path)
            if rec is None or rec.ftype != "link" or not rec.link_target:
                return rec
            if rec.link_target in seen:
                return rec
            seen.add(rec.link_target)
            path, depth = rec.link_target, depth - 1
        return None


# --------------------------------------------------------------------------- #
# Evidencia / interpretacao / hipotese
# --------------------------------------------------------------------------- #
class Severity(str, Enum):
    INFO = "info"
    LOW = "baixa"
    MEDIUM = "media"
    HIGH = "alta"

    @property
    def weight(self) -> int:
        return {"info": 5, "baixa": 25, "media": 50, "alta": 80}[self.value]

    @property
    def rank(self) -> int:
        return ["info", "baixa", "media", "alta"].index(self.value)


class Confidence(str, Enum):
    LOW = "baixa"
    MEDIUM = "media"
    HIGH = "alta"

    @property
    def rank(self) -> int:
        return ["baixa", "media", "alta"].index(self.value)


@dataclass
class Evidence:
    """Um fato efetivamente observado, com proveniencia.

    ``observed`` e a frase objetiva do que foi visto; ``raw`` guarda o dado
    literal, para que o analista possa reconferir na fonte.
    """

    kind: str                       # process | file | service | log | user
    observed: str
    source: SourceRef
    raw: str = ""
    entity: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "entity": self.entity, "observed": self.observed,
                "raw": self.raw, "source": self.source.to_dict()}


@dataclass
class Finding:
    """Resultado de uma regra de correlacao.

    Separa explicitamente os quatro elementos exigidos pelo enunciado:
    evidencia, interpretacao, hipotese e evidencia ausente.
    """

    rule_id: str
    title: str
    severity: Severity
    category: str
    correlation: str                       # quais dimensoes foram cruzadas
    evidence: List[Evidence] = field(default_factory=list)
    interpretation: str = ""
    hypothesis: str = ""
    missing_evidence: List[str] = field(default_factory=list)
    false_positives: List[str] = field(default_factory=list)
    entities: List[str] = field(default_factory=list)
    attack_path: List[str] = field(default_factory=list)

    # A ferramenta nunca afirma exploracao: o campo e constante por desenho.
    exploracao_comprovada: bool = False

    # Calculados pelo scoring
    confidence: Confidence = Confidence.LOW
    confidence_reason: str = ""
    risk_score: int = 0
    fingerprint: str = ""

    def distinct_sources(self) -> List[str]:
        seen = []
        for e in self.evidence:
            tag = f"{e.source.collector}::{e.source.artifact}"
            if tag not in seen:
                seen.append(tag)
        return seen

    def evidence_kinds(self) -> List[str]:
        seen = []
        for e in self.evidence:
            if e.kind not in seen:
                seen.append(e.kind)
        return seen

    def compute_fingerprint(self) -> str:
        payload = self.rule_id + "|" + "|".join(sorted(self.entities))
        self.fingerprint = hashlib.sha256(payload.encode()).hexdigest()[:12]
        return self.fingerprint

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id, "fingerprint": self.fingerprint,
            "title": self.title, "severity": self.severity.value,
            "risk_score": self.risk_score,
            "exploracao_comprovada": self.exploracao_comprovada,
            "confidence": self.confidence.value,
            "confidence_reason": self.confidence_reason,
            "category": self.category, "correlation": self.correlation,
            "entities": self.entities, "attack_path": self.attack_path,
            "evidence": [e.to_dict() for e in self.evidence],
            "interpretation": self.interpretation, "hypothesis": self.hypothesis,
            "missing_evidence": self.missing_evidence,
            "false_positives": self.false_positives,
        }


@dataclass
class TimelineEvent:
    ts: Optional[datetime]
    label: str
    detail: str
    kind: str
    source: Optional[SourceRef] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"ts": self.ts.isoformat() if self.ts else None, "label": self.label,
                "detail": self.detail, "kind": self.kind,
                "source": self.source.to_dict() if self.source else None}


@dataclass
class EvidenceBundle:
    """Saida estruturada do pipeline: o resultado da investigacao."""

    schema_version: str = SCHEMA_VERSION
    tool: str = "endpoint-investigator"
    tool_version: str = "1.0.0"
    host: str = "unknown"
    generated_at: str = ""
    collector: str = ""
    origin: str = ""
    inventory: Dict[str, int] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    timeline: List[TimelineEvent] = field(default_factory=list)
    graph: Dict[str, Any] = field(default_factory=dict)
    coverage: Dict[str, Any] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def summary(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        counts["total"] = len(self.findings)
        return counts

    def max_risk(self) -> int:
        return max((f.risk_score for f in self.findings), default=0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version, "tool": self.tool,
            "tool_version": self.tool_version, "host": self.host,
            "generated_at": self.generated_at, "collector": self.collector,
            "origin": self.origin, "inventory": self.inventory,
            "summary": self.summary(), "max_risk_score": self.max_risk(),
            "findings": [f.to_dict() for f in self.findings],
            "timeline": [t.to_dict() for t in self.timeline],
            "graph": self.graph, "coverage": self.coverage,
            "limitations": self.limitations, "notes": self.notes,
        }
