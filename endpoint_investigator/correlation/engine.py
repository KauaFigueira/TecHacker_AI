"""Motor de correlacao.

Executa as regras sobre (Snapshot, EntityGraph), aplica proveniencia e calcula
confianca e risco. Deterministico: o mesmo snapshot produz sempre o mesmo
conjunto de evidencias. Nenhum modelo de linguagem participa desta etapa.
"""


from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..graph import EntityGraph
from ..model import Finding, Snapshot
from ..scoring import score_finding


@dataclass
class RuleContext:
    """Tudo que uma regra pode consultar."""

    snap: Snapshot
    graph: EntityGraph
    options: Dict[str, object] = field(default_factory=dict)

class CorrelationEngine:
    def __init__(self, rules: Optional[List] = None):
        from .rules import ALL_RULES
        self.rules = list(rules if rules is not None else ALL_RULES)
        self.errors: List[str] = []
        self.executed: List[str] = []
        self.skipped: List[Dict[str, str]] = []

    def run(self, snap: Snapshot, graph: EntityGraph,
            options: Optional[Dict[str, object]] = None) -> List[Finding]:
        ctx = RuleContext(snap=snap, graph=graph, options=options or {})
        findings: List[Finding] = []
        for rule in self.rules:
            reason = rule.unavailable_reason(ctx)
            if reason:
                self.skipped.append({"rule_id": rule.id, "title": rule.title, "reason": reason})
                continue
            try:
                produced = list(rule.apply(ctx) or [])
            except Exception as exc:  # regra nunca derruba a execucao inteira
                self.errors.append(f"{rule.id} falhou: {type(exc).__name__}: {exc}")
                continue
            self.executed.append(rule.id)
            for f in produced:
                score_finding(f)
                f.compute_fingerprint()
                findings.append(f)

        findings = _dedupe(findings)
        findings.sort(key=lambda f: (-f.risk_score, -f.severity.rank, f.rule_id))
        return findings

    def coverage(self) -> Dict[str, object]:
        return {
            "rules_total": len(self.rules),
            "rules_executed": sorted(set(self.executed)),
            "rules_skipped": self.skipped,
            "engine_errors": self.errors,
        }


def _dedupe(findings: List[Finding]) -> List[Finding]:
    seen: Dict[str, Finding] = {}
    for f in findings:
        key = f.fingerprint or f.rule_id
        if key not in seen:
            seen[key] = f
    return list(seen.values())
