"""Confianca e risco deterministicos.

Confianca e funcao da corroboracao, nao de opiniao: 1 dimensao -> baixa,
2 -> media, >=3 -> alta; fonte unica rebaixa. O risco combina a severidade da
regra com esse fator.
"""


from .model import Confidence, Finding

CONFIDENCE_FACTOR = {Confidence.LOW: 0.65, Confidence.MEDIUM: 0.85, Confidence.HIGH: 1.0}


def compute_confidence(finding: Finding) -> tuple[Confidence, str]:
    kinds = finding.evidence_kinds()
    sources = finding.distinct_sources()
    n_kinds, n_sources = len(kinds), len(sources)

    if n_kinds >= 3:
        level = Confidence.HIGH
    elif n_kinds == 2:
        level = Confidence.MEDIUM
    else:
        level = Confidence.LOW

    # Uma unica fonte de dados derruba a confianca mesmo com varias dimensoes:
    # sem corroboracao independente o achado continua fragil.
    if n_sources <= 1 and level == Confidence.HIGH:
        level = Confidence.MEDIUM

    reason = (
        f"{len(finding.evidence)} evidencia(s) em {n_kinds} dimensao(oes) "
        f"({', '.join(kinds) or 'nenhuma'}) vindas de {n_sources} fonte(s) "
        f"independente(s): {', '.join(sources) or 'nenhuma'}."
    )
    return level, reason


def score_finding(finding: Finding) -> Finding:
    level, reason = compute_confidence(finding)
    finding.confidence = level
    finding.confidence_reason = reason

    base = finding.severity.weight
    score = base * CONFIDENCE_FACTOR[level]

    # Um caminho de ataque explicito (cadeia de privilegio reconstruida)
    # acrescenta peso porque demonstra viabilidade, nao apenas configuracao.
    if len(finding.attack_path) >= 3:
        score += 6
    elif len(finding.attack_path) == 2:
        score += 3

    # Achados que ja declaram o que falta para confirmar sao mais acionaveis,
    # mas isso nao aumenta o risco - apenas evita inflar o que nao foi provado.
    if not finding.missing_evidence and finding.severity.rank >= 3:
        score -= 2

    finding.risk_score = max(0, min(100, int(round(score))))
    return finding
