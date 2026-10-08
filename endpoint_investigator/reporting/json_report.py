"""Bundle estruturado em JSON.

E o artefato central: representa as evidencias produzidas antes de qualquer
interpretacao por modelo, e e a unica entrada aceita pela camada de IA.
"""


import json
from pathlib import Path
from typing import Optional

from ..model import EvidenceBundle


def render_json(bundle: EvidenceBundle, path: Optional[str | Path] = None,
                indent: int = 2) -> str:
    text = json.dumps(bundle.to_dict(), indent=indent, ensure_ascii=False)
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(text + "\n", encoding="utf-8")
    return text
