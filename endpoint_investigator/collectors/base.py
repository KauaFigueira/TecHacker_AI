"""Contrato comum dos coletores."""


from abc import ABC, abstractmethod

from ..model import Snapshot


class Collector(ABC):
    """Produz um ``Snapshot`` bruto (ainda nao normalizado)."""

    name: str = "abstract"

    @abstractmethod
    def collect(self) -> Snapshot:  # pragma: no cover - interface
        ...

    def describe(self) -> str:
        return self.name
