"""Camada de COLETA: dois coletores, um mesmo ``Snapshot``.

``DatasetCollector`` le os artefatos de um dataset em disco e
``LiveLinuxCollector`` le o estado real da maquina. Trocar o coletor nao
altera nenhuma camada posterior do pipeline.
"""

from .base import Collector
from .dataset import DatasetCollector
from .live_linux import LiveLinuxCollector

__all__ = ["Collector", "DatasetCollector", "LiveLinuxCollector"]
