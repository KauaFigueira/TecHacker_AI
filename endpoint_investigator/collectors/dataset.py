"""Coletor de datasets em disco.

Le os quatro artefatos do gerador da disciplina:

    processes.csv    timestamp,pid,ppid,user,stat,cmd
    permissions.csv  path,type,owner,group,mode,mtime
    services.txt     tabela UNIT / ACTIVE / USER / EXECSTART
    journal.log      linhas no formato syslog

``metadata.json`` e ``README.txt`` ficam no dataset mas **nao sao lidos** pelo
motor: os achados vem apenas dos artefatos observacionais, nunca das respostas
didaticas do gerador.

Cada registro guarda um ``SourceRef`` com o arquivo e a linha de origem, para
que qualquer evidencia do relatorio possa ser reconferida na fonte.
"""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import List

from ..model import (
    FileRecord, LogRecord, ProcessRecord, ServiceRecord, Snapshot, SourceRef,
)
from ..normalize import parse_log_line
from .base import Collector


class DatasetCollector(Collector):
    name = "dataset"

    def __init__(self, path: str | Path):
        self.path = Path(path)
        if not self.path.exists():
            raise FileNotFoundError(f"Dataset nao encontrado: {self.path}")
        if not self.path.is_dir():
            raise NotADirectoryError(f"Esperado um diretorio de dataset: {self.path}")

    def collect(self) -> Snapshot:
        snap = Snapshot(
            host=self._host(),
            collected_at=datetime.now().astimezone().isoformat(timespec="seconds"),
            collector=self.name,
            origin=str(self.path.resolve()),
        )
        snap.processes = self._processes()
        snap.files = self._permissions()
        snap.services = self._services()
        snap.logs = self._logs()
        faltando = [n for n in ("processes.csv", "permissions.csv", "services.txt",
                                "journal.log") if not (self.path / n).exists()]
        if faltando:
            snap.notes.append(
                "Artefatos ausentes no dataset (a analise degrada de forma controlada "
                "e as regras que dependem deles sao puladas): " + ", ".join(faltando))
        return snap

    # ------------------------------------------------------------------ #
    def _ref(self, artefato: str, linha: int) -> SourceRef:
        return SourceRef(self.name, artefato, f"linha {linha}")

    def _host(self) -> str:
        f = self.path / "journal.log"
        if f.exists():
            for linha in f.read_text(encoding="utf-8", errors="replace").splitlines():
                p = parse_log_line(linha)
                if p and p["host"]:
                    return p["host"]
        return self.path.name or "dataset"

    def _processes(self) -> List[ProcessRecord]:
        f = self.path / "processes.csv"
        out: List[ProcessRecord] = []
        if not f.exists():
            return out
        with f.open(encoding="utf-8", newline="") as fh:
            for i, row in enumerate(csv.DictReader(fh), start=2):
                try:
                    pid, ppid = int(row.get("pid") or 0), int(row.get("ppid") or 0)
                except ValueError:
                    continue
                ts = (row.get("timestamp") or "").strip() or None
                out.append(ProcessRecord(
                    pid=pid, ppid=ppid, user=(row.get("user") or "?").strip(),
                    cmdline=(row.get("cmd") or "").strip(),
                    state=(row.get("stat") or "").strip(),
                    timestamp=ts, started_at=ts,
                    source=self._ref("processes.csv", i)))
        return out

    def _permissions(self) -> List[FileRecord]:
        f = self.path / "permissions.csv"
        out: List[FileRecord] = []
        if not f.exists():
            return out
        with f.open(encoding="utf-8", newline="") as fh:
            for i, row in enumerate(csv.DictReader(fh), start=2):
                path = (row.get("path") or "").strip()
                if not path:
                    continue
                out.append(FileRecord(
                    path=path, ftype=(row.get("type") or "file").strip(),
                    owner=(row.get("owner") or "?").strip(),
                    group=(row.get("group") or "?").strip(),
                    mode=(row.get("mode") or "0000").strip(),
                    mtime=(row.get("mtime") or "").strip() or None,
                    source=self._ref("permissions.csv", i)))
        return out

    def _services(self) -> List[ServiceRecord]:
        """Le a tabela de servicos.

        O gerador escreve o cabecalho com larguras que nao coincidem com as das
        linhas de dados, entao a separacao e por espacos em branco
        (UNIT ACTIVE USER EXECSTART...), com as posicoes do cabecalho apenas
        como alternativa.
        """
        f = self.path / "services.txt"
        out: List[ServiceRecord] = []
        if not f.exists():
            return out
        linhas = f.read_text(encoding="utf-8", errors="replace").splitlines()
        if not linhas:
            return out
        cols = None
        cab = linhas[0]
        if all(k in cab for k in ("ACTIVE", "USER", "EXECSTART")):
            cols = (cab.index("ACTIVE"), cab.index("USER"), cab.index("EXECSTART"))
        for i, linha in enumerate(linhas[1:], start=2):
            if not linha.strip():
                continue
            partes = linha.split(None, 3)
            if len(partes) >= 3:
                unit, active, user = partes[0], partes[1], partes[2]
                execstart = partes[3] if len(partes) > 3 else ""
            elif cols:
                unit = linha[:cols[0]].strip()
                active = linha[cols[0]:cols[1]].strip()
                user = linha[cols[1]:cols[2]].strip()
                execstart = linha[cols[2]:].strip()
            else:
                continue
            if unit:
                out.append(ServiceRecord(unit=unit, active=active, user=user or "root",
                                         exec_start=execstart,
                                         source=self._ref("services.txt", i)))
        return out

    def _logs(self) -> List[LogRecord]:
        f = self.path / "journal.log"
        out: List[LogRecord] = []
        if not f.exists():
            return out
        for i, linha in enumerate(f.read_text(encoding="utf-8",
                                              errors="replace").splitlines(), start=1):
            p = parse_log_line(linha)
            if p:
                out.append(LogRecord(ts=p["ts"], message=p["message"], raw=p["raw"],
                                     host=p["host"], program=p["program"], pid=p["pid"],
                                     source=self._ref("journal.log", i)))
        return out
