"""Coletor do sistema GNU/Linux real (snapshot sob demanda).

Le as tres dimensoes obrigatorias e os logs, direto das fontes do sistema, sem
depender da saida formatada de ``ps``:

    processos    /proc/<pid>/{status,cmdline,exe,cwd,stat}
    servicos     systemctl list-units + systemctl show por unidade
    permissoes   os.lstat, **orientado por contexto**
    logs         journalctl, ou /var/log/syslog como alternativa

A coleta de permissoes e dirigida: sao inspecionados apenas os caminhos que ja
apareceram como recurso de um processo ou servico, seus diretorios-pai, os
vizinhos do mesmo diretorio e um conjunto curto de arquivos sensiveis de
referencia. Nao ha varredura indiscriminada do filesystem.
"""

from __future__ import annotations

import grp
import os
import pwd
import re
import shutil
import socket
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set

from ..model import (
    FileRecord, LogRecord, ProcessRecord, ServiceRecord, Snapshot, SourceRef,
)
from ..normalize import analyze_command, parse_log_line
from .base import Collector

# Arquivos sensiveis usados como linha de base de permissoes.
BASELINE_PATHS = [
    "/etc/shadow", "/etc/gshadow", "/etc/passwd", "/etc/group", "/etc/sudoers",
    "/etc/ssh/sshd_config", "/etc/crontab", "/root", "/etc/ld.so.preload",
]
# Diretorios de sistema com milhares de entradas: inspecionar os vizinhos ali
# dentro seria varredura indiscriminada, nao analise por contexto.
BULK_DIRS = {
    "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/lib", "/lib", "/usr/libexec",
    "/usr/lib64", "/lib64", "/usr/local/bin", "/usr/local/sbin", "/usr/share",
    "/etc", "/var", "/opt", "/", "/home", "/proc", "/sys", "/snap",
}
STATE_MAP = {"R": "R (running)", "S": "S (sleeping)", "D": "D (disk sleep)",
             "Z": "Z (zombie)", "T": "T (stopped)", "I": "I (idle)"}
EXECSTART_RE = re.compile(r"argv\[\]=([^;]*)")


class LiveLinuxCollector(Collector):
    name = "live-linux"

    def __init__(self, max_processes: int = 4000, log_window_min: int = 120,
                 timeout: int = 20, extra_paths: Optional[List[str]] = None):
        self.max_processes = max_processes
        self.log_window_min = log_window_min
        self.timeout = timeout
        self.extra_paths = list(extra_paths or [])
        self._uid_cache: Dict[int, str] = {}
        self._avisos: List[str] = []

    def collect(self) -> Snapshot:
        snap = Snapshot(
            host=socket.gethostname(),
            collected_at=datetime.now().astimezone().isoformat(timespec="seconds"),
            collector=self.name,
            origin=f"{os.uname().sysname} {os.uname().release}",
        )
        snap.processes = self._processes()
        snap.services = self._services()
        snap.logs = self._logs()
        snap.files = self._permissions(snap)   # depende do contexto ja coletado

        if os.geteuid() != 0:
            snap.notes.append(
                f"Coleta sem privilegio de root (uid={os.geteuid()}): cmdline e "
                "executavel de processos de outros usuarios podem estar incompletos.")
        snap.notes.extend(self._avisos)
        return snap

    # ------------------------------------------------------------------ #
    def _ref(self, artefato: str, localizador: str = "") -> SourceRef:
        return SourceRef(self.name, artefato, localizador)

    def _run(self, argv: List[str]) -> Optional[str]:
        if not shutil.which(argv[0]):
            self._avisos.append(f"Comando indisponivel no host: {argv[0]}")
            return None
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=self.timeout)
        except (subprocess.TimeoutExpired, OSError) as exc:
            self._avisos.append(f"Falha ao executar {' '.join(argv)}: {exc}")
            return None
        if r.returncode != 0 and not r.stdout.strip():
            self._avisos.append(f"{argv[0]} retornou {r.returncode}: "
                                f"{r.stderr.strip()[:120]}")
            return None
        return r.stdout

    def _uname(self, uid: int) -> str:
        if uid not in self._uid_cache:
            try:
                self._uid_cache[uid] = pwd.getpwuid(uid).pw_name
            except KeyError:
                self._uid_cache[uid] = str(uid)
        return self._uid_cache[uid]

    # ------------------------------------------------------------------ #
    # Processos via /proc
    # ------------------------------------------------------------------ #
    def _processes(self) -> List[ProcessRecord]:
        out: List[ProcessRecord] = []
        boot = _boot_time()
        for entrada in sorted(os.listdir("/proc"),
                              key=lambda x: int(x) if x.isdigit() else 1 << 30):
            if not entrada.isdigit() or len(out) >= self.max_processes:
                if not entrada.isdigit():
                    continue
                break
            pid = int(entrada)
            base = Path("/proc") / entrada
            try:
                status = (base / "status").read_text(errors="replace")
            except (OSError, PermissionError):
                continue

            campos = {}
            for linha in status.splitlines():
                if ":" in linha:
                    k, v = linha.split(":", 1)
                    campos[k.strip()] = v.strip()
            try:
                uid = int(campos.get("Uid", "0").split()[0])
                gid = int(campos.get("Gid", "0").split()[0])
                ppid = int(campos.get("PPid", "0"))
            except (ValueError, IndexError):
                uid, gid, ppid = -1, -1, 0

            try:
                cmdline = (base / "cmdline").read_bytes().replace(
                    b"\x00", b" ").decode(errors="replace").strip()
            except (OSError, PermissionError):
                cmdline = ""
            if not cmdline:
                cmdline = f"[{campos.get('Name', entrada)}]"   # thread de kernel

            exe, apagado = None, False
            try:
                alvo = os.readlink(base / "exe")
                apagado = alvo.endswith(" (deleted)")
                exe = alvo.replace(" (deleted)", "")
            except (OSError, PermissionError):
                pass
            try:
                cwd = os.readlink(base / "cwd")
            except (OSError, PermissionError):
                cwd = None

            inicio = None
            try:
                ticks = int((base / "stat").read_text(errors="replace")
                            .rsplit(")", 1)[1].split()[19])
                hz = os.sysconf("SC_CLK_TCK") or 100
                inicio = (boot + timedelta(seconds=ticks / hz)).astimezone(
                    ).isoformat(timespec="seconds")
            except Exception:
                pass

            out.append(ProcessRecord(
                pid=pid, ppid=ppid, user=self._uname(uid) if uid >= 0 else "?",
                uid=uid if uid >= 0 else None, gid=gid if gid >= 0 else None,
                cmdline=cmdline,
                state=STATE_MAP.get((campos.get("State", "") or "?")[0],
                                    (campos.get("State", "") or "?")[0]),
                exe=exe, cwd=cwd, started_at=inicio, exe_deleted=apagado,
                source=self._ref(f"/proc/{pid}", "status+cmdline+exe")))
        return out

    # ------------------------------------------------------------------ #
    # Servicos via systemd
    # ------------------------------------------------------------------ #
    def _services(self) -> List[ServiceRecord]:
        listagem = self._run(["systemctl", "list-units", "--type=service", "--all",
                              "--no-legend", "--no-pager", "--plain"])
        if listagem is None:
            return []
        unidades = [p[0].lstrip("*").strip()
                    for p in (l.split() for l in listagem.splitlines())
                    if p and p[0].lstrip("*").strip().endswith(".service")]

        out: List[ServiceRecord] = []
        props = "Id,SubState,ActiveState,User,ExecStart,FragmentPath,MainPID"
        for unidade in unidades:
            mostrado = self._run(["systemctl", "show", unidade,
                                  "--property=" + props, "--no-pager"])
            if not mostrado:
                continue
            dados = dict(l.split("=", 1) for l in mostrado.splitlines() if "=" in l)
            ativo = dados.get("SubState") or dados.get("ActiveState") or "unknown"
            if ativo not in ("running", "exited", "listening", "active"):
                continue    # so unidades com estado relevante para o snapshot
            out.append(ServiceRecord(
                unit=unidade, active=ativo, user=dados.get("User") or "root",
                exec_start=_parse_execstart(dados.get("ExecStart", "")),
                fragment_path=dados.get("FragmentPath") or None,
                source=self._ref("systemctl show", unidade)))
        return out

    # ------------------------------------------------------------------ #
    # Logs
    # ------------------------------------------------------------------ #
    def _logs(self) -> List[LogRecord]:
        texto = self._run(["journalctl", "--no-pager", "-o", "short-iso",
                           "--since", f"-{self.log_window_min}min", "-n", "800"])
        artefato = "journalctl"
        if not texto:
            for candidato in ("/var/log/syslog", "/var/log/messages"):
                p = Path(candidato)
                if p.exists() and os.access(candidato, os.R_OK):
                    try:
                        texto = "\n".join(p.read_text(errors="replace")
                                          .splitlines()[-800:])
                        artefato = candidato
                        break
                    except OSError:
                        continue
        if not texto:
            self._avisos.append(
                "Nenhuma fonte de log acessivel: as correlacoes temporais "
                "(EI-R14 e EI-R15) ficam indisponiveis.")
            return []
        out = []
        for i, linha in enumerate(texto.splitlines(), start=1):
            p = parse_log_line(linha)
            if p:
                out.append(LogRecord(ts=p["ts"], message=p["message"], raw=p["raw"],
                                     host=p["host"], program=p["program"], pid=p["pid"],
                                     source=self._ref(artefato, f"linha {i}")))
        return out

    # ------------------------------------------------------------------ #
    # Permissoes orientadas por contexto
    # ------------------------------------------------------------------ #
    def _permissions(self, snap: Snapshot) -> List[FileRecord]:
        alvos: Set[str] = set()

        def add(caminho: Optional[str]) -> None:
            if caminho and caminho.startswith("/") and len(caminho) > 1:
                alvos.add(os.path.normpath(caminho))

        # 1. Recursos citados por processos e servicos.
        for p in snap.processes:
            add(p.exe)
            _argv, exe, _i, script, _t = analyze_command(p.cmdline)
            add(exe); add(script)
        for s in snap.services:
            _argv, exe, _i, script, _t = analyze_command(s.exec_start)
            add(exe); add(script); add(s.fragment_path)

        # 2. Diretorio-pai (permite substituir o arquivo) e vizinhos do mesmo
        #    diretorio, que pertencem a mesma zona de confianca.
        for t in list(alvos):
            pai = os.path.dirname(t)
            add(pai)
            if pai in BULK_DIRS or not pai.startswith("/"):
                continue
            try:
                with os.scandir(pai) as it:
                    for i, e in enumerate(sorted(it, key=lambda x: x.name)):
                        if i >= 25:
                            break
                        add(e.path)
            except (OSError, PermissionError):
                continue

        # 3. Linha de base de arquivos sensiveis e caminhos pedidos pelo analista.
        for b in BASELINE_PATHS:
            add(b)
        for extra in self.extra_paths:
            add(extra)
            ep = Path(extra)
            if ep.is_dir():
                try:
                    for filho in sorted(ep.iterdir())[:60]:
                        add(str(filho))
                except (OSError, PermissionError):
                    pass

        # 4. Alvo real de cada link: a permissao efetiva e a do alvo.
        for t in list(alvos):
            try:
                if os.path.islink(t):
                    real = os.path.realpath(t)
                    if real != t:
                        add(real); add(os.path.dirname(real))
            except OSError:
                continue

        return [r for r in (self._stat(c) for c in sorted(alvos)) if r]

    def _stat(self, caminho: str) -> Optional[FileRecord]:
        try:
            st = os.lstat(caminho)
        except (OSError, PermissionError):
            return None
        alvo_link = None
        if os.path.islink(caminho):
            tipo = "link"
            try:
                alvo_link = os.path.realpath(caminho)
            except OSError:
                pass
        else:
            tipo = "directory" if os.path.isdir(caminho) else "file"
        try:
            dono = pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            dono = str(st.st_uid)
        try:
            grupo = grp.getgrgid(st.st_gid).gr_name
        except KeyError:
            grupo = str(st.st_gid)
        return FileRecord(
            path=caminho, ftype=tipo, owner=dono, group=grupo,
            mode=format(st.st_mode & 0o7777, "04o"),
            mtime=datetime.fromtimestamp(st.st_mtime).astimezone(
                ).isoformat(timespec="seconds"),
            size=st.st_size, link_target=alvo_link,
            source=self._ref("lstat", caminho))


def _boot_time() -> datetime:
    try:
        with open("/proc/uptime") as fh:
            return datetime.now() - timedelta(seconds=float(fh.read().split()[0]))
    except (OSError, ValueError, IndexError):
        return datetime.now()


def _parse_execstart(bruto: str) -> str:
    """Extrai a linha de comando de ``ExecStart={ path=... ; argv[]=... }``."""
    if not bruto:
        return ""
    m = EXECSTART_RE.search(bruto)
    if m:
        return m.group(1).strip()
    if bruto.startswith("{"):
        m2 = re.search(r"path=([^\s;]+)", bruto)
        return m2.group(1) if m2 else ""
    return bruto.strip()
