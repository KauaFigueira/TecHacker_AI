"""Camada de NORMALIZACAO.

Converte os dados crus em representacao comparavel: modos octais viram flags,
linhas de comando viram argv + interpretador + script, linhas de log viram
registros e enderecos ganham classificacao de alcance. E esta camada que cria
as chaves que ligam um processo a um arquivo e um arquivo a um servico.
"""


import ipaddress
import re
import shlex
from datetime import datetime
from typing import List, Optional, Tuple

from .model import (
    FileRecord,
    ProcessRecord,
    ServiceRecord,
    Snapshot,
    UserRecord,
)

# Interpretadores que recebem um script como argumento.
INTERPRETERS = {
    "sh", "bash", "dash", "zsh", "ksh", "ash",
    "python", "python2", "python3", "perl", "ruby", "php", "node", "lua",
}

# Ferramentas que iniciam trafego de saida (usadas na correlacao de egress).
NETWORK_TOOLS = {
    "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp",
    "rsync", "ftp", "tftp", "telnet", "openssl",
}

# Envolucros que nao sao o programa real (ex.: /usr/bin/env python3 x.py).
WRAPPERS = {"env", "nohup", "setsid", "stdbuf", "timeout", "nice", "ionice", "sudo", "doas"}

URL_RE = re.compile(r"\b(?:https?|ftp|tftp)://([^\s/:]+)(?::(\d+))?(/\S*)?", re.I)
BARE_HOST_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?\b")

# "Sep 14 09:00:00 srv-app-01 sshd[1204]: Accepted publickey for aluno ..."
SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<prog>[\w@.\-/]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
# Formato ISO usado pelo journalctl -o short-iso
ISO_LOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\s+"
    r"(?P<host>\S+)\s+(?P<prog>[\w@.\-/]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
)}

PRIVILEGED_USERS = {"root"}


# --------------------------------------------------------------------------- #
# Permissoes
# --------------------------------------------------------------------------- #
def parse_mode(mode: str) -> int:
    """Converte ``0755`` / ``4755`` / ``rwxr-xr-x`` em inteiro octal."""
    mode = (mode or "").strip()
    if not mode:
        return 0
    if re.fullmatch(r"[0-7]{3,5}", mode):
        return int(mode, 8)
    if re.fullmatch(r"[-dlbcpsrwxSsTt]{9,10}", mode):
        return _mode_from_symbolic(mode)
    return 0


def _mode_from_symbolic(sym: str) -> int:
    if len(sym) == 10:
        sym = sym[1:]
    bits = 0
    special = 0
    for block, (r, w, x) in enumerate([(0, 1, 2), (3, 4, 5), (6, 7, 8)]):
        val = 0
        if sym[r] == "r":
            val |= 4
        if sym[w] == "w":
            val |= 2
        ch = sym[x]
        if ch in ("x", "s", "t"):
            val |= 1
        if ch in ("s", "S"):
            special |= 4 >> block if block < 2 else 0
            if block == 0:
                special |= 0o4
            elif block == 1:
                special |= 0o2
        if ch in ("t", "T"):
            special |= 0o1
        bits |= val << (6 - block * 3)
    return (special << 9) | bits


def mode_text(mode_int: int) -> str:
    return format(mode_int & 0o7777, "04o")


def enrich_file(f: FileRecord) -> FileRecord:
    f.mode_int = parse_mode(f.mode)
    f.mode = mode_text(f.mode_int)
    # Um link simbolico sempre reporta 0777 e o kernel Linux ignora esse modo:
    # a permissao efetiva e a do alvo. Normalizar isso aqui evita que todo
    # /usr/bin/python3 -> python3.12 vire um achado de "world-writable".
    if f.ftype == "link":
        f.world_writable = f.group_writable = f.world_readable = False
        f.setuid = f.setgid = f.sticky = False
        f.owner_privileged = f.owner in PRIVILEGED_USERS or f.owner == "0"
        return f
    f.world_writable = bool(f.mode_int & 0o002)
    f.group_writable = bool(f.mode_int & 0o020)
    f.world_readable = bool(f.mode_int & 0o004)
    f.setuid = bool(f.mode_int & 0o4000)
    f.setgid = bool(f.mode_int & 0o2000)
    f.sticky = bool(f.mode_int & 0o1000)
    f.owner_privileged = f.owner in PRIVILEGED_USERS or f.owner == "0"
    return f


def perm_text(f: FileRecord) -> str:
    """Descricao humana curta das permissoes relevantes."""
    tags = []
    if f.setuid:
        tags.append("setuid")
    if f.setgid:
        tags.append("setgid")
    if f.world_writable:
        tags.append("world-writable")
    elif f.group_writable:
        tags.append(f"group-writable({f.group})")
    if f.sticky:
        tags.append("sticky")
    return ", ".join(tags) if tags else "sem flag de risco"


# --------------------------------------------------------------------------- #
# Linhas de comando
# --------------------------------------------------------------------------- #
def split_cmd(cmd: str) -> List[str]:
    cmd = (cmd or "").strip()
    if not cmd:
        return []
    try:
        return shlex.split(cmd)
    except ValueError:
        return cmd.split()


def basename(path: str) -> str:
    return path.rsplit("/", 1)[-1] if path else ""


def analyze_command(cmd: str) -> Tuple[List[str], Optional[str], Optional[str], Optional[str], List[str]]:
    """Decompoe uma linha de comando.

    Retorna ``(argv, exe, interpreter, script, network_targets)``.

    ``exe``        binario efetivamente executado (depois de remover wrappers);
    ``interpreter`` nome do interpretador quando o comando e ``bash x.sh``;
    ``script``      caminho do script passado ao interpretador;
    ``network_targets`` hosts/URLs encontrados nos argumentos.
    """
    argv = split_cmd(cmd)
    if not argv:
        return [], None, None, None, []

    # Formatos sinteticos como "sshd: aluno@pts/0" nao sao execucoes reais.
    if argv[0].endswith(":") and len(argv) > 1:
        return argv, argv[0].rstrip(":"), None, None, extract_network_targets(cmd)

    idx = 0
    while idx < len(argv) - 1 and basename(argv[idx]) in WRAPPERS:
        idx += 1
        while idx < len(argv) - 1 and argv[idx].startswith("-"):
            idx += 1
    exe = argv[idx]
    rest = argv[idx + 1:]

    interpreter = None
    script = None
    name = basename(exe)
    if name in INTERPRETERS:
        interpreter = name
        for token in rest:
            if token.startswith("-"):
                continue
            if token.endswith((".sh", ".py", ".pl", ".rb", ".php", ".js", ".lua")) or token.startswith("/"):
                script = token
                break

    return argv, exe, interpreter, script, extract_network_targets(cmd)


def extract_network_targets(text: str) -> List[str]:
    """Extrai hosts/URLs citados em uma linha de comando."""
    out: List[str] = []
    for m in URL_RE.finditer(text or ""):
        host = m.group(1)
        if host not in out:
            out.append(host)
    for m in BARE_HOST_RE.finditer(text or ""):
        host = m.group(1)
        if host not in out:
            out.append(host)
    return out


# Faixas efetivamente internas a um site (RFC 1918, RFC 4193, CGNAT RFC 6598).
SITE_LOCAL_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fc00::/7"),
]
# Faixas reservadas para documentacao (RFC 5737 / RFC 3849). Os datasets da
# disciplina as usam para representar hosts externos; o ``ipaddress`` do Python
# as marca como "privadas", o que levaria a ferramenta a concluir errado.
DOC_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
]

# Classificacoes que representam um destino fora do proprio host.
OFF_HOST = {"externo", "documentacao", "hostname"}


def classify_address(addr: str) -> str:
    """Classifica um endereco quanto ao alcance.

    Retorna ``wildcard`` | ``loopback`` | ``link-local`` | ``privado`` |
    ``documentacao`` | ``externo`` | ``hostname``.

    A distincao importa para a analise: uma porta em escuta em 127.0.0.1 nao e
    superficie de rede; em 0.0.0.0 e. Um destino em 10.0.0.0/8 e interno; um
    destino globalmente roteavel nao e.
    """
    addr = (addr or "").strip().strip("[]")
    # ss reporta o identificador de zona junto ao endereco (127.0.0.53%lo,
    # fe80::1%wlp0s20f3). Sem remove-lo, o endereco nao parseia e um bind em
    # loopback seria contado como porta exposta.
    if "%" in addr:
        addr = addr.split("%", 1)[0]
    if not addr or addr in ("*", "::", "0.0.0.0"):
        return "wildcard"
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return "hostname"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if any(ip in net for net in DOC_NETS):
        return "documentacao"
    if any(ip in net for net in SITE_LOCAL_NETS):
        return "privado"
    if ip.is_multicast:
        return "multicast"
    return "externo"


def enrich_process(p: ProcessRecord) -> ProcessRecord:
    argv, exe, interp, script, targets = analyze_command(p.cmdline)
    p.argv = argv
    if not p.exe:
        p.exe = exe
    p.interpreter = interp
    p.script = script
    p.network_targets = targets
    p.is_privileged = p.user in PRIVILEGED_USERS or p.uid == 0
    return p


def enrich_service(s: ServiceRecord) -> ServiceRecord:
    argv, exe, interp, script, _ = analyze_command(s.exec_start)
    s.exec_argv = argv
    s.exec_path = exe
    s.exec_script = script
    s.is_privileged = s.user in PRIVILEGED_USERS or s.user in ("", "0")
    return s


# --------------------------------------------------------------------------- #
# Logs
# --------------------------------------------------------------------------- #
def parse_log_line(line: str, default_year: int = 2026) -> Optional[dict]:
    line = line.rstrip("\n")
    if not line.strip():
        return None
    m = ISO_LOG_RE.match(line)
    if m:
        ts = _parse_iso(m.group("ts"))
        return {
            "ts": ts, "host": m.group("host"), "program": m.group("prog"),
            "pid": int(m.group("pid")) if m.group("pid") else None,
            "message": m.group("msg"), "raw": line,
        }
    m = SYSLOG_RE.match(line)
    if m:
        try:
            ts = datetime(
                default_year, MONTHS[m.group("mon")], int(m.group("day")),
                *[int(x) for x in m.group("time").split(":")],
            )
        except (KeyError, ValueError):
            ts = None
        return {
            "ts": ts, "host": m.group("host"), "program": m.group("prog"),
            "pid": int(m.group("pid")) if m.group("pid") else None,
            "message": m.group("msg"), "raw": line,
        }
    return {"ts": None, "host": "", "program": "", "pid": None, "message": line, "raw": line}


def _parse_iso(text: str) -> Optional[datetime]:
    text = text.replace(",", ".").replace("Z", "+00:00")
    if len(text) > 5 and text[-5] in "+-" and ":" not in text[-5:]:
        text = text[:-2] + ":" + text[-2:]
    for fmt in (None,):
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            pass
    return None


def parse_dt(text: Optional[str]) -> Optional[datetime]:
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def to_naive(dt: Optional[datetime]) -> Optional[datetime]:
    """Remove tzinfo para permitir comparacoes entre fontes heterogeneas."""
    if dt is None:
        return None
    return dt.replace(tzinfo=None) if dt.tzinfo else dt


# --------------------------------------------------------------------------- #
# Normalizacao do snapshot completo
# --------------------------------------------------------------------------- #
def normalize_snapshot(snap: Snapshot) -> Snapshot:
    """Enriquece todas as entidades e monta os indices de busca."""
    for p in snap.processes:
        enrich_process(p)
    for f in snap.files:
        enrich_file(f)
    for s in snap.services:
        enrich_service(s)
    snap.by_pid = {p.pid: p for p in snap.processes}
    snap.by_path = {f.path: f for f in snap.files}
    snap.by_unit = {s.unit: s for s in snap.services}
    snap.by_user = {u.name: u for u in snap.users}

    # Usuarios inferidos a partir dos processos quando nao ha /etc/passwd.
    known = set(snap.by_user)
    for p in snap.processes:
        if p.user and p.user not in known:
            u = UserRecord(name=p.user, uid=p.uid, source=p.source)
            snap.users.append(u)
            snap.by_user[p.user] = u
            known.add(p.user)

    snap.processes.sort(key=lambda p: p.pid)
    snap.files.sort(key=lambda f: f.path)
    snap.services.sort(key=lambda s: s.unit)
    snap.logs.sort(key=lambda l: (l.ts or datetime.min.replace(tzinfo=None)) if not (l.ts and l.ts.tzinfo) else l.ts.replace(tzinfo=None))
    return snap
