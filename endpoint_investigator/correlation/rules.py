"""Regras de correlacao.

Cada regra cruza pelo menos duas das dimensoes coletadas e declara os quatro
elementos exigidos pelo enunciado: evidencia (o observado, com arquivo e
linha), interpretacao (significado tecnico), hipotese (explicacao possivel) e
evidencia ausente (o que confirmaria ou rejeitaria).

As quatro correlacoes citadas no enunciado estao cobertas:

    processo + servico + permissao  -> EI-R01, EI-R02
    processo + PPID + usuario       -> EI-R07, EI-R08
    servico + arquivo + usuario     -> EI-R01, EI-R03
    processo + servico + log        -> EI-R14, EI-R15

Nenhuma regra classifica um processo pelo nome, e nenhuma trata "servico como
root" como vulnerabilidade por si so.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from datetime import timedelta
from typing import Dict, Iterable, List, Optional, Tuple

from ..model import (
    Evidence, FileRecord, Finding, LogRecord, ProcessRecord, ServiceRecord,
    Severity, SourceRef, UserRecord,
)
from ..normalize import NETWORK_TOOLS, OFF_HOST, basename, classify_address, perm_text, to_naive
from .engine import RuleContext

PRIVILEGED_GROUPS = {"root", "shadow", "sudo", "wheel"}
SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "ash", "csh", "tcsh", "fish"}

# Pais para os quais um shell e esperado.
EXPECTED_SHELL_PARENTS = {
    "sshd", "login", "systemd", "init", "cron", "crond", "su", "sudo", "bash",
    "sh", "zsh", "gnome-terminal-server", "tmux", "screen", "konsole", "code",
    "containerd-shim", "runc", "docker", "systemd-logind", "agetty", "lightdm",
    "gdm-session-worker", "xterm", "kitty", "alacritty", "terminator", "node",
}
# Linha de base de permissoes: (modo maximo, dono esperado, motivo).
SENSITIVE_BASELINE: Dict[str, Tuple[int, str, str]] = {
    "/etc/shadow":          (0o640, "root", "hashes de senha nao devem ser legiveis por todos"),
    "/etc/gshadow":         (0o640, "root", "hashes de grupo nao devem ser legiveis por todos"),
    "/etc/passwd":          (0o644, "root", "nunca gravavel por nao-root"),
    "/etc/group":           (0o644, "root", "nunca gravavel por nao-root"),
    "/etc/sudoers":         (0o440, "root", "escrita permite elevacao direta de privilegio"),
    "/etc/ssh/sshd_config": (0o644, "root", "escrita permite alterar autenticacao remota"),
    "/etc/crontab":         (0o644, "root", "escrita permite execucao agendada como root"),
    "/etc/ld.so.preload":   (0o644, "root", "escrita permite injecao em qualquer binario"),
    "/root":                (0o750, "root", "diretorio do superusuario"),
}
SSH_ACCEPT_RE = re.compile(
    r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)", re.I)


# --------------------------------------------------------------------------- #
class Rule(ABC):
    id: str = "EI-R00"
    title: str = ""
    category: str = ""
    correlation: str = ""
    requires: Tuple[str, ...] = ()

    def unavailable_reason(self, ctx: RuleContext) -> Optional[str]:
        need = {
            "processes": (ctx.snap.processes, "nenhum processo coletado"),
            "files": (ctx.snap.files, "nenhuma permissao coletada"),
            "services": (ctx.snap.services, "nenhum servico coletado"),
            "logs": (ctx.snap.logs, "nenhum log coletado"),
        }
        for dim in self.requires:
            data, why = need[dim]
            if not data:
                return why
        return None

    @abstractmethod
    def apply(self, ctx: RuleContext) -> Iterable[Finding]:
        ...


# --------------------------------------------------------------------------- #
# Construtores de evidencia
# --------------------------------------------------------------------------- #
def _ev(kind: str, entity: str, observed: str, raw: str, src) -> Evidence:
    return Evidence(kind=kind, entity=entity, observed=observed, raw=raw,
                    source=src or SourceRef("desconhecido", kind))


def ev_process(p: ProcessRecord, observed: str) -> Evidence:
    return _ev("process", p.key, observed,
               f"pid={p.pid} ppid={p.ppid} user={p.user} cmd={p.cmdline}", p.source)


def ev_file(f: FileRecord, observed: str) -> Evidence:
    return _ev("file", f.key, observed,
               f"{f.mode} {f.owner}:{f.group} {f.path} (mtime={f.mtime})", f.source)


def ev_service(s: ServiceRecord, observed: str) -> Evidence:
    return _ev("service", s.key, observed,
               f"{s.unit} active={s.active} user={s.user} ExecStart={s.exec_start}",
               s.source)


def ev_log(l: LogRecord, observed: str) -> Evidence:
    return _ev("log", "log", observed, l.raw, l.source)


def ev_user(u: UserRecord, observed: str) -> Evidence:
    return _ev("user", f"user:{u.name}", observed, f"{u.name} (uid={u.uid})", u.source)


def writers_beyond(f: FileRecord, identity: str) -> List[Tuple[str, str]]:
    """Quem pode alterar o recurso alem da identidade que o executa.

    O risco nao e "ser root": e haver um conjunto de escritores maior que o de
    executores. Links simbolicos sao ignorados - o modo 0777 que sempre exibem
    nao e aplicado pelo kernel.
    """
    if f.ftype == "link":
        return []
    out: List[Tuple[str, str]] = []
    if f.world_writable:
        out.append(("qualquer usuario local", f"modo {f.mode} concede escrita a 'outros'"))
    if (f.group_writable and f.group not in PRIVILEGED_GROUPS
            and f.group not in ("?", identity)):
        out.append((f"membros do grupo '{f.group}'", f"modo {f.mode} concede escrita ao grupo"))
    if not f.owner_privileged and f.owner not in ("?", "", identity):
        out.append((f"usuario '{f.owner}'", "proprietario e outra identidade"))
    return out


def _quem(writers: List[Tuple[str, str]]) -> str:
    return "; ".join(f"{w} ({why})" for w, why in writers)


# --------------------------------------------------------------------------- #
# EI-R01  servico + permissao + usuario
# --------------------------------------------------------------------------- #
class ServicoExecutaRecursoGravavel(Rule):
    id = "EI-R01"
    title = "Servico executa recurso modificavel por identidade diferente da sua"
    category = "Relacao de privilegio"
    correlation = "servico + permissao + usuario"
    requires = ("services", "files")

    def apply(self, ctx: RuleContext) -> Iterable[Finding]:
        for svc in ctx.snap.services:
            for path in svc.resources:
                f = ctx.snap.file_for(path)
                if not f or f.ftype == "directory":
                    continue
                writers = writers_beyond(f, svc.user)
                if not writers:
                    continue
                procs = ctx.graph.processes_of_service(svc.unit)
                ev = [
                    ev_service(svc, f"Unidade '{svc.unit}' esta {svc.active} com "
                                    f"User={svc.user} e ExecStart={svc.exec_start}"),
                    ev_file(f, f"'{f.path}' tem modo {f.mode} ({perm_text(f)}), "
                               f"dono {f.owner}:{f.group}"),
                ]
                ev += [ev_process(p, f"pid {p.pid} ({p.user}) corresponde ao ExecStart "
                                     f"da unidade") for p in procs[:3]]
                yield Finding(
                    rule_id=self.id,
                    title=(f"{svc.unit} ({svc.user}) executa {f.path}, gravavel por "
                           + ("usuario nao privilegiado" if svc.is_privileged
                              else "identidade diferente da que executa")),
                    severity=Severity.HIGH if svc.is_privileged else Severity.MEDIUM,
                    category=self.category, correlation=self.correlation, evidence=ev,
                    interpretation=(
                        f"'{svc.unit}' executa como '{svc.user}' e depende de '{f.path}', "
                        f"que pode ser alterado por {_quem(writers)}. Quem altera o "
                        "conteudo determina o que sera executado com esse privilegio na "
                        "proxima execucao da unidade."
                    ),
                    hypothesis=(
                        f"Hipotese: alguem fora do escopo do servico substitui '{f.path}' e "
                        f"obtem execucao como {svc.user}. As evidencias descrevem a "
                        "viabilidade da relacao, nao que isso tenha ocorrido."
                    ),
                    missing_evidence=[
                        f"Historico de alteracao e hash conhecido-bom de '{f.path}'.",
                        "Quais usuarios nao privilegiados tem sessao nesta maquina.",
                        "ACL estendida e politica MAC, que podem restringir a escrita "
                        "apesar do modo observado.",
                    ],
                    false_positives=[
                        "O modo pode vir de um instalador, com o recurso protegido por "
                        "ACL, SELinux/AppArmor ou montagem read-only.",
                    ],
                    entities=[svc.key, f.key] + [p.key for p in procs[:3]],
                    attack_path=[
                        f"{writers[0][0]} altera '{f.path}'",
                        f"unidade '{svc.unit}' executa '{f.path}'",
                        f"codigo passa a executar como '{svc.user}'",
                    ],
                )


# --------------------------------------------------------------------------- #
# EI-R02  processo + permissao + usuario
# --------------------------------------------------------------------------- #
class ProcessoExecutaRecursoGravavel(Rule):
    id = "EI-R02"
    title = "Processo executa recurso modificavel por identidade diferente da sua"
    category = "Relacao de privilegio"
    correlation = "processo + permissao + usuario"
    requires = ("processes", "files")

    def apply(self, ctx: RuleContext) -> Iterable[Finding]:
        # Recursos ja cobertos por EI-R01 (via servico) nao sao repetidos.
        coberto = {r for svc in ctx.snap.services for r in svc.resources}
        for p in ctx.snap.processes:
            if p.cmdline.startswith("["):        # thread de kernel
                continue
            for path in filter(None, (p.script, p.exe)):
                if path in coberto:
                    continue
                f = ctx.snap.file_for(path)
                if not f or f.ftype == "directory":
                    continue
                writers = writers_beyond(f, p.user)
                if not writers:
                    continue
                parent = ctx.snap.by_pid.get(p.ppid)
                ev = [
                    ev_process(p, f"pid {p.pid} executa como '{p.user}': {p.short_cmd}"),
                    ev_file(f, f"'{f.path}' com modo {f.mode} ({perm_text(f)}), "
                               f"dono {f.owner}:{f.group}"),
                ]
                if parent:
                    ev.append(ev_process(parent, f"Pai pid {parent.pid} ({parent.user}): "
                                                 f"{parent.short_cmd}"))
                yield Finding(
                    rule_id=self.id,
                    title=f"pid {p.pid} ({p.user}) executa {f.path}, gravavel por terceiro",
                    severity=Severity.HIGH if p.is_privileged else Severity.MEDIUM,
                    category=self.category, correlation=self.correlation, evidence=ev,
                    interpretation=(
                        f"O pid {p.pid} executa, como '{p.user}', o recurso '{f.path}', "
                        f"alteravel por {_quem(writers)} - uma fronteira de identidade "
                        "atravessada. Diferente de EI-R01, nenhuma unidade systemd "
                        "explica esta execucao."
                    ),
                    hypothesis=(
                        "Hipotese: script operacional mantido por equipe que nao restringiu "
                        "o modo. Alternativa: recurso preparado para execucao privilegiada "
                        "de conteudo controlado por terceiro."
                    ),
                    missing_evidence=[
                        f"Como '{f.path}' foi invocado (cron, sessao, outro daemon).",
                        f"Conteudo e historico de alteracao de '{f.path}'.",
                    ],
                    false_positives=[
                        "Scripts em diretorio de usuario executados pelo proprio dono.",
                    ],
                    entities=[p.key, f.key],
                    attack_path=[f"{writers[0][0]} altera '{f.path}'",
                                 f"pid {p.pid} ({p.user}) executa o recurso"],
                )


# --------------------------------------------------------------------------- #
# EI-R03  servico + permissao do diretorio + usuario
# --------------------------------------------------------------------------- #
class DiretorioGravavelExpoeRecurso(Rule):
    id = "EI-R03"
    title = "Recurso de servico privilegiado reside em diretorio gravavel por terceiros"
    category = "Relacao de privilegio"
    correlation = "servico + permissao (diretorio) + usuario"
    requires = ("services", "files")

    def apply(self, ctx: RuleContext) -> Iterable[Finding]:
        for svc in ctx.snap.services:
            if not svc.is_privileged:
                continue
            for path in svc.resources:
                f = ctx.snap.file_for(path)
                if not f:
                    continue
                parent = ctx.snap.file_for(f.parent)
                if not parent or parent.ftype != "directory" or parent.sticky:
                    continue
                writers = writers_beyond(parent, svc.user)
                # Se o proprio arquivo ja e gravavel, EI-R01 cobre o caso.
                if not writers or (writers_beyond(f, svc.user) and f.ftype != "directory"):
                    continue
                yield Finding(
                    rule_id=self.id,
                    title=f"Diretorio {parent.path} gravavel expoe recurso de {svc.unit}",
                    severity=Severity.MEDIUM,
                    category=self.category, correlation=self.correlation,
                    evidence=[
                        ev_service(svc, f"'{svc.unit}' ({svc.active}) executa como "
                                        f"{svc.user} usando '{f.path}'"),
                        ev_file(f, f"Recurso '{f.path}' com modo {f.mode}"),
                        ev_file(parent, f"Diretorio-pai '{parent.path}' com modo "
                                        f"{parent.mode} ({perm_text(parent)}), sem sticky"),
                    ],
                    interpretation=(
                        f"O arquivo esta protegido (modo {f.mode}), mas reside em "
                        f"'{parent.path}', alteravel por {_quem(writers)}. Em Linux a "
                        "escrita no diretorio permite renomear e recriar o arquivo: a "
                        "protecao efetiva do recurso e a do diretorio."
                    ),
                    hypothesis=(
                        f"Hipotese: substituicao do recurso por renomeacao dentro de "
                        f"'{parent.path}'. Nao ha evidencia de que tenha ocorrido."
                    ),
                    missing_evidence=[
                        f"Inode e mtime historicos de '{f.path}', para detectar "
                        "substituicao ja ocorrida.",
                        f"ACL ou politica MAC aplicavel a '{parent.path}'.",
                    ],
                    false_positives=[
                        "Diretorios de aplicacao podem ser gravaveis por desenho, com o "
                        "risco aceito e compensado por outros controles.",
                    ],
                    entities=[svc.key, f.key, parent.key],
                    attack_path=[
                        f"{writers[0][0]} recria '{f.path}' dentro de '{parent.path}'",
                        f"unidade '{svc.unit}' executa o novo conteudo como '{svc.user}'",
                    ],
                )


# --------------------------------------------------------------------------- #
# EI-R04  permissao + ausencia de vinculo com execucao
# --------------------------------------------------------------------------- #
class PermissaoAmplaSemExecucao(Rule):
    """Distingue configuracao inadequada de relacao de privilegio demonstrada.

    Um arquivo world-writable e um problema de configuracao. So vira relacao de
    privilegio quando alguma identidade privilegiada o executa.
    """

    id = "EI-R04"
    title = "Permissao ampla em recurso sem relacao de execucao observada"
    category = "Configuracao"
    correlation = "permissao + ausencia de vinculo com processo/servico"
    requires = ("files",)

    PREFIXOS = ("/opt", "/usr", "/etc", "/srv", "/var/www", "/var/lib", "/home",
                "/root", "/bin", "/sbin", "/lib")
    IGNORADOS = ("/tmp", "/var/tmp", "/dev/shm", "/run")

    def apply(self, ctx: RuleContext) -> Iterable[Finding]:
        executados = {r for s in ctx.snap.services for r in s.resources}
        executados |= {x for p in ctx.snap.processes for x in (p.exe, p.script) if x}

        for f in ctx.snap.files:
            if (f.ftype == "link" or f.path in executados
                    or f.path.startswith(self.IGNORADOS)
                    or not f.path.startswith(self.PREFIXOS)
                    or f.path in SENSITIVE_BASELINE
                    or not f.world_writable or f.sticky):
                continue
            yield Finding(
                rule_id=self.id,
                title=f"{f.path} e world-writable, porem sem execucao privilegiada observada",
                severity=Severity.LOW,
                category=self.category, correlation=self.correlation,
                evidence=[
                    ev_file(f, f"'{f.path}' ({f.ftype}) com modo {f.mode} "
                               f"({perm_text(f)}), dono {f.owner}:{f.group}"),
                    _ev("service", "service:*",
                        f"Nenhuma das {len(ctx.snap.services)} unidades e nenhum dos "
                        f"{len(ctx.snap.processes)} processos coletados referencia "
                        f"'{f.path}' como executavel ou script",
                        "recursos em execucao: " + (", ".join(sorted(executados)[:8]) or "-"),
                        ctx.snap.services[0].source if ctx.snap.services else f.source),
                ],
                interpretation=(
                    f"'{f.path}' concede escrita a qualquer usuario local (modo {f.mode}), "
                    "mas nenhum processo e nenhuma unidade o executa. Portanto e "
                    "configuracao inadequada, nao relacao de privilegio demonstrada: falta "
                    "o elo 'identidade privilegiada executa o recurso' que tornaria o "
                    "achado grave (ver EI-R01)."
                ),
                hypothesis=(
                    "Hipotese: permissao herdada de copia ou provisionamento. O recurso "
                    "pode ser executado por mecanismo que este snapshot nao cobre (cron de "
                    "usuario, agendador de aplicacao); nesse caso subiria de severidade, "
                    "mas isso nao foi observado."
                ),
                missing_evidence=[
                    f"Se algum agendador invoca '{f.path}'.",
                    f"Se '{f.path}' e incluido por um script executado com privilegio.",
                ],
                false_positives=[
                    "Arquivos de dados compartilhados e diretorios de upload podem ser "
                    "gravaveis por desenho.",
                ],
                entities=[f.key],
            )


# --------------------------------------------------------------------------- #
# EI-R05  permissao + processo/servico (SUID/SGID)
# --------------------------------------------------------------------------- #
class BinarioSuidNoContexto(Rule):
    id = "EI-R05"
    title = "Binario SUID/SGID presente no contexto analisado"
    category = "Superficie de privilegio"
    correlation = "permissao + processo/servico"
    requires = ("files",)

    def apply(self, ctx: RuleContext) -> Iterable[Finding]:
        for f in ctx.snap.files:
            if f.ftype == "link" or not (f.setuid or f.setgid):
                continue
            writers = writers_beyond(f, "root")
            bit = "SUID" if f.setuid else "SGID"
            ev = [ev_file(f, f"'{f.path}' com modo {f.mode} ({perm_text(f)}), "
                             f"dono {f.owner}:{f.group}")] + self._referencias(ctx, f.path)
            yield Finding(
                rule_id=self.id,
                title=f"Binario {bit} {f.path} ({f.owner}:{f.group})",
                severity=Severity.HIGH if writers else Severity.MEDIUM,
                category=self.category, correlation=self.correlation, evidence=ev,
                interpretation=(
                    f"'{f.path}' carrega o bit {bit}: executa com a identidade do dono "
                    f"('{f.owner}'), nao com a de quem o invoca. Qualquer falha de "
                    "tratamento de entrada nesse binario e explorada com esse privilegio."
                    + (f" Alem disso, o binario pode ser alterado por {_quem(writers)}, "
                       "o que o torna um caminho direto de elevacao." if writers else "")
                ),
                hypothesis=(
                    "Hipotese: bit definido pelo empacotador da distribuicao, como em "
                    "sudo, passwd e mount. A presenca do bit nao caracteriza "
                    "vulnerabilidade nem comprometimento."
                ),
                missing_evidence=[
                    f"Hash de '{f.path}' comparado ao pacote de origem (dpkg -V / rpm -V).",
                    "Se o binario e conhecido por permitir escape de privilegio quando SUID.",
                ],
                false_positives=[
                    "Binarios SUID de sistema sao esperados em qualquer instalacao.",
                ],
                entities=[f.key],
            )

    @staticmethod
    def _referencias(ctx: RuleContext, path: str) -> List[Evidence]:
        out = []
        p = next((x for x in ctx.snap.processes
                  if x.exe == path or x.script == path or path in x.cmdline), None)
        if p:
            out.append(ev_process(p, f"pid {p.pid} ({p.user}) referencia '{path}'"))
        s = next((x for x in ctx.snap.services
                  if path in x.resources or path in (x.exec_start or "")), None)
        if s:
            out.append(ev_service(s, f"'{s.unit}' referencia '{path}' no ExecStart"))
        return out


# --------------------------------------------------------------------------- #
# EI-R06  permissao + linha de base
# --------------------------------------------------------------------------- #
class ArquivoSensivelForaDaBase(Rule):
    id = "EI-R06"
    title = "Arquivo sensivel com permissao divergente da linha de base"
    category = "Configuracao"
    correlation = "permissao + identidade (linha de base)"
    requires = ("files",)

    def apply(self, ctx: RuleContext) -> Iterable[Finding]:
        for path, (max_mode, dono, motivo) in SENSITIVE_BASELINE.items():
            f = ctx.snap.file_for(path)
            if not f:
                continue
            extra = f.mode_int & ~max_mode & 0o7777
            dono_ok = f.owner in (dono, "0")
            if not extra and dono_ok:
                continue
            problemas = []
            if extra:
                problemas.append(f"bits {format(extra, '04o')} alem da base "
                                 f"{format(max_mode, '04o')}")
            if not dono_ok:
                problemas.append(f"dono '{f.owner}' em vez de '{dono}'")
            yield Finding(
                rule_id=self.id,
                title=f"{path} com modo {f.mode} (esperado ate {format(max_mode, '04o')})",
                severity=(Severity.HIGH if (f.world_writable or f.group_writable)
                          else Severity.MEDIUM),
                category=self.category, correlation=self.correlation,
                evidence=[ev_file(f, f"'{path}' com modo {f.mode}, dono {f.owner}:{f.group}")],
                interpretation=f"'{path}' esta fora da linha de base ({', '.join(problemas)}). "
                               f"Motivo da base: {motivo}.",
                hypothesis=(
                    "Hipotese: alteracao manual em manutencao ou pos-instalacao de "
                    "software. Alternativa: alteracao deliberada para facilitar acesso. "
                    "O snapshot nao distingue as duas."
                ),
                missing_evidence=[
                    f"Modo original conforme o pacote da distribuicao para '{path}'.",
                    "Quando e por quem o modo foi alterado.",
                ],
                false_positives=[
                    "Algumas distribuicoes e imagens de container adotam modos diferentes "
                    "da base Debian/RHEL usada aqui.",
                ],
                entities=[f.key],
            )


# --------------------------------------------------------------------------- #
# EI-R07  processo + PPID + usuario
# --------------------------------------------------------------------------- #
class TransicaoDePrivilegio(Rule):
    id = "EI-R07"
    title = "Transicao de privilegio na arvore de processos"
    category = "Contexto de execucao"
    correlation = "processo + PPID + usuario"
    requires = ("processes",)

    def apply(self, ctx: RuleContext) -> Iterable[Finding]:
        for p in ctx.snap.processes:
            if not p.is_privileged or p.pid == 1:
                continue
            parent = ctx.snap.by_pid.get(p.ppid)
            if not parent or parent.is_privileged:
                continue
            mecanismo, extra = self._mecanismo(ctx, p, parent)
            cadeia = [f"pid {a.pid} ({a.user}) {a.short_cmd}"
                      for a in reversed(ctx.snap.ancestry(p))]
            yield Finding(
                rule_id=self.id,
                title=f"pid {p.pid} executa como {p.user} tendo pai pid {parent.pid} "
                      f"como {parent.user}",
                severity=Severity.MEDIUM,
                category=self.category, correlation=self.correlation,
                evidence=[
                    ev_process(p, f"pid {p.pid} executa como '{p.user}': {p.short_cmd}"),
                    ev_process(parent, f"Pai pid {parent.pid} executa como "
                                       f"'{parent.user}': {parent.short_cmd}"),
                ] + extra,
                interpretation=(
                    f"Houve elevacao entre pai e filho: '{parent.user}' -> '{p.user}'. Em "
                    "Linux isso so ocorre por mecanismo explicito - binario SUID, sudo/su, "
                    f"capability ou auxilio de servico privilegiado. Mecanismo "
                    f"identificado: {mecanismo}."
                ),
                hypothesis=(
                    "Hipotese: uso legitimo de sudo ou su. Alternativa: abuso de binario "
                    "SUID ou de regra sudo permissiva. O snapshot nao distingue as duas."
                ),
                missing_evidence=[
                    "Registros de autenticacao (sudo/PAM) no instante da criacao do filho.",
                    "Conteudo de /etc/sudoers e capabilities efetivas do processo.",
                ],
                false_positives=[
                    "Sessoes administrativas normais produzem exatamente este padrao.",
                ],
                entities=[p.key, parent.key],
                attack_path=cadeia + [f"pid {p.pid} ({p.user}) {p.short_cmd}"],
            )

    @staticmethod
    def _mecanismo(ctx, p, parent) -> Tuple[str, List[Evidence]]:
        nome = basename(parent.exe or (parent.argv[0] if parent.argv else ""))
        if nome in ("sudo", "su", "pkexec", "doas"):
            return f"pai e '{nome}'", []
        f = ctx.snap.file_for(p.exe or "")
        if f and (f.setuid or f.setgid):
            return ("binario do filho possui bit SUID/SGID",
                    [ev_file(f, f"Executavel do filho '{f.path}' com modo {f.mode}")])
        return "nao identificado nas fontes coletadas", []


# --------------------------------------------------------------------------- #
# EI-R08  processo + PPID + servico
# --------------------------------------------------------------------------- #
class ShellGeradoPorDaemon(Rule):
    id = "EI-R08"
    title = "Shell interativo gerado por daemon que normalmente nao cria shells"
    category = "Contexto de execucao"
    correlation = "processo + PPID + servico"
    requires = ("processes",)

    def apply(self, ctx: RuleContext) -> Iterable[Finding]:
        for p in ctx.snap.processes:
            nome = basename(p.exe or (p.argv[0] if p.argv else ""))
            if nome not in SHELLS:
                continue
            parent = ctx.snap.by_pid.get(p.ppid)
            if not parent or parent.ppid == 0:
                continue
            pnome = basename(parent.exe or (parent.argv[0] if parent.argv else "")).rstrip(":")
            if not pnome or pnome in EXPECTED_SHELL_PARENTS or pnome in SHELLS:
                continue
            svc = next((s for s in ctx.snap.services if parent.pid in
                        {x.pid for x in ctx.graph.processes_of_service(s.unit, loose=True)}),
                       None)
            ev = [
                ev_process(p, f"Shell '{nome}' no pid {p.pid} executando como '{p.user}'"),
                ev_process(parent, f"Pai pid {parent.pid} e '{pnome}' como "
                                   f"'{parent.user}': {parent.short_cmd}"),
            ]
            if svc:
                ev.append(ev_service(svc, f"O pai pertence a '{svc.unit}' (User={svc.user})"))

            # O que o shell fez em seguida muda o peso do achado.
            net = [c for c in ctx.snap.children_of(p.pid)
                   if basename(c.exe or (c.argv[0] if c.argv else "")) in NETWORK_TOOLS]
            ev += [ev_process(c, f"Filho do shell: pid {c.pid} executa "
                                 f"'{basename(c.exe or '')}' com destino "
                                 f"{', '.join(c.network_targets) or 'nao identificado'}")
                   for c in net[:2]]
            l = next((l for l in ctx.snap.logs if l.pid in (p.pid, parent.pid)), None)
            if l:
                ev.append(ev_log(l, f"Evento associado a cadeia: {l.message}"))

            cauda = ""
            if net:
                destinos = ", ".join(t for c in net for t in c.network_targets) or "destino externo"
                cauda = (f" Em seguida o shell gerou {basename(net[0].exe or '')} com destino "
                         f"{destinos}, completando a sequencia daemon -> shell -> trafego "
                         "de saida. E a sequencia, nao o shell isolado, que sustenta o achado.")
            yield Finding(
                rule_id=self.id,
                title=(f"{nome} (pid {p.pid}) criado por {pnome} (pid {parent.pid})"
                       + (f" seguido de {basename(net[0].exe or '')}" if net else "")),
                severity=(Severity.HIGH if net else
                          Severity.MEDIUM if (svc or parent.is_privileged) else Severity.LOW),
                category=self.category,
                correlation=self.correlation + (" + argumentos de rede" if net else ""),
                evidence=ev,
                interpretation=(
                    f"Um shell foi criado tendo '{pnome}' como pai. Servidores de aplicacao "
                    "e daemons raramente precisam gerar shells; quando o fazem, costuma ser "
                    "por execucao de comando vinda de entrada externa ou por manutencao "
                    "manual." + cauda
                ),
                hypothesis=(
                    "Hipotese: execucao administrativa pontual ou hook de deploy. "
                    "Alternativa: execucao derivada de uma requisicao tratada pelo daemon. "
                    "O snapshot nao contem a entrada que originou o processo."
                ),
                missing_evidence=[
                    f"Argumentos completos e ambiente do pid {p.pid}.",
                    f"Logs da aplicacao '{pnome}' no instante da criacao do shell.",
                ],
                false_positives=[
                    "Scripts de deploy, hooks e healthchecks invocam shells legitimamente.",
                ],
                entities=[p.key, parent.key] + ([svc.key] if svc else []),
                attack_path=[f"pid {parent.pid} ({pnome}, {parent.user})",
                             f"pid {p.pid} ({nome}, {p.user})"]
                            + [f"pid {c.pid} ({basename(c.exe or '')}) -> "
                               f"{', '.join(c.network_targets) or 'destino externo'}"
                               for c in net[:1]],
            )


# --------------------------------------------------------------------------- #
# EI-R09  servico + processo + PPID
# --------------------------------------------------------------------------- #
class CadeiaServicoInterpretadorRede(Rule):
    id = "EI-R09"
    title = "Cadeia servico privilegiado -> interpretador -> ferramenta de rede"
    category = "Contexto de execucao"
    correlation = "servico + processo + PPID"
    requires = ("services", "processes")

    def apply(self, ctx: RuleContext) -> Iterable[Finding]:
        for svc in ctx.snap.services:
            if not svc.is_privileged:
                continue
            for proc in ctx.graph.processes_of_service(svc.unit):
                filhos = [c for c in ctx.snap.children_of(proc.pid)
                          if basename(c.exe or (c.argv[0] if c.argv else "")) in NETWORK_TOOLS]
                if not filhos:
                    continue
                c = filhos[0]
                yield Finding(
                    rule_id=self.id,
                    title=f"{svc.unit} -> pid {proc.pid} -> {basename(c.exe or '')} "
                          f"(pid {c.pid})",
                    severity=Severity.LOW,
                    category=self.category, correlation=self.correlation,
                    evidence=[
                        ev_service(svc, f"'{svc.unit}' ativa como {svc.user}"),
                        ev_process(proc, f"pid {proc.pid} corresponde ao ExecStart"),
                        ev_process(c, f"Filho pid {c.pid} (PPID {c.ppid}) executa "
                                      f"'{c.short_cmd}'"),
                    ],
                    interpretation=(
                        "A cadeia servico -> processo -> subprocesso foi reconstruida pelo "
                        "PPID. Um servico privilegiado gera subprocessos que falam com a "
                        "rede: qualquer entrada que o servico processe pode influenciar os "
                        "argumentos desses subprocessos."
                    ),
                    hypothesis=(
                        "Hipotese: comportamento previsto do agente (publicar metricas, "
                        "baixar atualizacao, enviar backup). A cadeia por si nao indica abuso."
                    ),
                    missing_evidence=[
                        "Se os argumentos do subprocesso derivam de entrada externa "
                        "(risco de injecao de comando).",
                        "Configuracao do servico.",
                    ],
                    false_positives=[
                        "Praticamente todo agente de monitoramento apresenta esta cadeia.",
                    ],
                    entities=[svc.key, proc.key, c.key],
                    attack_path=[f"unidade '{svc.unit}' (User={svc.user})",
                                 f"pid {proc.pid} {proc.short_cmd}",
                                 f"pid {c.pid} {c.short_cmd}"],
                )


# --------------------------------------------------------------------------- #
# EI-R10  processo + servico + usuario
# --------------------------------------------------------------------------- #
class DaemonSemUnidade(Rule):
    id = "EI-R10"
    title = "Processo privilegiado persistente sem unidade systemd correspondente"
    category = "Contexto de execucao"
    correlation = "processo + servico + usuario"
    requires = ("processes", "services")

    def apply(self, ctx: RuleContext) -> Iterable[Finding]:
        # loose=True: um processo explicado por uma unidade, ainda que por nome,
        # nao e um daemon fora do inventario.
        geridos = {x.pid for svc in ctx.snap.services
                   for x in ctx.graph.processes_of_service(svc.unit, loose=True)}
        for p in ctx.snap.processes:
            if (p.pid == 1 or p.ppid != 1 or not p.is_privileged
                    or p.pid in geridos or p.cmdline.startswith("[")
                    or basename(p.exe or "") in ("systemd", "init")):
                continue
            yield Finding(
                rule_id=self.id,
                title=f"pid {p.pid} ({p.user}) adotado pelo PID 1 sem unidade correspondente",
                severity=Severity.MEDIUM if p.interpreter else Severity.LOW,
                category=self.category, correlation=self.correlation,
                evidence=[
                    ev_process(p, f"pid {p.pid} tem PPID 1, executa como '{p.user}' e "
                                  f"cmdline '{p.short_cmd}'"),
                    _ev("service", "service:*",
                        f"Nenhuma das {len(ctx.snap.services)} unidades coletadas declara "
                        f"ExecStart compativel com o comando do pid {p.pid}",
                        "; ".join(s.exec_start for s in ctx.snap.services[:6]),
                        ctx.snap.services[0].source),
                ],
                interpretation=(
                    f"O pid {p.pid} executa com privilegio ligado ao PID 1, padrao de "
                    "daemon, mas nenhuma unidade coletada explica sua execucao. Pode ter "
                    "sido iniciado fora do systemd (rc.local, cron, nohup, container) ou "
                    "ter sido reparentado apos o pai terminar."
                ),
                hypothesis=(
                    "Hipotese: daemon lancado por mecanismo nao inventariado, ou "
                    "reparentacao. A ausencia de unidade nao implica malicia."
                ),
                missing_evidence=[
                    f"Origem da execucao do pid {p.pid} (auditd execve, /proc/{p.pid}/environ).",
                    "Inventario de cron, rc.local e unidades de usuario.",
                ],
                false_positives=[
                    "Daemons iniciados por SysV, supervisord ou docker aparecem assim.",
                ],
                entities=[p.key],
            )


# --------------------------------------------------------------------------- #
# EI-R11  servico + processo
# --------------------------------------------------------------------------- #
class UnidadeSemProcesso(Rule):
    id = "EI-R11"
    title = "Unidade ativa sem processo correspondente ao ExecStart declarado"
    category = "Inconsistencia de estado"
    correlation = "servico + processo"
    requires = ("services", "processes")

    def apply(self, ctx: RuleContext) -> Iterable[Finding]:
        for svc in ctx.snap.services:
            if svc.active not in ("running", "active"):
                continue
            if ctx.graph.processes_of_service(svc.unit):
                continue        # correspondencia estrita: nada a relatar
            loose = ctx.graph.processes_of_service(svc.unit, loose=True)

            if loose:
                p = loose[0]
                yield Finding(
                    rule_id=self.id,
                    title=f"{svc.unit} executa '{p.short_cmd}', diferente do ExecStart "
                          f"declarado",
                    severity=Severity.INFO,
                    category=self.category, correlation=self.correlation,
                    evidence=[
                        ev_service(svc, f"'{svc.unit}' ({svc.active}) declara "
                                        f"ExecStart='{svc.exec_start}'"),
                        ev_process(p, f"pid {p.pid} ({p.user}), com nome compativel, "
                                      f"executa '{p.cmdline}'"),
                    ],
                    interpretation=(
                        f"O comando declarado ('{svc.exec_start}') nao e o que esta em "
                        f"execucao ('{p.cmdline}'). O padrao usual e um wrapper de "
                        "inicializacao que troca a imagem do processo. A divergencia e "
                        "registrada para que o pareamento servico-processo seja auditavel."
                    ),
                    hypothesis=(
                        "Hipotese: wrapper legitimo. So seria relevante se o processo em "
                        "execucao nao pudesse ser explicado pelo pacote que fornece a unidade."
                    ),
                    missing_evidence=[
                        f"Conteudo do arquivo de unidade de '{svc.unit}' e do wrapper.",
                        f"MainPID declarado pelo systemd para '{svc.unit}'.",
                    ],
                    false_positives=[
                        "Quase todo servico com script de inicializacao diverge assim.",
                    ],
                    entities=[svc.key, p.key],
                )
                continue

            yield Finding(
                rule_id=self.id,
                title=f"{svc.unit} consta como {svc.active} mas nao ha processo equivalente",
                severity=Severity.LOW,
                category=self.category, correlation=self.correlation,
                evidence=[
                    ev_service(svc, f"'{svc.unit}' consta como '{svc.active}' com "
                                    f"ExecStart='{svc.exec_start}'"),
                    _ev("process", "process:*",
                        f"Nenhum dos {len(ctx.snap.processes)} processos coletados tem "
                        f"linha de comando ou nome compativel com essa unidade",
                        "; ".join(p.short_cmd for p in ctx.snap.processes[:6]),
                        ctx.snap.processes[0].source),
                ],
                interpretation=(
                    "Os inventarios de servicos e de processos descrevem o mesmo host e "
                    "deveriam concordar. Nem por nome nem por linha de comando foi "
                    "possivel atribuir um processo a esta unidade."
                ),
                hypothesis=(
                    "Hipotese mais provavel: unidade oneshot/forking ja concluida, ou "
                    "defasagem entre a coleta das duas fontes. Menos provavel, mas nao "
                    "descartavel: o processo real difere do declarado."
                ),
                missing_evidence=[
                    f"Type= e MainPID= de '{svc.unit}' (systemctl show).",
                    "Instante exato de coleta de cada fonte, para descartar defasagem.",
                ],
                false_positives=[
                    "Unidades Type=oneshot produzem esta divergencia legitimamente.",
                ],
                entities=[svc.key],
            )


# --------------------------------------------------------------------------- #
# EI-R12  processo + arquivo (inode removido)
# --------------------------------------------------------------------------- #
class ExecutavelRemovido(Rule):
    id = "EI-R12"
    title = "Processo em execucao cujo executavel foi removido do disco"
    category = "Integridade"
    correlation = "processo + arquivo (inode removido)"
    requires = ("processes",)

    def apply(self, ctx: RuleContext) -> Iterable[Finding]:
        # Uma atualizacao de pacote deixa dezenas de processos assim ao mesmo
        # tempo. Agrupar por executavel transforma "18 achados iguais" em
        # "4 binarios substituidos", que e a informacao util.
        por_exe: Dict[str, List[ProcessRecord]] = {}
        for p in ctx.snap.processes:
            if p.exe_deleted and p.exe:
                por_exe.setdefault(p.exe, []).append(p)

        for exe, procs in sorted(por_exe.items()):
            procs.sort(key=lambda x: x.pid)
            privilegiado = any(x.is_privileged for x in procs)
            usuarios = sorted({x.user for x in procs})
            ev = [ev_process(x, f"/proc/{x.pid}/exe aponta para '{x.exe} (deleted)': o "
                                f"inode nao existe mais") for x in procs[:3]]
            if len(procs) > 3:
                ev.append(_ev("process", f"file:{exe}",
                              f"Mais {len(procs) - 3} processo(s) executam o mesmo binario",
                              "pids: " + ", ".join(str(x.pid) for x in procs),
                              procs[0].source))
            f = ctx.snap.file_for(exe)
            if f:
                ev.append(ev_file(f, f"Ha um arquivo em '{exe}' agora, modo {f.mode}, "
                                     f"mtime {f.mtime}: foi substituido, nao so apagado"))
            yield Finding(
                rule_id=self.id,
                title=f"{len(procs)} processo(s) executam '{exe}', que foi removido ou "
                      f"substituido ({', '.join(usuarios)})",
                severity=Severity.HIGH if privilegiado else Severity.LOW,
                category=self.category, correlation=self.correlation, evidence=ev,
                interpretation=(
                    f"{len(procs)} processo(s) seguem executando a partir de um inode ja "
                    f"removido ('{exe}'). Isso impede verificar a integridade do binario "
                    "pelo caminho, e e tanto uma tecnica de dificultar analise quanto o "
                    "resultado normal de atualizacao de pacote sem reinicio."
                    + (" O numero de processos afetados ao mesmo tempo e consistente com "
                       "substituicao de pacote." if len(procs) >= 3 else "")
                ),
                hypothesis=(
                    "Hipotese mais provavel em host atualizado: pacote substituido sem "
                    "reinicio. Alternativa: binario apagado deliberadamente. O registro de "
                    "atualizacao de pacotes separa as duas."
                ),
                missing_evidence=[
                    f"Hash do binario via /proc/<pid>/exe comparado ao pacote de '{exe}'.",
                    "Registro de atualizacao de pacotes no periodo (dpkg.log, dnf history).",
                ],
                false_positives=[
                    "Comum apos 'apt upgrade' sem reinicio, e em aplicacoes que se "
                    "auto-atualizam.",
                ],
                entities=[f"file:{exe}"] + [x.key for x in procs[:5]],
            )


# --------------------------------------------------------------------------- #
# EI-R13  processo + usuario + servico/log
# --------------------------------------------------------------------------- #
class SaidaDeRedePrivilegiada(Rule):
    id = "EI-R13"
    title = "Conexao de saida iniciada a partir de contexto privilegiado"
    category = "Contexto de execucao"
    correlation = "processo + usuario + servico/log"
    requires = ("processes",)

    def apply(self, ctx: RuleContext) -> Iterable[Finding]:
        for p in ctx.snap.processes:
            if not p.is_privileged or not p.network_targets:
                continue
            ferramenta = basename(p.exe or (p.argv[0] if p.argv else ""))
            if ferramenta not in NETWORK_TOOLS:
                continue
            externos = [t for t in p.network_targets if classify_address(t) in OFF_HOST]
            if not externos:
                continue
            parent = ctx.snap.by_pid.get(p.ppid)
            svc = self._servico_de(ctx, p, parent)
            ev = [ev_process(p, f"pid {p.pid} executa '{ferramenta}' como '{p.user}' "
                                f"com destino {', '.join(externos)}")]
            if parent:
                ev.append(ev_process(parent, f"Pai pid {parent.pid} ({parent.user}): "
                                             f"{parent.short_cmd}"))
            if svc:
                ev.append(ev_service(svc, f"'{svc.unit}' ({svc.user}) explica a cadeia "
                                          f"de execucao do pid {p.pid}"))
            ev += [ev_log(l, f"Registro associado: {l.message}") for l in ctx.snap.logs
                   if l.pid == p.pid or any(t in l.message for t in externos)][:2]

            yield Finding(
                rule_id=self.id,
                title=f"pid {p.pid} ({p.user}) inicia trafego externo para {externos[0]}",
                severity=Severity.MEDIUM,
                category=self.category, correlation=self.correlation, evidence=ev,
                interpretation=(
                    f"Processo com privilegio ('{p.user}') invoca '{ferramenta}' com "
                    f"destino fora do host ({', '.join(externos)}). O destino vem dos "
                    "argumentos do comando, nao de coleta de rede. O relevante nao e a "
                    "conexao existir, e o contexto: saida originada de identidade "
                    "privilegiada amplia o impacto de um canal comprometido."
                ),
                hypothesis=(
                    "Hipotese: agente de telemetria, atualizacao ou backup - sustentada "
                    + (f"por '{svc.unit}'." if svc else "pelo processo pai do sistema.")
                    + " A ferramenta NAO classifica a conexao como C2 ou malware: destino, "
                    "frequencia e conteudo do trafego nao estao entre as fontes coletadas."
                ),
                missing_evidence=[
                    f"Resolucao DNS e reputacao de '{externos[0]}'.",
                    "Se a conexao chegou a ser estabelecida, e com que volume.",
                ],
                false_positives=[
                    "Agentes de monitoramento e atualizadores fazem exatamente isso.",
                    "Uma URL em linha de comando nao prova que houve conexao.",
                ],
                entities=[p.key] + ([svc.key] if svc else []),
            )

    @staticmethod
    def _servico_de(ctx, p, parent):
        for svc in ctx.snap.services:
            pids = {x.pid for x in ctx.graph.processes_of_service(svc.unit)}
            if p.pid in pids or (parent and parent.pid in pids):
                return svc
        return None


# --------------------------------------------------------------------------- #
# EI-R14  log + processo + usuario (reconstrucao temporal)
# --------------------------------------------------------------------------- #
class ReconstrucaoDeSessao(Rule):
    id = "EI-R14"
    title = "Reconstrucao temporal de sessao interativa remota"
    category = "Reconstrucao temporal"
    correlation = "log + processo + usuario"
    requires = ("logs", "processes")

    def apply(self, ctx: RuleContext) -> Iterable[Finding]:
        for l in ctx.snap.logs:
            m = SSH_ACCEPT_RE.search(l.message)
            if not m:
                continue
            user, ip, metodo = m.group("user"), m.group("ip"), m.group("method")
            da_sessao = [p for p in ctx.snap.processes if p.user == user]
            if not da_sessao:
                continue
            ancora = next((p for p in da_sessao if l.pid and p.pid == l.pid), None)
            cadeia = self._descendentes(ctx, ancora) if ancora else da_sessao

            ev = [ev_log(l, f"sshd aceitou autenticacao de '{user}' vinda de {ip} "
                            f"por {metodo}")]
            ev += [ev_process(p, f"pid {p.pid} de '{p.user}' na cadeia da sessao")
                   for p in cadeia[:4]]
            u = ctx.snap.by_user.get(user)
            if u:
                ev.append(ev_user(u, f"'{user}' e a identidade sob a qual esses processos "
                                     f"executam"))

            notaveis = [p for p in cadeia if p.interpreter
                        or basename(p.exe or "") in NETWORK_TOOLS]
            yield Finding(
                rule_id=self.id,
                title=f"Sessao de '{user}' a partir de {ip} reconstruida com "
                      f"{len(cadeia)} processo(s)",
                severity=Severity.LOW if notaveis else Severity.INFO,
                category=self.category, correlation=self.correlation, evidence=ev,
                interpretation=(
                    f"O registro de autenticacao e o inventario de processos foram "
                    f"costurados para reconstruir o que a sessao de '{user}' fez apos o "
                    f"login: origem {ip}, metodo {metodo}, {len(cadeia)} processo(s) "
                    "atribuiveis. E linha de base de atividade, nao achado de risco."
                    + (" Dentro da sessao houve execucao de interpretador ou ferramenta "
                       "de rede, o que merece leitura de contexto." if notaveis else "")
                ),
                hypothesis=(
                    "Hipotese: acesso administrativo legitimo. A reconstrucao responde "
                    "'o que aconteceu depois do login', nao se o acesso foi indevido."
                ),
                missing_evidence=[
                    f"Se {ip} pertence a faixa autorizada de administracao.",
                    "Historico de comandos executados na sessao.",
                ],
                false_positives=[
                    "Processos antigos do mesmo usuario entram na lista quando o PID do "
                    "sshd nao pode ser ancorado.",
                ],
                entities=[p.key for p in cadeia[:6]] + [f"user:{user}"],
                attack_path=[f"{l.ts_text} sshd registra login de '{user}' de {ip}"]
                            + [f"pid {p.pid} ({p.user}) {p.short_cmd}" for p in cadeia[:6]],
            )

    @staticmethod
    def _descendentes(ctx, raiz):
        if not raiz:
            return []
        out, fila = [raiz], [raiz]
        while fila:
            atual = fila.pop(0)
            for filho in ctx.snap.children_of(atual.pid):
                if filho not in out:
                    out.append(filho)
                    fila.append(filho)
        return out


# --------------------------------------------------------------------------- #
# EI-R15  permissao (mtime) + log + servico
# --------------------------------------------------------------------------- #
class RecursoAlteradoNaJanela(Rule):
    id = "EI-R15"
    title = "Recurso de servico alterado dentro da janela de observacao dos logs"
    category = "Reconstrucao temporal"
    correlation = "permissao (mtime) + log + servico"
    requires = ("files", "logs", "services")

    def apply(self, ctx: RuleContext) -> Iterable[Finding]:
        from ..normalize import parse_dt
        marcas = [to_naive(l.ts) for l in ctx.snap.logs if l.ts]
        if not marcas:
            return
        primeiro, ultimo = min(marcas), max(marcas)
        janela = (primeiro - timedelta(minutes=5), ultimo + timedelta(minutes=5))
        for svc in ctx.snap.services:
            for path in svc.resources:
                f = ctx.snap.file_for(path)
                if not f or not f.mtime:
                    continue
                mt = to_naive(parse_dt(f.mtime))
                if not mt or not (janela[0] <= mt <= janela[1]):
                    continue
                proximos = sorted(((abs((to_naive(l.ts) - mt).total_seconds()), l)
                                   for l in ctx.snap.logs if l.ts), key=lambda x: x[0])[:2]
                yield Finding(
                    rule_id=self.id,
                    title=f"{f.path} modificado em {f.mtime}, dentro da janela dos logs",
                    severity=Severity.LOW,
                    category=self.category, correlation=self.correlation,
                    evidence=[
                        ev_file(f, f"'{f.path}' com mtime {f.mtime} e modo {f.mode}"),
                        ev_service(svc, f"'{svc.unit}' ({svc.user}) utiliza '{f.path}'"),
                    ] + [ev_log(l, f"Evento a {int(d)}s da modificacao: {l.message}")
                         for d, l in proximos],
                    interpretation=(
                        f"O recurso usado por '{svc.unit}' foi modificado dentro do "
                        f"intervalo coberto pelos logs ({primeiro} a {ultimo}). "
                        "Proximidade temporal entre alteracao de recurso privilegiado e "
                        "atividade registrada e ponto de partida para a linha do tempo."
                    ),
                    hypothesis=(
                        "Hipotese: atualizacao ou deploy legitimo no periodo. Alternativa: "
                        "alteracao durante a janela investigada. Coincidencia temporal nao "
                        "estabelece causalidade."
                    ),
                    missing_evidence=[
                        f"Quem alterou '{f.path}' (auditd watch, historico de deploy).",
                        "Hash do arquivo antes e depois da janela.",
                    ],
                    false_positives=[
                        "mtime e alteravel com touch e preservado por copia; imagens "
                        "recem-provisionadas concentram mtimes.",
                    ],
                    entities=[f.key, svc.key],
                )


ALL_RULES: List[Rule] = [
    ServicoExecutaRecursoGravavel(), ProcessoExecutaRecursoGravavel(),
    DiretorioGravavelExpoeRecurso(), PermissaoAmplaSemExecucao(),
    BinarioSuidNoContexto(), ArquivoSensivelForaDaBase(),
    TransicaoDePrivilegio(), ShellGeradoPorDaemon(), CadeiaServicoInterpretadorRede(),
    DaemonSemUnidade(), UnidadeSemProcesso(), ExecutavelRemovido(),
    SaidaDeRedePrivilegiada(), ReconstrucaoDeSessao(), RecursoAlteradoNaJanela(),
]
