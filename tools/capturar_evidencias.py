#!/usr/bin/env python3
"""Gera os prints de execucao da ferramenta.

Cada print e a saida REAL de um comando: executado em um pty (para preservar as
cores ANSI), renderizado como janela de terminal e fotografado com Chrome em
modo headless. As faixas do relatorio HTML sao recortadas com um iframe
deslocado, para nao rasterizar a pagina inteira.

Uso:  python3 tools/capturar_evidencias.py [DIRETORIO_DE_SAIDA]
"""
from __future__ import annotations

import html
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image, ImageChops

RAIZ = Path(__file__).resolve().parent.parent
SAIDA = Path(sys.argv[1]) if len(sys.argv) > 1 else RAIZ / "evidencias"
EI = "python3 -m endpoint_investigator"
DS_CORR = "datasets/04-correlacao"

SGR = re.compile(r"\x1b\[([0-9;]*)m")
# Remove controle que NAO e cor: o 'm' final fica de fora de proposito.
OUTRO = re.compile(r"\x1b\[[0-9;?]*[a-ln-zA-Z]|\x1b\][^\x07]*\x07|\x1b[=>]|\r")
FG = {30: "#3b4252", 31: "#ff6b6b", 32: "#3ecf8e", 33: "#ffc857", 34: "#5ec8ff",
      35: "#c792ea", 36: "#5ee0d0", 37: "#d8dee9", 90: "#7d8ea3", 91: "#ff8a8a",
      92: "#6ee7a8", 93: "#ffd68a", 94: "#8ad6ff", 95: "#dbb0ff", 96: "#8ae8dc",
      97: "#f2f6fb"}
BG = {41: "#8c2b2b", 42: "#1f5c42", 43: "#6b5410", 44: "#1d4c6b", 45: "#4c2b63",
      46: "#1f5c58", 47: "#2b3440"}

PAGINA = """<!doctype html><html><head><meta charset="utf-8"><title>{t}</title><style>
body{{margin:0;background:#0b0f14;font-family:ui-sans-serif,system-ui,sans-serif}}
.bar{{display:flex;align-items:center;gap:8px;padding:9px 14px;background:#151b24;
border-bottom:1px solid #1e2836}}
.d{{width:11px;height:11px;border-radius:50%}}
.ttl{{margin-left:8px;color:#8ea3bb;font-size:12.5px;font-family:ui-monospace,monospace}}
pre{{margin:0;padding:16px 18px;color:#d8dee9;background:#0d1219;font-size:{fs}px;
font-family:ui-monospace,"JetBrains Mono",Menlo,Consolas,monospace;line-height:1.485;
white-space:pre;overflow-x:auto}}
.cmd{{color:#3ecf8e;font-weight:700}}.pr{{color:#5ec8ff;font-weight:700}}
</style></head><body><div class="bar"><span class="d" style="background:#ff5f56"></span>
<span class="d" style="background:#ffbd2e"></span><span class="d" style="background:#27c93f">
</span><span class="ttl">{t}</span></div>
<pre><span class="pr">$</span> <span class="cmd">{c}</span>
{b}</pre></body></html>"""

MOLDURA = """<!doctype html><html><head><meta charset="utf-8"><style>
html,body{{margin:0;overflow:hidden;background:#0f1319}}
iframe{{position:absolute;top:-{off}px;left:0;width:{w}px;height:{full}px;border:0}}
</style></head><body><iframe src="{url}" scrolling="no"></iframe></body></html>"""


def ansi_para_html(bruto: str) -> str:
    saida, fg, bg, neg, fraco, ital, pos = [], None, None, False, False, False, 0

    def estilo() -> str:
        p = []
        if fg: p.append(f"color:{fg}")
        if bg: p.append(f"background:{bg};padding:0 2px")
        if neg: p.append("font-weight:700")
        if fraco: p.append("opacity:.66")
        if ital: p.append("font-style:italic")
        return ";".join(p)

    def emitir(txt: str) -> None:
        if not txt:
            return
        e = estilo()
        saida.append(f'<span style="{e}">{html.escape(txt)}</span>' if e
                     else html.escape(txt))

    for m in SGR.finditer(bruto):
        emitir(bruto[pos:m.start()])
        pos = m.end()
        for c in [int(x) for x in (m.group(1) or "0").split(";") if x != ""] or [0]:
            if c == 0: fg = bg = None; neg = fraco = ital = False
            elif c == 1: neg = True
            elif c == 2: fraco = True
            elif c == 3: ital = True
            elif c == 22: neg = fraco = False
            elif c == 23: ital = False
            elif c == 39: fg = None
            elif c == 49: bg = None
            elif c in FG: fg = FG[c]
            elif c in BG: bg = BG[c]
    emitir(bruto[pos:])
    return "".join(saida)


def fotografar(url: str, destino: Path, largura: int, altura: int,
               recortar: bool = True) -> None:
    fd, png = tempfile.mkstemp(suffix=".png"); os.close(fd)
    perfil = tempfile.mkdtemp(prefix="ei-shot-")
    subprocess.run(
        ["google-chrome", "--headless=new", "--disable-gpu", "--hide-scrollbars",
         "--no-first-run", "--disable-extensions", "--allow-file-access-from-files",
         f"--user-data-dir={perfil}", "--virtual-time-budget=4000",
         "--force-device-scale-factor=2", f"--window-size={largura},{altura}",
         f"--screenshot={png}", url],
        capture_output=True, timeout=180)
    im = Image.open(png).convert("RGB")
    if recortar:
        # A cor de fundo e estimada em dois cantos; vale a que revelar mais.
        melhor = 0
        for canto in ((im.width - 4, im.height - 4), (4, im.height - 4)):
            caixa = ImageChops.difference(
                im, Image.new("RGB", im.size, im.getpixel(canto))).getbbox()
            if caixa:
                melhor = max(melhor, caixa[3])
        if melhor > im.height * 0.12:
            im = im.crop((0, 0, im.width, min(im.height, melhor + 48)))
    destino.parent.mkdir(parents=True, exist_ok=True)
    im.save(destino, optimize=True)
    os.unlink(png)
    subprocess.run(["rm", "-rf", perfil], capture_output=True)
    print(f"  {destino.name}  {im.width}x{im.height}")


def terminal(n: str, slug: str, titulo: str, comando: str, fs: float = 12.5) -> None:
    amb = dict(os.environ, TERM="xterm-256color", COLUMNS="150", LINES="200")
    r = subprocess.run(["script", "-qec", comando, "/dev/null"],
                       capture_output=True, env=amb, cwd=RAIZ)
    bruto = OUTRO.sub("", (r.stdout + r.stderr).decode("utf-8", "replace"))
    limpo = [OUTRO.sub("", SGR.sub("", l)) for l in bruto.splitlines()]
    altura = min(int((len(limpo) + 2) * fs * 1.485 + 102), 6200)
    largura = min(max(int(max((len(l) for l in limpo), default=80) * fs * 0.607 + 42),
                      900), 1700)
    tmp = Path(tempfile.mkstemp(suffix=".html")[1])
    tmp.write_text(PAGINA.format(t=html.escape(titulo), c=html.escape(comando),
                                 b=ansi_para_html(bruto), fs=fs), encoding="utf-8")
    fotografar(tmp.as_uri(), SAIDA / f"{n}-{slug}.png", largura, altura)
    tmp.unlink(missing_ok=True)


def medir(pagina: Path, alvo: str | None = None) -> int:
    """Altura da pagina, ou deslocamento de uma secao, com 1320px de largura."""
    js = f'"{alvo}"' if alvo else "null"
    doc = f"""<!doctype html><html><body><div id="r">?</div>
<iframe id="f" src="{pagina.resolve().as_uri()}" style="width:1320px;height:600px;
border:0"></iframe><script>document.getElementById('f').addEventListener('load',
function(){{var d=this.contentDocument,a={js},v=a?(d.getElementById(a)?
Math.round(d.getElementById(a).getBoundingClientRect().top):0):
d.documentElement.scrollHeight;document.getElementById('r').textContent='V='+v;}});
</script></body></html>"""
    tmp = Path(tempfile.mkstemp(suffix=".html")[1]); tmp.write_text(doc, encoding="utf-8")
    perfil = tempfile.mkdtemp(prefix="ei-medida-")
    r = subprocess.run(
        ["google-chrome", "--headless=new", "--disable-gpu", "--no-first-run",
         "--allow-file-access-from-files", f"--user-data-dir={perfil}",
         "--virtual-time-budget=4000", "--window-size=1340,700", "--dump-dom",
         tmp.as_uri()], capture_output=True, text=True, timeout=120)
    tmp.unlink(missing_ok=True)
    subprocess.run(["rm", "-rf", perfil], capture_output=True)
    m = re.search(r"V=(\d+)", r.stdout or "")
    return int(m.group(1)) if m else 0


def faixa(n: str, slug: str, relatorio: Path, full: int, off: int, alt: int) -> None:
    tmp = Path(tempfile.mkstemp(suffix=".html")[1])
    tmp.write_text(MOLDURA.format(url=relatorio.resolve().as_uri(), w=1320,
                                  full=full, off=off), encoding="utf-8")
    fotografar(tmp.as_uri(), SAIDA / f"{n}-{slug}.png", 1320, alt, recortar=False)
    tmp.unlink(missing_ok=True)


PRINTS = [
    ("01", "catalogo-de-regras",
     "as 15 regras de correlacao e as dimensoes que cada uma cruza",
     f"{EI} --list-rules", 12),
    ("02", "arquitetura-do-projeto", "estrutura do projeto: uma camada por etapa",
     "find endpoint_investigator tools tests docs -maxdepth 2 "
     "-not -path '*__pycache__*' | sort", 12.5),
    ("03", "pipeline-sobre-dataset-de-correlacao",
     "pipeline completo: evidencia, interpretacao, hipotese e evidencia ausente",
     f"{EI} --dataset datasets/04-correlacao --min-severity alta", 12.5),
    ("04", "cenario-normal-sem-alarme",
     "cenario normal: a ferramenta nao inventa risco onde nao ha correlacao",
     f"{EI} --dataset datasets/01-normal", 12.5),
    ("05", "servico-root-nao-e-vulnerabilidade",
     "servico root com script 0700: nenhum achado alto",
     f"{EI} --dataset datasets/03-servico-root", 12.5),
    ("06", "configuracao-inadequada-vs-privilegio",
     "EI-R04 - permissao ampla SEM relacao de execucao observada",
     f"{EI} --dataset datasets/02-permissao-ampla --rule EI-R04", 12.5),
    ("07", "processo-ppid-usuario",
     "correlacao processo + PPID + usuario e a cadeia reconstruida",
     f"{EI} --dataset datasets/04-correlacao --rule EI-R02", 12.5),
    ("08", "reconstrucao-temporal-de-sessao",
     "correlacao processo + servico + log: o que a sessao fez apos o login",
     f"{EI} --dataset datasets/04-correlacao --rule EI-R14", 12.5),
    ("09", "cenario-ambiguo-sem-diagnostico",
     "saida de rede de agente root: contexto, nao diagnostico de malware",
     f"{EI} --dataset datasets/05-ambiguo --rule EI-R13", 12.5),
    ("10", "coleta-ao-vivo-maquina-real",
     "coleta ao vivo (/proc, systemctl, lstat, journalctl) detectando o cenario de laboratorio",
     f"{EI} --live --rule EI-R02 --rule EI-R04", 12.5),
    ("11", "laboratorio-controlado",
     "cenario controlado na propria maquina, sem root e reversivel",
     "tools/lab_scenario.sh status", 13),
    ("12", "suite-de-testes", "36 testes, apenas unittest da biblioteca padrao",
     "python3 -m unittest discover -s tests -v 2>&1 | tail -46", 11),
    ("13", "cobertura-e-limitacoes",
     "cobertura das regras, notas da coleta e limitacoes declaradas do escopo",
     f"{EI} --dataset datasets/06-gerador-aleatorio --min-severity alta", 12.5),
]


def main() -> None:
    os.chdir(RAIZ)
    SAIDA.mkdir(parents=True, exist_ok=True)
    print("== gerando relatorios ==")
    subprocess.run(["python3", "-m", "endpoint_investigator", "--dataset", DS_CORR,
                    "--out", "out/04-correlacao", "--all-formats", "--quiet"],
                   check=False)

    print("== prints de terminal ==")
    for n, slug, titulo, cmd, fs in PRINTS:
        terminal(n, slug, titulo, cmd, fs)

    print("== faixas do relatorio HTML ==")
    rel = RAIZ / "out/04-correlacao/report.html"
    full = medir(rel)
    for n, slug, off, alt in (
            ("14", "relatorio-html-topo", 0, 1120),
            ("15", "relatorio-html-achado", 860, 1400),
            ("16", "relatorio-html-linha-do-tempo", medir(rel, "sec-linha-do-tempo") - 20, 1060),
            ("17", "relatorio-html-cobertura", medir(rel, "sec-cobertura") - 20, 1200)):
        faixa(n, slug, rel, full, off, alt)

    print(f"\nevidencias em: {SAIDA}")


if __name__ == "__main__":
    main()
