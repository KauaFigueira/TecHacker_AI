# Evidências de execução — Endpoint Investigator

**Dupla:** Kauã Figueira Santos · Matheus Constante

Demonstração prática da solução funcionando sobre os datasets de teste e sobre
uma máquina Linux real. Cada imagem é a **saída real** de um comando, capturada
em um pty (para preservar as cores do terminal) e fotografada com Chrome
headless.

**Reprodução:**

```bash
cd endpoint-investigator
tools/lab_scenario.sh setup        # monta o cenário controlado (prints 10 e 11)
python3 tools/capturar_evidencias.py
tools/lab_scenario.sh teardown     # desfaz o cenário
```

Os números dos prints 10 e 11 variam a cada execução: são o estado real da
máquina no momento da coleta.

| # | Arquivo | O que comprova |
|---|---------|----------------|
| 01 | `01-catalogo-de-regras.png` | As **15 regras** e as dimensões que cada uma cruza. O enunciado exige pelo menos duas formas de correlação. |
| 02 | `02-arquitetura-do-projeto.png` | Estrutura do código: uma camada por etapa do pipeline (coletores, normalização, grafo, correlação, relatórios). |
| 03 | `03-pipeline-sobre-dataset-de-correlacao.png` | Pipeline completo `COLETA → NORMALIZAÇÃO → CORRELAÇÃO → EVIDÊNCIAS → HIPÓTESES → RESULTADO`. O achado EI-R01 mostra **evidência** (3 fontes rastreáveis, com arquivo e linha), **interpretação**, **hipótese**, **cadeia reconstruída** e **evidência ausente**. |
| 04 | `04-cenario-normal-sem-alarme.png` | Cenário normal: nenhum achado de severidade alta. A ferramenta não inventa risco onde não há correlação. |
| 05 | `05-servico-root-nao-e-vulnerabilidade.png` | Serviço rodando como root com script `0700`: **nenhum achado alto**. O enunciado é explícito — serviço root não é automaticamente vulnerável. |
| 06 | `06-configuracao-inadequada-vs-privilegio.png` | **EI-R04.** Um arquivo `0777` que ninguém executa sai em BAIXA, dizendo que falta o elo "identidade privilegiada executa o recurso". É a diferença entre configuração inadequada e relação de privilégio demonstrada. |
| 07 | `07-processo-ppid-usuario.png` | Correlação **processo + permissão + usuário** com a cadeia reconstruída e os processos pai. |
| 08 | `08-reconstrucao-temporal-de-sessao.png` | Correlação **processo + serviço + log**: o registro de autenticação costurado com o inventário de processos reconstrói o que a sessão fez após o login. |
| 09 | `09-cenario-ambiguo-sem-diagnostico.png` | Saída de rede de um agente root: a ferramenta apresenta o **contexto** e recusa explicitamente rotular como C2 ou malware. |
| 10 | `10-coleta-ao-vivo-maquina-real.png` | **Coleta ao vivo em máquina Linux real:** processos via `/proc`, permissões via `lstat` orientado por contexto, unidades via `systemctl`, logs via `journalctl`. Grafo com milhares de relações. A ferramenta encontra o `agent.sh` do laboratório em MÉDIA (EI-R02) e separa dele o `report.sh`, que é world-writable mas ninguém executa, em BAIXA (EI-R04). |
| 11 | `11-laboratorio-controlado.png` | Cenário controlado montado na própria máquina, sem root e reversível — como o enunciado prevê nos testes locais. |
| 12 | `12-suite-de-testes.png` | 36 testes passando, apenas `unittest` da biblioteca padrão. |
| 13 | `13-cobertura-e-limitacoes.png` | Cobertura das regras (quais rodaram, quais foram puladas e por quê), notas da coleta e **limitações declaradas do escopo**. |
| 14 | `14-relatorio-html-topo.png` | Relatório HTML: cabeçalho, inventário coletado, grafo de correlação e resumo por severidade. |
| 15 | `15-relatorio-html-achado.png` | Card de um achado no HTML: os quatro elementos separados por cor, cada evidência com a fonte e o dado bruto para reconferência. |
| 16 | `16-relatorio-html-linha-do-tempo.png` | Linha do tempo correlacionada: logs, criação de processos e `mtime` de recursos privilegiados em sequência única. |
| 17 | `17-relatorio-html-cobertura.png` | Cobertura, notas da coleta e limitações no relatório HTML. |

---

## Como os prints foram gerados

Tudo em um único script, `tools/capturar_evidencias.py`:

1. O comando roda dentro de `script -qec`, que aloca um pty — a ferramenta
   detecta um terminal e emite as cores normalmente.
2. A saída ANSI vira HTML preservando cor, negrito e itálico, com a altura da
   janela calculada pelo número de linhas.
3. Chrome headless fotografa a página com um perfil descartável, sem tocar no
   perfil real do navegador.
4. As faixas do relatório HTML são medidas e recortadas com um iframe deslocado,
   para não rasterizar a página inteira.

Nada nas imagens foi editado ou montado.
