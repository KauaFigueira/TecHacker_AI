# Endpoint Investigator

**Avaliação Intermediária — Tecnologias Hackers**  
**Dupla:** Kauã Figueira Santos · Matheus Constante  
**Professor:** Dr. Rodolfo Avelino · Insper — Engenharia de Computação

Ferramenta de investigação de segurança para endpoints GNU/Linux. Coleta,
normaliza e **correlaciona** processos, permissões e serviços — somadas aos logs
do sistema, usados na reconstrução temporal — e apresenta o resultado sempre
separado em **evidência**, **interpretação**, **hipótese** e **evidência ausente**.

> A ferramenta não é um antivírus nem um EDR. Ela não conclui que houve
> comprometimento: produz evidências estruturadas e hipóteses para que um
> analista decida. Todo achado carrega `exploracao_comprovada: false`.

---

## Entregáveis

| Entregável do enunciado | Onde está |
|---|---|
| **Código-fonte completo da solução** | [`endpoint_investigator/`](endpoint_investigator/) — 15 regras de correlação, apenas biblioteca padrão |
| **README** com arquitetura, dependências, instalação, execução, fontes de informação, correlações implementadas e limitações | este arquivo, seções 1 a 9 |
| **Documento técnico** de até quatro páginas | [`docs/documento-tecnico.pdf`](docs/documento-tecnico.pdf) — 4 páginas · [fonte em Markdown](docs/documento-tecnico.md) |
| **Demonstração prática** sobre dataset e ambiente de teste | [`evidencias/`](evidencias/) — 17 capturas de execução real, índice em [`EVIDENCIAS.md`](evidencias/EVIDENCIAS.md) · exemplo de saída nos três formatos em [`docs/exemplo-de-saida/`](docs/exemplo-de-saida/) |

### Demonstração rápida

```bash
python3 -m endpoint_investigator --list-rules                       # as 15 regras e o que cada uma cruza
python3 -m endpoint_investigator --dataset datasets/04-correlacao   # achado ALTA, risco 86
python3 -m endpoint_investigator --dataset datasets/01-normal       # máquina normal: nenhum achado alto
python3 -m endpoint_investigator --live                             # snapshot desta máquina
python3 -m unittest discover -s tests                               # 36 testes
```

---

## 1. Arquitetura e pipeline

```
COLETA  →  NORMALIZAÇÃO  →  CORRELAÇÃO  →  EVIDÊNCIAS  →  HIPÓTESES  →  RESULTADO
  (1)          (2)              (3)            (4)           (5)          (6)
```

| # | Camada | Módulo | O que faz |
|---|--------|--------|-----------|
| 1 | Coleta | `collectors/` | `/proc`, `systemctl`, `lstat`, `journalctl` — ou os artefatos de um dataset |
| 2 | Normalização | `normalize.py` | Modos octais → flags; cmdline → argv, interpretador e script; linha de log → registro; endereço → alcance |
| 3 | Correlação | `graph.py` | Grafo dirigido de entidades e relações entre as dimensões |
| 4 | Evidências | `correlation/` | 15 regras determinísticas consultam o grafo |
| 5 | Hipóteses | `scoring.py`, `timeline.py` | Confiança e risco por corroboração; linha do tempo unificada |
| 6 | Resultado | `reporting/` | Console, JSON e HTML |

**Proveniência.** Toda entidade carrega um `SourceRef`
(`coletor::artefato:localizador`), propagado a cada item de evidência. Qualquer
linha do relatório pode ser reconferida na fonte: `dataset::permissions.csv:linha 3`,
`live-linux::/proc/2417`.

**Sobre IA.** A ferramenta **não incorpora modelo de linguagem**: toda a análise
é determinística, feita por regras próprias sobre o grafo de correlação. O uso de
IA no desenvolvimento está declarado no documento técnico.

---

## 2. Instalação e dependências

**Apenas a biblioteca padrão do Python 3.10+.** Não há dependências a instalar.

```bash
cd endpoint-investigator
python3 -m endpoint_investigator --help
```

Ferramentas do sistema usadas na coleta ao vivo — todas opcionais, a análise
degrada de forma controlada e declara o que faltou: `systemctl`, `journalctl`.

---

## 3. Execução

```bash
# Snapshot da própria máquina
python3 -m endpoint_investigator --live

# Dataset de teste
python3 -m endpoint_investigator --dataset datasets/04-correlacao

# Relatórios em arquivo (json + html + txt)
python3 -m endpoint_investigator --dataset datasets/04-correlacao \
    --out saida --all-formats

# Catálogo das 15 regras, com a correlação que cada uma aplica
python3 -m endpoint_investigator --list-rules

# Um achado específico
python3 -m endpoint_investigator --dataset datasets/04-correlacao --rule EI-R01

# Código de saída 1 se houver achado >= alta
python3 -m endpoint_investigator --live --quiet --fail-on alta
```

Outras opções: `--min-severity`, `--verbose` (mostra o dado bruto de cada
evidência), `--path CAMINHO` (acrescenta caminhos à coleta de permissões),
`--log-window MIN`, `--no-color`.

---

## 4. Fontes de informação

| Dimensão | Ao vivo | Dataset |
|---|---|---|
| **Processos** (obrigatória) | `/proc/<pid>/{status,cmdline,exe,cwd,stat}` | `processes.csv` |
| **Permissões** (obrigatória) | `os.lstat`, orientado por contexto | `permissions.csv` |
| **Serviços** (obrigatória) | `systemctl list-units` + `systemctl show` | `services.txt` |
| Logs do sistema | `journalctl`, ou `/var/log/syslog` | `journal.log` |

Os logs entram porque a quarta correlação citada no enunciado é
*"processo + serviço + log → reconstrução temporal"*.

**A coleta de permissões é orientada por contexto, não por varredura do
filesystem.** São inspecionados: (a) os recursos citados por processos e
serviços; (b) os diretórios-pai, que permitem substituí-los; (c) os vizinhos do
mesmo diretório — mesma zona de confiança —, excluindo diretórios de sistema de
grande volume; (d) uma linha de base curta de arquivos sensíveis; (e) o alvo
real de cada link simbólico.

**Identidades** (`usuário`) são derivadas dos próprios processos e serviços — é o
campo observado no snapshot, não um inventário de contas do sistema.

---

## 5. Correlações implementadas

O enunciado exige **pelo menos duas**. São **15 regras**, todas cruzando no
mínimo duas dimensões. As quatro correlações citadas no enunciado estão
cobertas:

| Correlação do enunciado | Regras |
|---|---|
| Processo + serviço + permissão → hipótese de risco | EI-R01, EI-R02 |
| Processo + PPID + usuário → contexto de execução | EI-R07, EI-R08 |
| Serviço + arquivo + usuário → relação de privilégio | EI-R01, EI-R03 |
| Processo + serviço + log → reconstrução temporal | EI-R14, EI-R15 |

### Catálogo

| ID | Correlação | O que identifica |
|---|---|---|
| EI-R01 | serviço + permissão + usuário | Serviço executa recurso alterável por outra identidade |
| EI-R02 | processo + permissão + usuário | Processo executa recurso alterável por outra identidade |
| EI-R03 | serviço + permissão (diretório) + usuário | Recurso protegido dentro de diretório gravável |
| EI-R04 | permissão + **ausência** de vínculo com execução | Permissão ampla **sem** relação de privilégio demonstrada |
| EI-R05 | permissão + processo/serviço | Binário SUID/SGID no contexto analisado |
| EI-R06 | permissão + identidade (linha de base) | Arquivo sensível fora do modo esperado |
| EI-R07 | processo + PPID + usuário | Transição de privilégio na árvore de processos |
| EI-R08 | processo + PPID + serviço | Shell gerado por daemon que não costuma gerar shells |
| EI-R09 | serviço + processo + PPID | Cadeia serviço → interpretador → ferramenta de rede |
| EI-R10 | processo + serviço + usuário | Daemon privilegiado sem unidade correspondente |
| EI-R11 | serviço + processo | Unidade ativa sem processo, ou processo divergente do `ExecStart` |
| EI-R12 | processo + arquivo (inode removido) | Executável apagado com processo vivo |
| EI-R13 | processo + usuário + serviço/log | Saída de rede a partir de contexto privilegiado |
| EI-R14 | log + processo + usuário | Reconstrução temporal de sessão remota |
| EI-R15 | permissão (mtime) + log + serviço | Recurso alterado dentro da janela dos logs |

### Uma regra que existe para *não* exagerar

**EI-R04** é a contrapartida de EI-R01: um arquivo `0777` que ninguém executa é
relatado em BAIXA, dizendo explicitamente que falta o elo *"identidade
privilegiada executa o recurso"*. É a diferença entre **configuração inadequada**
e **relação de privilégio observada**.

### Como a confiança é calculada

Confiança é função da corroboração (`scoring.py`), não de opinião:

| Dimensões distintas na evidência | Confiança |
|---|---|
| 1 | baixa |
| 2 | média |
| ≥ 3 | alta |

Uma única fonte de dados rebaixa a confiança mesmo com várias dimensões. O risco
(0–100) combina a severidade base com esse fator, mais um acréscimo quando há
cadeia de privilégio explicitamente reconstruída.

---

## 6. Estrutura do projeto

```
endpoint_investigator/
├── model.py          Entidades canônicas, Finding, EvidenceBundle, SourceRef
├── normalize.py      Camada 2 — padronização e derivação de campos
├── graph.py          Camada 3 — grafo de entidades e relações
├── scoring.py        Confiança e risco determinísticos
├── timeline.py       Linha do tempo unificada
├── pipeline.py       Orquestração das camadas 1–5
├── cli.py            Interface de linha de comando
├── collectors/       Camada 1 — live-linux e dataset
├── correlation/      Camadas 3–5 — motor e as 15 regras
└── reporting/        Camada 6 — console, json, html
tools/
├── generate_dataset.py            cópia adaptada do gerador da disciplina
├── generate_dataset_original.py   o arquivo recebido, preservado byte a byte
├── gerar_datasets.sh              regenera os 6 datasets
├── lab_scenario.sh                cenário controlado reversível na própria máquina
└── capturar_evidencias.py         gera os prints da demonstração
datasets/             6 datasets dos cenários do gerador
docs/                 documento técnico, correções no gerador e exemplo de saída
evidencias/           17 capturas da demonstração prática
tests/                36 testes, apenas unittest
```

---

## 7. Testes

```bash
python3 -m unittest discover -s tests -v
```

36 testes cobrindo normalização, proveniência de toda evidência, casamento
serviço↔processo, as quatro correlações do enunciado, ausência de falso positivo
em cenário normal, os quatro elementos em todo achado, cálculo de confiança e as
correções feitas no gerador.

### Cenário controlado na própria máquina

O enunciado prevê usar a própria VM para criar situações controladas:

```bash
tools/lab_scenario.sh setup       # lab/agent.sh (0777) + unidade systemd --user
python3 -m endpoint_investigator --live
tools/lab_scenario.sh teardown    # remove tudo
```

Sem root, sem tráfego de rede, sem tocar em nada fora do projeto e de
`~/.config/systemd/user`.

---

## 8. Escopo e limitações

**Dentro do escopo:** relações entre processos, identidades, permissões,
serviços e logs do sistema, em um snapshot pontual.

**Fora do escopo — declarado em todo relatório gerado:**

1. Snapshot pontual: o que ocorreu antes ou depois da coleta não é observado, e
   PIDs podem ser reaproveitados.
2. Não há inspeção de conteúdo de arquivo nem análise de binário.
3. Conexões de rede, contas do sistema e arquivos abertos **não são coletados** —
   uma URL em linha de comando não prova que houve conexão.
4. ACLs POSIX estendidas, atributos, *capabilities* e MAC (SELinux/AppArmor) não
   são lidos: um recurso pode estar mais protegido que o modo octal sugere.
5. Sem root, `cmdline` e executável de processos de outros usuários ficam
   incompletos — registrado nas notas da coleta.
6. Namespaces de containers não são percorridos.
7. A ferramenta não conclui a existência de comprometimento.

### Falsos positivos conhecidos

| Situação | Por quê | Como a ferramenta lida |
|---|---|---|
| Binários SUID de sistema (`sudo`, `passwd`) | Esperados em qualquer instalação | EI-R05 declara no bloco de falso positivo e não eleva sem outro fator |
| Serviços `Type=oneshot` | Terminam e ficam sem processo | EI-R11 emite BAIXA com a hipótese mais provável primeiro |
| Wrapper de inicialização (`apachectl` → `apache2`) | `ExecStart` difere do processo real | EI-R11 emite INFO e explica o padrão |
| Agentes de telemetria/backup | Invocam `curl` como root | EI-R13 recusa explicitamente rotular como C2 ou malware |
| Executável removido após `apt upgrade` | Padrão normal de atualização | EI-R12 agrupa por binário e emite BAIXA quando não é privilegiado |
| App desktop gerando shell | Terminais e IDEs fazem isso | EI-R08 cai para BAIXA quando pai e filho são do mesmo usuário não privilegiado |
| `mtime` recente | Trivialmente alterável com `touch` | EI-R15 declara e mantém BAIXA |
| Permissão ampla sem execução | Não há relação de privilégio | EI-R04 existe para esse caso, em BAIXA |

---

## 9. Saídas

| Arquivo | Uso |
|---|---|
| `report.json` | Bundle estruturado (`ei-evidence-bundle/1.0`) — troca e integração |
| `report.html` | Relatório navegável para anexar ao caso |
| `report.txt` | Saída de console completa, sem cores |

Um exemplo completo dos três formatos, gerado sobre `datasets/04-correlacao`, está
versionado em [`docs/exemplo-de-saida/`](docs/exemplo-de-saida/).

Códigos de saída: `0` normal, `1` com `--fail-on` atingido, `2` erro.
