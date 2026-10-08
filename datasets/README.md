# Datasets de teste

Gerados com cenário escolhido **por nome** (`--scenario`) e seed fixa, para que
os resultados sejam reproduzíveis — o sorteio por seed não garante que um
cenário específico apareça.

Regenerar tudo: `tools/gerar_datasets.sh`

| Diretório | Cenário | O que exercita |
|---|---|---|
| `01-normal` | normal, seed 1 | Linha de base: host saudável. **Nenhum achado alto deve aparecer.** |
| `02-permissao-ampla` | permission, seed 2 | `/opt/reports/report.sh` em `0777` que **ninguém executa** → EI-R04 em BAIXA |
| `03-servico-root` | privileged_service, seed 1 | Serviço root com script `0700` → root **não** vira achado sozinho |
| `04-correlacao` | correlation, seed 5 | Serviço root + script `0777` → EI-R01 em ALTA, com a cadeia reconstruída |
| `05-ambiguo` | ambiguous, seed 7 | Agente root com saída de rede → EI-R13, explicitamente **não** rotulado como C2 |
| `06-gerador-aleatorio` | random, seed 42 | O cenário aleatório do gerador. Só é alcançável depois da correção em `random_noise()` — veja [`docs/correcoes-no-gerador.md`](../docs/correcoes-no-gerador.md). Com seed 42 o script sai com modo `0750`, então **nenhum achado alto**: serve de controle negativo. |

Cada dataset traz os quatro artefatos observacionais (`processes.csv`,
`permissions.csv`, `services.txt`, `journal.log`) mais `metadata.json` e
`README.txt`. **O motor não lê os dois últimos**: os achados vêm apenas dos
artefatos observacionais, nunca das respostas didáticas do gerador. Há um teste
que verifica isso.

Todos os dados são sintéticos e não representam um incidente real.
