# Correções na cópia do gerador

**Dupla:** Kauã Figueira Santos · Matheus Constante

O arquivo recebido na disciplina está preservado byte a byte em
[`tools/generate_dataset_original.py`](../tools/generate_dataset_original.py).
As alterações abaixo afetam somente a cópia usada pelo projeto,
[`tools/generate_dataset.py`](../tools/generate_dataset.py).

Cada item foi reproduzido antes de ser corrigido, e cada correção tem um teste
em `tests/` (classe `TestGeradorCorrigido`).

## 1. O cenário aleatório não executava

```
$ python3 tools/generate_dataset.py --level intermediate --seed 11 --output /tmp/x
ValueError: too many values to unpack (expected 5)
```

`random_noise()` parte de `scenario_normal(start)` — que já devolve a **saída**
de `build()`, com processos e permissões convertidos em dicionários e os logs
em pares `(datetime, mensagem)`. Em seguida acrescenta tuplas e deslocamentos em
segundos e chama `build()` outra vez, que tenta desempacotar os dicionários como
tuplas de cinco campos.

**Correção:** desfazer a conversão antes de reaproveitar — dicionários voltam a
tuplas, e os `datetime` voltam a deslocamentos relativos ao início.

**Por que importa:** `random_noise` é um dos sorteios possíveis em
`--level intermediate` e `--level challenge`. Quem gerasse um dataset com uma
seed que caísse nesse ramo recebia apenas o traceback. Enquanto o defeito
existia, nenhum dataset `random` podia ser produzido — e portanto esse cenário
nunca era testado.

## 2. Os CSV ficavam três horas adiantados em relação ao journal

```python
start = datetime(2026, 9, 14, 9, 0, tzinfo=timezone.utc)   # 09:00 UTC
def iso(dt):  return dt.strftime("%Y-%m-%dT%H:%M:%S-03:00")  # rótulo fixo
```

`iso()` escrevia o deslocamento `-03:00` como texto, sem converter a hora. O
`processes.csv` então declarava `2026-09-14T09:00:00-03:00` para um instante que
era 09:00 **UTC** — ou seja, 06:00 em -03:00. O `journal.log`, por sua vez,
escreve o mesmo instante com `strftime("%b %d %H:%M:%S")`, sem fuso, resultando
em `Sep 14 09:00:00`. As duas fontes descreviam o mesmo momento com três horas
de diferença.

**Correção:** tornar o horário-base local (sem `tzinfo`). O rótulo `-03:00`
passa a ser verdadeiro e os dois artefatos voltam a concordar. O conteúdo
textual dos cenários fixos não muda: `iso()` imprime exatamente a mesma string.

**Por que importa:** a ferramenta correlaciona `mtime` de arquivos com a janela
coberta pelos logs (regra EI-R011). Com as fontes desalinhadas, uma correlação
temporal legítima poderia ser descartada — ou inventada.

## 3. O cenário `permission` se identificava como `normal`

`scenario_permission()` parte de `scenario_normal()` e acrescenta um arquivo
`0777`, mas não trocava o campo `kind`. O `metadata.json` gerado dizia
`"scenario": "normal"`.

**Correção:** definir `kind = "permission"`.

**Observação:** isso é um rótulo didático. O motor de análise **não lê**
`metadata.json` nem `README.txt` — os achados vêm apenas dos quatro artefatos
observacionais. A correção serve a quem organiza os datasets, não à análise.

## 4. Escolha explícita de cenário

Acrescentado `--scenario {normal,permission,privileged_service,correlation,ambiguous,random}`,
com precedência sobre `--level`. `--level` e `--batch` continuam funcionando
como antes.

**Por que importa:** o sorteio por seed não garante que um cenário apareça.
Para reproduzir um resultado numa apresentação, ou para montar um conjunto de
testes que cubra os seis casos, é preciso pedir o cenário pelo nome.
`tools/gerar_datasets.sh` usa essa opção.

---

## O que não foi alterado

- Os dados observacionais dos cinco cenários fixos.
- A ausência de ano e fuso no `journal.log`. A ferramenta preserva essa
  incerteza em vez de preencher por adivinhação.
- O fato de `metadata.json` e `README.txt` conterem as respostas didáticas.
  Eles continuam no dataset e continuam **ignorados** pelo motor.
