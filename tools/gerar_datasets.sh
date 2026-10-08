#!/usr/bin/env bash
# Regenera os datasets de teste. Resultado reproduzível.
#
# Os cenários são escolhidos por nome (--scenario), e não por sorteio de seed:
# o sorteio não garante que um cenário específico apareça, o que atrapalha
# reproduzir um resultado. Veja docs/correcoes-no-gerador.md.

set -eu
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
G="python3 tools/generate_dataset.py"
rm -rf datasets && mkdir -p datasets

$G --level basic        --scenario normal             --seed 1  --output datasets/01-normal              >/dev/null
$G --level intermediate --scenario permission         --seed 2  --output datasets/02-permissao-ampla     >/dev/null
$G --level intermediate --scenario privileged_service --seed 1  --output datasets/03-servico-root        >/dev/null
$G --level intermediate --scenario correlation        --seed 5  --output datasets/04-correlacao          >/dev/null
$G --level challenge    --scenario ambiguous          --seed 7  --output datasets/05-ambiguo             >/dev/null
# O cenário aleatório do gerador: só é alcançável depois da correção em
# random_noise(). A seed fixa mantém o resultado reproduzível.
$G --level intermediate --scenario random             --seed 42 --output datasets/06-gerador-aleatorio   >/dev/null

for d in datasets/*/; do
  printf '  %-26s %s\n' "$(basename "$d")" \
    "$(python3 -c "import json;m=json.load(open('$d/metadata.json'));print(m['level'],'/',m['scenario'])")"
done
