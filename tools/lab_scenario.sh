#!/usr/bin/env bash
# Ambiente controlado de validacao do Endpoint Investigator.
#
# O enunciado autoriza criar situacoes controladas na propria maquina para
# testar a LOGICA da ferramenta - nao para produzir um incidente real. Este
# script monta um cenario totalmente reversivel, SEM privilegio de root, SEM
# trafego de rede e SEM tocar em nada fora do diretorio do projeto e da pasta
# de unidades systemd do proprio usuario.
#
# O que e criado:
#   lab/agent.sh                              script com modo 0777 (world-writable)
#   lab/report.sh                             script 0777 que NINGUEM executa
#   ~/.config/systemd/user/ei-lab-agent.service  unidade de usuario que roda agent.sh
#
# O que se espera que a ferramenta detecte:
#   EI-R02   o processo da unidade executa um recurso que qualquer usuario local
#            pode alterar. A deteccao sai em EI-R02 (processo + permissao +
#            usuario) e nao em EI-R01 (servico + permissao + usuario) porque o
#            coletor lista unidades de sistema ('systemctl list-units') e esta e
#            uma unidade de usuario: a relacao observada e com o processo.
#   EI-R04   report.sh e world-writable, porem sem relacao de execucao observada
#            (configuracao inadequada != relacao de privilegio demonstrada)
#
# Uso:  tools/lab_scenario.sh setup | status | teardown

set -u

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_DIR="$PROJECT_DIR/lab"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
UNIT_NAME="ei-lab-agent.service"
UNIT_PATH="$UNIT_DIR/$UNIT_NAME"

say() { printf '  %s\n' "$*"; }

setup() {
  echo "[lab] montando cenario controlado"
  mkdir -p "$LAB_DIR" "$UNIT_DIR"

  cat > "$LAB_DIR/agent.sh" <<'EOS'
#!/bin/bash
# Cenario de laboratorio do Endpoint Investigator.
# Nao faz nada alem de permanecer vivo: o objetivo e existir como recurso
# executado por uma unidade systemd enquanto o modo do arquivo e inseguro.
while true; do sleep 60; done
EOS

  cat > "$LAB_DIR/report.sh" <<'EOS'
#!/bin/bash
# Script deliberadamente world-writable que NENHUM servico ou processo executa.
# Serve para verificar se a ferramenta distingue configuracao inadequada de
# relacao de privilegio efetivamente observada.
echo "relatorio de laboratorio"
EOS

  chmod 0777 "$LAB_DIR/agent.sh" "$LAB_DIR/report.sh"
  say "criado $LAB_DIR/agent.sh   (0777)"
  say "criado $LAB_DIR/report.sh  (0777, nao executado por ninguem)"

  cat > "$UNIT_PATH" <<EOS
[Unit]
Description=Endpoint Investigator - unidade de laboratorio (removivel)

[Service]
Type=simple
ExecStart=/bin/bash $LAB_DIR/agent.sh
Restart=no
EOS
  say "criado $UNIT_PATH"

  systemctl --user daemon-reload 2>/dev/null
  systemctl --user start "$UNIT_NAME" 2>/dev/null
  sleep 1
  status
}

status() {
  echo "[lab] estado atual"
  if [ -d "$LAB_DIR" ]; then
    ls -l "$LAB_DIR" | sed 's/^/  /'
  else
    say "diretorio lab/ ausente"
  fi
  systemctl --user is-active "$UNIT_NAME" >/dev/null 2>&1 \
    && say "unidade $UNIT_NAME: ATIVA (pid $(systemctl --user show -p MainPID --value "$UNIT_NAME" 2>/dev/null))" \
    || say "unidade $UNIT_NAME: inativa ou inexistente"
}

teardown() {
  echo "[lab] desmontando cenario"
  systemctl --user stop "$UNIT_NAME" 2>/dev/null && say "unidade parada"
  rm -f "$UNIT_PATH" && say "removido $UNIT_PATH"
  systemctl --user daemon-reload 2>/dev/null
  rm -rf "$LAB_DIR" && say "removido $LAB_DIR"
  say "nenhum arquivo fora do projeto e de ~/.config/systemd/user foi tocado"
}

case "${1:-}" in
  setup) setup ;;
  status) status ;;
  teardown) teardown ;;
  *) echo "uso: $0 {setup|status|teardown}"; exit 2 ;;
esac
