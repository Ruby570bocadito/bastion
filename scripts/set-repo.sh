#!/usr/bin/env bash
# Sustituye el repositorio de ejemplo (tu-usuario/bastion) por el real en
# todo el proyecto: ruta del módulo Go, instaladores, docs y README.
#
#   ./scripts/set-repo.sh mi-usuario/bastion
set -euo pipefail
new="${1:?uso: $0 <owner/repo>}"
case "$new" in */*) ;; *) echo "formato: owner/repo" >&2; exit 1 ;; esac
cd "$(dirname "$0")/.."
old="tu-usuario/bastion"
files="$(grep -rl --exclude-dir=.git --exclude-dir=bin --exclude-dir=dist "$old" . || true)"
[ -n "$files" ] || { echo "no se encontró $old"; exit 0; }
# shellcheck disable=SC2086
sed -i.bak "s#${old}#${new}#g" $files && find . -name '*.bak' -not -path './.git/*' -delete
go mod tidy >/dev/null 2>&1 || true
echo "✓ Repositorio cambiado a ${new} en $(echo "$files" | wc -l) ficheros"
