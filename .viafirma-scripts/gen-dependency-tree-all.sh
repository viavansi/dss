#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"$REPO_ROOT/.viafirma-scripts/gen-dependency-tree.sh"
while IFS= read -r m; do
  [[ -n "$m" ]] || continue
  s="$REPO_ROOT/$m/.viafirma-scripts/gen-dependency-tree.sh"
  [[ -x "$s" ]] && "$s"
done < <(sed -n "s:.*<module>\(.*\)</module>.*:\1:p" "$REPO_ROOT/pom.xml")
