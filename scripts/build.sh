#!/usr/bin/env bash
# Compile every contract for every network with the pinned compiler.
#   SILVERSCRIPT_DIR  checkout of https://github.com/kaspanet/silverscript (default ~/silverscript)
# The checkout must be at the commit pinned in params/*.json; the script refuses anything else.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SS="${SILVERSCRIPT_DIR:-$HOME/silverscript}"
PINNED="3ed973335b59269293564805cc2c58a14595ec03"   # tag v1.0.0

actual="$(git -C "$SS" rev-parse HEAD)"
if [[ "$actual" != "$PINNED" ]]; then
  echo "silverscript at $actual, expected $PINNED (v1.0.0)" >&2; exit 1
fi
if [[ -n "$(git -C "$SS" status --porcelain --untracked-files=no)" ]]; then
  echo "silverscript checkout has local modifications" >&2; exit 1
fi
SILVERC="$SS/target/release/silverc"
if [[ ! -x "$SILVERC" ]]; then
  (cd "$SS" && cargo build --release -p silverscript-lang --bin silverc)
fi

for params in "$ROOT"/params/*.json; do
  net="$(basename "$params" .json)"
  for p in $(python3 -c "import json,sys;p=json.load(open(sys.argv[1]));print(p['compiler']['commit'])" "$params"); do
    [[ "$p" == "$PINNED" ]] || { echo "$params pins compiler $p" >&2; exit 1; }
  done
  python3 "$ROOT/scripts/build.py" "$SILVERC" "$params" "$ROOT/artifacts/$net"
done
