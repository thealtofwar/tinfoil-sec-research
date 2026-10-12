#!/bin/sh
# Finding 2 PoC: tinfoil==0.14.0 from PyPI, real Intel artifacts, local only.
# Heavy files (venv, cache) go to $WORK (default /root/tinfoil-review/work/disclosures/02).
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:-/root/tinfoil-review/work/disclosures/02}
mkdir -p "$WORK"
if [ ! -x "$WORK/venv/bin/python" ]; then
  python3 -m venv "$WORK/venv"
  "$WORK/venv/bin/pip" install -q tinfoil==0.14.0
fi
"$WORK/venv/bin/pip" show tinfoil | grep -E '^(Name|Version)'
# fresh HOME so the real user collateral cache is never touched; -I = isolated mode
mkdir -p "$WORK/home"
HOME="$WORK/home" "$WORK/venv/bin/python" -I "$HERE/poc_f2.py" "$HERE/data"
