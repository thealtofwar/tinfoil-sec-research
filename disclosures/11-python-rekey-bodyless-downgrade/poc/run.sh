#!/usr/bin/env bash
# Finding 11 PoC: tinfoil-python 0.14.0 + tinfoil-ehbp 0.4.0 (PyPI wheels), loopback only.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-/root/tinfoil-review/work/disclosures/11}"
PY="${PYTHON:-python3}"
mkdir -p "$WORK"

mkvenv() { # mkvenv <dir> [tinfoil-ehbp version]
  rm -rf "$1"; "$PY" -m venv "$1"
  "$1/bin/pip" install -q 'tinfoil==0.14.0' "tinfoil-ehbp==${2:-0.4.0}"
}

# Wheel provenance (sha256 as published on PyPI).
rm -rf "$WORK/wheels"
"$PY" -m pip download -q --no-deps -d "$WORK/wheels" 'tinfoil==0.14.0' 'tinfoil-ehbp==0.4.0'
(cd "$WORK/wheels" && sha256sum *.whl)

mkvenv "$WORK/venv"
"$WORK/venv/bin/pip" freeze | grep -iE '^(tinfoil|tinfoil-ehbp|httpx|openai)=='
echo "##### shipped wheels, expect=vulnerable"
POC_EXPECT=vulnerable "$WORK/venv/bin/python" -I "$HERE/poc_rekey_bodyless.py"

# Negative control: same wheels, with a minimal fix in _EHBPReVerifyingTransport
# (sync and async): never retry a request whose body stream is not replayable.
mkvenv "$WORK/venv-fixed"
"$WORK/venv-fixed/bin/python" -I - <<'EOF'
import pathlib, tinfoil.client as m
p = pathlib.Path(m.__file__); s = p.read_text()
old = "            if reverify_failed:\n                raise\n\n            assert retry_inner is not None\n"
new = ("            if reverify_failed:\n                raise\n"
       "            if not isinstance(request.stream, httpx.ByteStream):\n"
       "                raise  # FIX: one-shot body already consumed; never resend it bodyless\n\n"
       "            assert retry_inner is not None\n")
a = s.index("class _EHBPReVerifyingTransport"); b = s.index("def _enclave_url_header")
mid = s[a:b]; assert mid.count(old) == 2, mid.count(old)  # sync + async EHBP classes only
p.write_text(s[:a] + mid.replace(old, new) + s[b:])
print("patched", p)
EOF
echo "##### patched wheels, expect=fixed"
POC_EXPECT=fixed "$WORK/venv-fixed/bin/python" -I "$HERE/poc_rekey_bodyless.py"

# Version bound: tinfoil 0.14.0 requires tinfoil-ehbp>=0.3.0. With 0.3.2 the
# EHBP transport buffers the body (request.read()), so the retry is re-sealed.
mkvenv "$WORK/venv-ehbp032" 0.3.2
echo "##### tinfoil 0.14.0 + tinfoil-ehbp 0.3.2 (unpatched), expect=fixed"
POC_EXPECT=fixed "$WORK/venv-ehbp032/bin/python" -I "$HERE/poc_rekey_bodyless.py"
