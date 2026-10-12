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
