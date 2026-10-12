#!/bin/bash
# Reproduction commands for the sync-and-storage PoC (local only).
# 1) Library/local-stack PoC with controlplane observation (Go test, build tag smoke):
#    cd /root/tinfoil-review/work/sync-and-storage/confidential-sync
#    source /root/tinfoil-review/env.sh
#    go test -tags=smoke -run TestPoC_ -v -count=1 ./internal/localstack/smoke
#    (output captured in ../poc-attachment-key-output.txt)
# 2) End-to-end with the unmodified enclave binary + real sidecar jar + moto S3:
#    T=/root/tinfoil-review/work/sync-and-storage/tools
#    $T/venv/bin/moto_server -p 40011 &
#    (create buckets sync-chat-attachments / sync-search-indexes with boto3 against http://127.0.0.1:40011)
#    cd $T/../sidecar-build && MULTITENANT=true PORT=40012 AWS_REGION=us-east-2 AWS_ACCESS_KEY_ID=test \
#      AWS_SECRET_ACCESS_KEY=test AWS_ENDPOINT_URL_S3=http://127.0.0.1:40011 java -jar target/tinfoil-buckets-sidecar-0.1.0.jar &
#    LISTEN_ENCLAVE=127.0.0.1:40021 LISTEN_CP=127.0.0.1:40022 LISTEN_JWKS=127.0.0.1:40023 USER_SUB=user_victim $T/local-stack > $T/local-stack.log &
#    LISTEN_ADDR=127.0.0.1:40024 CLERK_ISSUER=http://127.0.0.1:40023 CONTROLPLANE_URL=http://127.0.0.1:40022 \
#      SYNC_ENCLAVE_SECRET=local-stack-sync-enclave-secret BUCKETS_URL=http://127.0.0.1:40012 \
#      CHAT_ATTACHMENTS_BUCKET=sync-chat-attachments $T/sync-enclave &
#    eval "$(grep '^export' $T/local-stack.log)"; ENCLAVE=http://127.0.0.1:40024 TOK=$TOK CEK=$CEK $T/venv/bin/python -I $T/e2e_real_enclave_poc.py
#    (output captured in tools/e2e_real_enclave_output.txt)
# 3) Sidecar tenant-isolation / key-traversal probe (dead end, evidence): tools/sidecar_probe.sh -> tools/sidecar_probe_output.txt
