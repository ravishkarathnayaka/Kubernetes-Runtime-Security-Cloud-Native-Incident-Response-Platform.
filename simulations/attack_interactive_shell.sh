#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Simulation 1: Interactive Shell Spawn Inside Pod (T1059 / Execution)
# ==============================================================================

NAMESPACE="demo"
POD_NAME="demo-workload"

echo "==> [Attack Vector 1] Interactive Terminal Shell Spawn"
echo "Target Pod: ${NAMESPACE}/${POD_NAME}"

# Ensure demo pod is running
if ! kubectl -n "${NAMESPACE}" get pod "${POD_NAME}" &>/dev/null; then
  echo "Deploying target pod '${POD_NAME}'..."
  kubectl -n "${NAMESPACE}" run "${POD_NAME}" \
    --image=alpine:latest \
    --restart=Always \
    --labels="app=demo-workload,env=test" \
    -- /bin/sh -c "while true; do sleep 3600; done"
  
  echo "Waiting for pod to be in Ready state..."
  kubectl -n "${NAMESPACE}" wait --for=condition=ready pod/"${POD_NAME}" --timeout=60s
fi

echo "Executing interactive shell within target container..."
echo "Command: kubectl exec -n ${NAMESPACE} ${POD_NAME} -- /bin/sh -c 'whoami; id; hostname'"
kubectl -n "${NAMESPACE}" exec "${POD_NAME}" -- /bin/sh -c "whoami; id; hostname"

echo "Terminal shell execution simulated successfully."
echo "Falco rule 'Interactive Shell Spawned Inside Pod' should be triggered."
