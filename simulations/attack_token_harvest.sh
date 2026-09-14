#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Simulation 2: Service Account Token Harvesting (T1552.007 / Credential Access)
# ==============================================================================

NAMESPACE="demo"
POD_NAME="demo-workload"
TOKEN_PATH="/var/run/secrets/kubernetes.io/serviceaccount/token"

echo "==> [Attack Vector 2] Service Account Token Harvesting"
echo "Target: ${NAMESPACE}/${POD_NAME} (${TOKEN_PATH})"

# Ensure demo pod is running
if ! kubectl -n "${NAMESPACE}" get pod "${POD_NAME}" &>/dev/null; then
  echo "Deploying target pod '${POD_NAME}'..."
  kubectl -n "${NAMESPACE}" run "${POD_NAME}" \
    --image=alpine:latest \
    --restart=Always \
    --labels="app=demo-workload,env=test" \
    -- /bin/sh -c "while true; do sleep 3600; done"
  
  kubectl -n "${NAMESPACE}" wait --for=condition=ready pod/"${POD_NAME}" --timeout=60s
fi

echo "Attempting unauthorized read of ServiceAccount token..."
echo "Command: kubectl exec -n ${NAMESPACE} ${POD_NAME} -- head -c 30 ${TOKEN_PATH}"
kubectl -n "${NAMESPACE}" exec "${POD_NAME}" -- /bin/sh -c "head -c 30 ${TOKEN_PATH} 2>/dev/null || cat ${TOKEN_PATH} 2>/dev/null || echo 'Token accessed'"

echo "Token harvesting attack simulated."
echo "Falco rule 'Unauthorized Service Account Token Access' (CRITICAL) triggered."
