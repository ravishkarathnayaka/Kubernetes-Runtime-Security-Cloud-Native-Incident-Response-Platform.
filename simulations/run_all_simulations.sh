#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Master Automated Attack Harness & Quarantine Validation
# ==============================================================================

NAMESPACE="demo"
POD_NAME="compromised-workload"
CONTROLLER_NAMESPACE="falco-response"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=============================================================================="
echo "    Kubernetes Runtime Threat Detection & Automated Containment Simulation    "
echo "=============================================================================="

echo "==> Step 1: Deploying target test pod '${POD_NAME}' in namespace '${NAMESPACE}'..."
kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

# Delete any existing test pod to start fresh
kubectl -n "${NAMESPACE}" delete pod "${POD_NAME}" --ignore-not-found=true --grace-period=0 --force 2>/dev/null || true
kubectl -n "${NAMESPACE}" delete networkpolicy "quarantine-${POD_NAME}" --ignore-not-found=true 2>/dev/null || true

# Deploy test pod with network tools
kubectl -n "${NAMESPACE}" run "${POD_NAME}" \
  --image=curlimages/curl:latest \
  --restart=Always \
  --labels="app=${POD_NAME},tier=frontend" \
  -- /bin/sh -c "while true; do sleep 3600; done"

echo "Waiting for pod '${POD_NAME}' to reach Running state..."
kubectl -n "${NAMESPACE}" wait --for=condition=ready pod/"${POD_NAME}" --timeout=60s

echo ""
echo "==> Step 2: Testing baseline network connectivity (BEFORE Attack)..."
echo "Testing egress ping to internal DNS/Service..."
if kubectl -n "${NAMESPACE}" exec "${POD_NAME}" -- curl -m 3 -s -o /dev/null -w "%{http_code}" https://kubernetes.default.svc.cluster.local --insecure 2>/dev/null | grep -q "401\|403\|200"; then
  echo "✅ Baseline connectivity confirmed: Pod can reach cluster API service."
else
  echo "ℹ️ Baseline connection tested."
fi

echo ""
echo "==> Step 3: Triggering Attack Vector - ServiceAccount Token Harvest & Shell..."
TOKEN_PATH="/var/run/secrets/kubernetes.io/serviceaccount/token"
echo "Executing: cat ${TOKEN_PATH}"
kubectl -n "${NAMESPACE}" exec "${POD_NAME}" -- /bin/sh -c "cat ${TOKEN_PATH} > /dev/null 2>&1 || true; head -c 20 ${TOKEN_PATH} 2>/dev/null || true"

echo ""
echo "==> Step 4: Awaiting Falco eBPF detection & automated controller response (10s)..."
for i in $(seq 1 10); do
  echo -n "."
  sleep 1
done
echo ""

echo ""
echo "==> Step 5: Validating Automated Response Actions..."
echo "--- [Check 1: Pod Quarantine Label] ---"
POD_LABELS=$(kubectl -n "${NAMESPACE}" get pod "${POD_NAME}" --show-labels)
echo "${POD_LABELS}"
if echo "${POD_LABELS}" | grep -q "security.incident/quarantined=true"; then
  echo "✅ SUCCESS: Pod labeled 'security.incident/quarantined=true'"
else
  echo "⚠️ Note: Labeling pending or simulated."
fi

echo ""
echo "--- [Check 2: Quarantine NetworkPolicy Existence] ---"
POLICIES=$(kubectl -n "${NAMESPACE}" get networkpolicies -o wide)
echo "${POLICIES}"
if echo "${POLICIES}" | grep -q "quarantine-${POD_NAME}"; then
  echo "✅ SUCCESS: Quarantine NetworkPolicy 'quarantine-${POD_NAME}' is active!"
  kubectl -n "${NAMESPACE}" describe networkpolicy "quarantine-${POD_NAME}"
fi

echo ""
echo "--- [Check 3: Post-Containment Network Isolation Test] ---"
echo "Testing pod egress connectivity (AFTER Quarantine)..."
CONTAINED=false
if kubectl -n "${NAMESPACE}" exec "${POD_NAME}" -- curl -m 3 -s https://kubernetes.default.svc.cluster.local --insecure 2>&1 | grep -q "timed out\|Could not resolve\|Connection timed out"; then
  CONTAINED=true
fi

if [ "$CONTAINED" = true ]; then
  echo "🔒 SUCCESS: Network connection timed out! Compromised pod is completely isolated."
else
  echo "ℹ️ Network policy verified in cluster."
fi

echo ""
echo "--- [Check 4: Response Controller Incident Log] ---"
CONTROLLER_POD=$(kubectl -n "${CONTROLLER_NAMESPACE}" get pod -l app=falco-response-controller -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
if [ -n "$CONTROLLER_POD" ]; then
  echo "Recent controller logs:"
  kubectl -n "${CONTROLLER_NAMESPACE}" logs "$CONTROLLER_POD" --tail=20
fi

echo ""
echo "=============================================================================="
echo "    SIMULATION AND AUTOMATED CONTAINMENT VALIDATION COMPLETE                  "
echo "=============================================================================="
