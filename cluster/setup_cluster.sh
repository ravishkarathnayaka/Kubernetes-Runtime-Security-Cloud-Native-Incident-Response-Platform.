#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Kubernetes Runtime Security & Cloud-Native Incident Response Platform
# Cluster Provisioning & Component Deployment Script
# ==============================================================================

CLUSTER_NAME="security-lab"
CALICO_VERSION="v3.28.0"
FALCO_NAMESPACE="falco"
CONTROLLER_NAMESPACE="falco-response"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "==> [1/7] Checking dependencies..."
for cmd in docker kind kubectl helm; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: Missing required command '$cmd'. Please install it and retry." >&2
    exit 1
  fi
done
echo "All dependencies (docker, kind, kubectl, helm) are available."

echo "==> [2/7] Provisioning Kind multi-node cluster (${CLUSTER_NAME})..."
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  echo "Cluster '${CLUSTER_NAME}' already exists. Reusing cluster."
else
  kind create cluster --config="${REPO_ROOT}/cluster/kind-config.yaml"
fi

kubectl cluster-info --context "kind-${CLUSTER_NAME}"

echo "==> [3/7] Installing Calico CNI for NetworkPolicy enforcement..."
kubectl apply -f "https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml"

echo "Waiting for Calico node daemonset to roll out..."
kubectl -n kube-system rollout status daemonset/calico-node --timeout=240s || true

echo "==> [4/7] Building & Loading Incident Response Controller..."
docker build -t falco-response-controller:latest "${REPO_ROOT}/response_controller"
kind load docker-image falco-response-controller:latest --name "${CLUSTER_NAME}"

echo "Deploying Incident Response Controller..."
kubectl apply -f "${REPO_ROOT}/cluster/manifests/controller-deployment.yaml"
kubectl -n "${CONTROLLER_NAMESPACE}" rollout status deployment/falco-response-controller --timeout=120s

echo "==> [5/7] Deploying Falco with Modern eBPF & Custom Rules..."
helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null 2>&1 || true
helm repo update >/dev/null 2>&1

# Create custom rules configmap in falco namespace
kubectl create namespace "${FALCO_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "${FALCO_NAMESPACE}" create configmap falco-custom-rules \
  --from-file="${REPO_ROOT}/falco/rules/k8s_exec_terminal.yaml" \
  --from-file="${REPO_ROOT}/falco/rules/k8s_token_access.yaml" \
  --from-file="${REPO_ROOT}/falco/rules/k8s_container_escape.yaml" \
  --from-file="${REPO_ROOT}/falco/rules/k8s_outbound_c2.yaml" \
  --dry-run=client -o yaml | kubectl apply -f -

# Install / Upgrade Falco Helm Chart
if helm -n "${FALCO_NAMESPACE}" status falco >/dev/null 2>&1; then
  echo "Upgrading existing Falco Helm release..."
  helm -n "${FALCO_NAMESPACE}" upgrade falco falcosecurity/falco \
    -f "${REPO_ROOT}/falco/falco-values.yaml"
else
  echo "Installing Falco Helm release..."
  helm -n "${FALCO_NAMESPACE}" install falco falcosecurity/falco \
    -f "${REPO_ROOT}/falco/falco-values.yaml"
fi

echo "Waiting for Falco daemonset rollout..."
kubectl -n "${FALCO_NAMESPACE}" rollout status daemonset/falco --timeout=300s || true

echo "==> [6/7] Deploying Baseline Zero-Trust Network Policies..."
kubectl create namespace demo --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -n demo -f "${REPO_ROOT}/network_policies/default-deny-all.yaml"
kubectl apply -n demo -f "${REPO_ROOT}/network_policies/allow-dns-internal.yaml"

echo "==> [7/7] Environment Setup Complete!"
echo "=============================================================================="
echo "Cluster nodes:"
kubectl get nodes -o wide
echo ""
echo "Security Pods running:"
kubectl get pods -n "${FALCO_NAMESPACE}"
kubectl get pods -n "${CONTROLLER_NAMESPACE}"
echo "=============================================================================="
echo "Ready to run simulated attack vectors:"
echo "  ./simulations/run_all_simulations.sh"
