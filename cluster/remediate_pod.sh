#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Security Remediation & Un-quarantine Utility
# Usage: ./cluster/remediate_pod.sh <namespace> <pod_name> [unquarantine|delete]
# ==============================================================================

if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <namespace> <pod_name> [unquarantine|delete]" >&2
  echo "Example: $0 demo compromised-workload unquarantine" >&2
  exit 1
fi

NAMESPACE="$1"
POD_NAME="$2"
ACTION="${3:-unquarantine}"
POLICY_NAME="quarantine-${POD_NAME}"

echo "==> Remediation Utility: Processing Pod ${NAMESPACE}/${POD_NAME}"

if ! kubectl -n "${NAMESPACE}" get pod "${POD_NAME}" &>/dev/null; then
  echo "ERROR: Pod '${POD_NAME}' not found in namespace '${NAMESPACE}'." >&2
  exit 1
fi

case "${ACTION}" in
  unquarantine)
    echo "Lifting network quarantine for ${NAMESPACE}/${POD_NAME}..."
    
    # 1. Remove Quarantine NetworkPolicy
    if kubectl -n "${NAMESPACE}" get networkpolicy "${POLICY_NAME}" &>/dev/null; then
      echo "Deleting NetworkPolicy '${POLICY_NAME}'..."
      kubectl -n "${NAMESPACE}" delete networkpolicy "${POLICY_NAME}"
    else
      echo "NetworkPolicy '${POLICY_NAME}' was not found. Skipping."
    fi

    # 2. Update pod labels & annotations
    echo "Updating pod security labels..."
    kubectl -n "${NAMESPACE}" label pod "${POD_NAME}" \
      security.incident/quarantined="false" \
      security.incident/status="remediated" \
      --overwrite

    kubectl -n "${NAMESPACE}" annotate pod "${POD_NAME}" \
      security.incident/remediated-at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
      security.incident/action="quarantine-lifted" \
      --overwrite

    echo "✅ SUCCESS: Pod ${NAMESPACE}/${POD_NAME} un-quarantined. Network ingress/egress restored."
    ;;

  delete)
    echo "Terminating compromised pod ${NAMESPACE}/${POD_NAME} for clean respawn..."
    
    # Clean up NetworkPolicy
    kubectl -n "${NAMESPACE}" delete networkpolicy "${POLICY_NAME}" --ignore-not-found=true

    # Delete pod
    kubectl -n "${NAMESPACE}" delete pod "${POD_NAME}" --grace-period=5

    echo "✅ SUCCESS: Compromised pod deleted. Workload controller will provision clean replica."
    ;;

  *)
    echo "ERROR: Unknown action '${ACTION}'. Must be 'unquarantine' or 'delete'." >&2
    exit 1
    ;;
esac
