#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# CIS Kubernetes Benchmark Audit via Aqua Security kube-bench
# ==============================================================================

BENCHMARK_NAMESPACE="kube-bench"
JOB_NAME="kube-bench-run"

echo "==> Running CIS Kubernetes Benchmark Audit on Kind Cluster..."

# Ensure namespace exists
kubectl create namespace "${BENCHMARK_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

# Clean up any existing job
kubectl -n "${BENCHMARK_NAMESPACE}" delete job "${JOB_NAME}" --ignore-not-found=true

# Deploy kube-bench job
cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: ${JOB_NAME}
  namespace: ${BENCHMARK_NAMESPACE}
spec:
  template:
    metadata:
      labels:
        app: kube-bench
    spec:
      hostPID: true
      nodeSelector:
        node-role.kubernetes.io/control-plane: ""
      tolerations:
        - key: node-role.kubernetes.io/control-plane
          operator: Exists
          effect: NoSchedule
        - key: node-role.kubernetes.io/master
          operator: Exists
          effect: NoSchedule
      containers:
        - name: kube-bench
          image: aquasec/kube-bench:v0.8.0
          command: ["kube-bench", "run", "--targets", "master,node,etcd,policies", "--check", "1.1,1.2,2.1,3.1,4.1,5.1"]
          volumeMounts:
            - name: var-lib-etcd
              mountPath: /var/lib/etcd
              readOnly: true
            - name: var-lib-kubelet
              mountPath: /var/lib/kubelet
              readOnly: true
            - name: etc-systemd
              mountPath: /etc/systemd
              readOnly: true
            - name: etc-kubernetes
              mountPath: /etc/kubernetes
              readOnly: true
      restartPolicy: Never
      volumes:
        - name: var-lib-etcd
          hostPath:
            path: /var/lib/etcd
        - name: var-lib-kubelet
          hostPath:
            path: /var/lib/kubelet
        - name: etc-systemd
          hostPath:
            path: /etc/systemd
        - name: etc-kubernetes
          hostPath:
            path: /etc/kubernetes
EOF

echo "Waiting for kube-bench audit job to complete..."
kubectl -n "${BENCHMARK_NAMESPACE}" wait --for=condition=complete job/"${JOB_NAME}" --timeout=180s || {
  echo "Job failed or timed out. Fetching pod logs:"
  kubectl -n "${BENCHMARK_NAMESPACE}" logs -l app=kube-bench --tail=50
  exit 1
}

echo "=============================================================================="
echo "                   CIS BENCHMARK COMPLIANCE AUDIT RESULTS                     "
echo "=============================================================================="
kubectl -n "${BENCHMARK_NAMESPACE}" logs -l app=kube-bench

echo "Cleaning up kube-bench job..."
kubectl -n "${BENCHMARK_NAMESPACE}" delete job "${JOB_NAME}" --ignore-not-found=true
