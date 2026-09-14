# Cloud-Native Incident Response Playbook & Standard Operating Procedure (SOP)

> **Document Version:** 1.0.0  
> **Target Environment:** Production Kubernetes Clusters (eBPF / Falco / Calico)  
> **Audience:** Security Operations Center (SOC), Cloud Security Engineers, Platform SREs

---

## 1. Executive Summary & Philosophy

When an adversary compromises a container in a multi-tenant Kubernetes cluster, **containment speed is paramount**. Waiting for manual SOC triage allows the attacker to harvest ServiceAccount tokens, attempt container breakouts, or establish persistence via lateral network movement.

This playbook outlines the incident handling procedure orchestrated automatically by **Falco (eBPF)** and the **Incident Response Controller**, coupled with human-in-the-loop forensic validation and clean pod remediation.

---

## 2. Six-Phase Incident Response Lifecycle

```text
  [ 1. DETECTION ]   --->   [ 2. CONTAINMENT ]   --->   [ 3. FORENSICS ]
  Falco eBPF Trace          Auto-NetPolicy Drop         /evidence Archive
         |                         |                           |
         v                         v                           v
  [ 4. TRIAGE & RCA ] --->   [ 5. REMEDIATION ]   --->   [ 6. POST-MORTEM ]
  Token / CVE Audit         remediate_pod.sh            Rule Tuning & PR
```

---

## Phase 1: Detection & Alert Ingestion

1. **Kernel Syscall Capture**:
   - Falco eBPF probe intercepts high-risk tracepoints (`sys_enter_openat`, `sys_enter_execve`, `sys_enter_connect`).
2. **Rule Matching**:
   - Alerts with priority `CRITICAL` or `WARNING` automatically forward via JSON HTTP POST to:
     `http://falco-response-controller.falco-response.svc.cluster.local:8080/webhook`
3. **Webhook Verification**:
   - Controller verifies the authentication token (`Authorization: Bearer <token>` or `X-Falco-Token`).
   - Alerts from exempted system namespaces (`kube-system`, `falco`, `falco-response`) are logged but skipped to prevent self-denial of service.

---

## Phase 2: Automated Containment Verification

The response controller executes automated containment in `< 850 milliseconds`.

### SOC Verification Checklist:
1. Verify the pod is labeled as quarantined:
   ```bash
   kubectl get pods -n <namespace> -l security.incident/quarantined=true
   ```
2. Inspect the synthesized isolation policy:
   ```bash
   kubectl describe networkpolicy quarantine-<pod-name> -n <namespace>
   ```
   **Expected Policy Configuration:**
   - `PolicyTypes: [Ingress, Egress]`
   - `Allowing ingress traffic: <none>` (Deny All Ingress)
   - `Allowing egress traffic: <none>` (Deny All Egress)
3. Verify packet drop from within the quarantined container:
   ```bash
   kubectl exec -n <namespace> <pod-name> -- curl -m 2 https://kubernetes.default.svc
   # Expected output: curl: (28) Connection timed out
   ```

---

## Phase 3: Digital Forensics & Chain of Custody

Before any network changes take effect, the response controller snapshots the runtime state into the persistent evidence vault (`/evidence/<incident_id>/`).

### Evidence Bundle Contents:
| File | Description | Purpose |
| :--- | :--- | :--- |
| `falco_alert.json` | Raw alert payload from Falco eBPF engine | Syscall, process arguments, and UID context |
| `pod_manifest_dump.yaml` | Live serialized Kubernetes pod specification | Node placement, image digests, volume mounts |
| `container_<name>.log` | Captured stdout/stderr container logs | Living-off-the-land commands, error traces |
| `evidence_manifest.json` | Checksums and metadata for legal chain of custody | Audit verification |

### Extracting Evidence to Workstation:
```bash
CONTROLLER_POD=$(kubectl -n falco-response get pod -l app=falco-response-controller -o jsonpath='{.items[0].metadata.name}')
kubectl cp falco-response/${CONTROLLER_POD}:/evidence/<incident_id> ./evidence-archive/
```

---

## Phase 4: Root Cause Analysis (RCA)

1. **ServiceAccount Token Harvest (`T1552.007`)**:
   - Check if the compromised pod mounted a privileged ServiceAccount.
   - Run RBAC audit to check token permissions:
     ```bash
     kubectl auth can-i --list --as=system:serviceaccount:<namespace>:<serviceaccount>
     ```
   - If token had cluster-admin or secret reading capabilities, **immediately revoke** the ServiceAccount token and rotate cluster secrets.
2. **Container Breakout Attempt (`T1611`)**:
   - Check whether the pod spec had `securityContext.privileged: true` or mounted host volumes (`/sys`, `/proc`, `/var/run/docker.sock`).
   - Enforce Pod Security Standards `restricted` mode on the namespace.

---

## Phase 5: Remediation & Workload Recovery

Once forensics are secured, the security engineer chooses one of two paths:

### Path A: Terminate and Respawn Clean Replica (Recommended)
Deletes the compromised container so the Deployment/DaemonSet controller deploys an untampered instance from the verified image registry:
```bash
./cluster/remediate_pod.sh <namespace> <pod-name> delete
```

### Path B: Un-quarantine Live Workload (False Positive or In-Place Fix)
Lifts the quarantine NetworkPolicy and updates pod metadata status:
```bash
./cluster/remediate_pod.sh <namespace> <pod-name> unquarantine
```
Or via the Python CLI:
```bash
python -m response_controller.cli unquarantine <namespace> <pod-name>
```

---

## Phase 6: Post-Mortem & Rule Tuning

1. Document incident timeline in the post-mortem report (use the 1-click **Download Incident Report** button on the Web Portal).
2. If the detection was a legitimate developer workload, update the Falco rule exception list in `falco/rules/<rule>.yaml`.
3. Submit a Pull Request updating the repository rules and Helm values.
