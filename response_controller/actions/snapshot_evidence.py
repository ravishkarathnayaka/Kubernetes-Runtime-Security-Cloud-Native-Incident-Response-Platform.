"""Forensic Evidence Collection & Incident Snapshotting."""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional
import yaml

from response_controller.k8s_client import KubernetesClient

logger = logging.getLogger("response_controller.actions.snapshot_evidence")


def snapshot_evidence(
    k8s_client: KubernetesClient,
    namespace: str,
    pod_name: str,
    incident_id: str,
    alert_payload: Dict[str, Any],
    evidence_base_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Extracts forensic evidence from target pod (logs, pod spec, alert context).

    Args:
        k8s_client: Kubernetes client instance.
        namespace: Pod namespace.
        pod_name: Pod name.
        incident_id: Unique incident ID.
        alert_payload: Full Falco alert webhook payload.
        evidence_base_dir: Directory where evidence will be persisted.

    Returns:
        Dict summarizing captured evidence and artifact file paths.
    """
    base_dir = evidence_base_dir or os.getenv("EVIDENCE_DIR", "/evidence")
    incident_dir = Path(base_dir) / incident_id
    incident_dir.mkdir(parents=True, exist_ok=True)

    evidence_summary: Dict[str, Any] = {
        "incident_id": incident_id,
        "pod_name": pod_name,
        "namespace": namespace,
        "captured_files": [],
        "pod_status": "Unknown",
        "node_name": "Unknown",
        "pod_ip": "Unknown",
    }

    # 1. Capture full alert context
    alert_file = incident_dir / "falco_alert.json"
    with open(alert_file, "w", encoding="utf-8") as f:
        json.dump(alert_payload, f, indent=2)
    evidence_summary["captured_files"].append(str(alert_file))

    # 2. Fetch Pod manifest & status
    pod = k8s_client.get_pod(namespace, pod_name)
    containers = []
    if pod:
        evidence_summary["node_name"] = pod.spec.node_name if pod.spec else "Unknown"
        evidence_summary["pod_ip"] = pod.status.pod_ip if pod.status else "Unknown"
        evidence_summary["pod_status"] = pod.status.phase if pod.status else "Unknown"

        if pod.spec and pod.spec.containers:
            containers = [c.name for c in pod.spec.containers]

        # Dump Pod spec to YAML
        try:
            if hasattr(k8s_client.core_v1, "api_client") and hasattr(k8s_client.core_v1.api_client, "sanitize_for_serialization"):
                pod_dict = k8s_client.core_v1.api_client.sanitize_for_serialization(pod)
            else:
                pod_dict = {
                    "metadata": {"name": getattr(pod.metadata, "name", pod_name)},
                    "spec": {"nodeName": evidence_summary["node_name"]},
                    "status": {"phase": evidence_summary["pod_status"], "podIP": evidence_summary["pod_ip"]},
                }
            spec_file = incident_dir / "pod_manifest_dump.yaml"
            with open(spec_file, "w", encoding="utf-8") as f:
                yaml.safe_dump(pod_dict, f, default_flow_style=False)
            evidence_summary["captured_files"].append(str(spec_file))
        except Exception as e:
            logger.warning(f"Failed to serialize pod manifest: {e}")
    else:
        logger.warning(f"Could not retrieve pod spec for {namespace}/{pod_name}")

    # 3. Capture container logs
    if not containers:
        containers = [None]  # default container

    for c_name in containers:
        file_suffix = f"_{c_name}" if c_name else ""
        log_content = k8s_client.get_pod_logs(namespace, pod_name, container_name=c_name, tail_lines=500)
        log_file = incident_dir / f"container{file_suffix}.log"
        with open(log_file, "w", encoding="utf-8") as f:
            f.write(log_content)
        evidence_summary["captured_files"].append(str(log_file))

    # 4. Save evidence manifest
    manifest_file = incident_dir / "evidence_manifest.json"
    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(evidence_summary, f, indent=2)
    evidence_summary["captured_files"].append(str(manifest_file))

    logger.info(f"Forensic evidence bundle captured at {incident_dir} ({len(evidence_summary['captured_files'])} files)")
    return evidence_summary
