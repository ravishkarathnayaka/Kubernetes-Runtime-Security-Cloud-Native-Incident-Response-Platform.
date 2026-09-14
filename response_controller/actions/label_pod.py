"""Pod Labeling & Metadata Annotation for Security Incidents."""

import datetime
import logging
from typing import Optional
from response_controller.k8s_client import KubernetesClient

logger = logging.getLogger("response_controller.actions.label_pod")


def label_pod(
    k8s_client: KubernetesClient,
    namespace: str,
    pod_name: str,
    incident_id: str,
    rule_name: str,
    priority: str,
    timestamp: Optional[str] = None,
) -> bool:
    """Labels and annotates the compromised pod with quarantine and forensic metadata.

    Args:
        k8s_client: Initialized Kubernetes client wrapper.
        namespace: Target pod namespace.
        pod_name: Target pod name.
        incident_id: Unique incident tracking identifier.
        rule_name: Falco detection rule that triggered containment.
        priority: Falco alert priority.
        timestamp: Incident timestamp.

    Returns:
        bool: True if metadata patch succeeded, False otherwise.
    """
    ts = timestamp or datetime.datetime.now(datetime.timezone.utc).isoformat()

    labels = {
        "security.incident/quarantined": "true",
        "security.incident/target-pod": pod_name,
        "security.incident/status": "contained",
    }

    annotations = {
        "security.incident/id": incident_id,
        "security.incident/rule": rule_name,
        "security.incident/priority": priority,
        "security.incident/timestamp": ts,
        "security.incident/action": "quarantine-networkpolicy-applied",
    }

    logger.info(f"Applying quarantine labels and annotations to pod {namespace}/{pod_name}")
    return k8s_client.patch_pod_metadata(
        namespace=namespace,
        pod_name=pod_name,
        labels=labels,
        annotations=annotations,
    )
