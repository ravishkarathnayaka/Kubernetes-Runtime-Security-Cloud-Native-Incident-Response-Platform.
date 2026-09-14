"""Automated Pod Isolation via Kubernetes NetworkPolicy."""

import logging
from typing import Dict, Optional
from response_controller.k8s_client import KubernetesClient

logger = logging.getLogger("response_controller.actions.isolate_pod")


def isolate_pod(
    k8s_client: KubernetesClient,
    namespace: str,
    pod_name: str,
    incident_id: str,
    custom_selector: Optional[Dict[str, str]] = None,
) -> bool:
    """Applies a zero-traffic Quarantine NetworkPolicy targeting the compromised pod.

    Args:
        k8s_client: Initialized Kubernetes client wrapper.
        namespace: Target pod namespace.
        pod_name: Target pod name.
        incident_id: Unique incident tracking identifier.
        custom_selector: Optional dictionary of pod labels to target.

    Returns:
        bool: True if policy was applied successfully, False otherwise.
    """
    logger.info(f"Initiating network isolation for pod {namespace}/{pod_name} (Incident: {incident_id})")

    policy_name = f"quarantine-{pod_name}"

    # Target selector: specific to this pod via incident target label and pod name
    if custom_selector:
        selector = custom_selector
    else:
        selector = {
            "security.incident/target-pod": pod_name,
        }

    success = k8s_client.apply_quarantine_network_policy(
        namespace=namespace,
        policy_name=policy_name,
        pod_selector_labels=selector,
    )

    if success:
        logger.info(f"Successfully applied network isolation policy '{policy_name}' in namespace '{namespace}'")
    else:
        logger.error(f"Failed to apply isolation policy '{policy_name}' in namespace '{namespace}'")

    return success
