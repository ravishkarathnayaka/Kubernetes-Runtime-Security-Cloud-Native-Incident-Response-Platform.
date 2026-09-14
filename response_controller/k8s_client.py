"""Kubernetes API Client Wrapper for Incident Response Operations."""

import logging
from typing import Dict, List, Optional
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

logger = logging.getLogger("response_controller.k8s_client")


class KubernetesClient:
    """Provides high-level incident response operations against the Kubernetes API."""

    def __init__(
        self,
        core_v1: Optional[client.CoreV1Api] = None,
        networking_v1: Optional[client.NetworkingV1Api] = None,
    ):
        """Initializes the Kubernetes API clients with cluster or local config."""
        if core_v1 is not None and networking_v1 is not None:
            self.core_v1 = core_v1
            self.networking_v1 = networking_v1
            return

        try:
            config.load_incluster_config()
            logger.info("Loaded in-cluster Kubernetes configuration.")
        except config.ConfigException:
            try:
                config.load_kube_config()
                logger.info("Loaded local kubeconfig.")
            except Exception as e:
                logger.warning(
                    f"Could not load Kubernetes configuration: {e}. Running in standalone/mock mode."
                )

        self.core_v1 = core_v1 or client.CoreV1Api()
        self.networking_v1 = networking_v1 or client.NetworkingV1Api()

    def get_pod(self, namespace: str, pod_name: str) -> Optional[client.V1Pod]:
        """Fetches pod metadata and specification."""
        try:
            return self.core_v1.read_namespaced_pod(name=pod_name, namespace=namespace)
        except ApiException as e:
            logger.error(f"Error fetching pod {pod_name} in namespace {namespace}: {e.status} {e.reason}")
            return None

    def patch_pod_metadata(
        self,
        namespace: str,
        pod_name: str,
        labels: Optional[Dict[str, str]] = None,
        annotations: Optional[Dict[str, str]] = None,
    ) -> bool:
        """Patches pod labels and annotations."""
        metadata: Dict[str, Dict[str, str]] = {}
        if labels:
            metadata["labels"] = labels
        if annotations:
            metadata["annotations"] = annotations

        if not metadata:
            return True

        body = {"metadata": metadata}
        try:
            self.core_v1.patch_namespaced_pod(name=pod_name, namespace=namespace, body=body)
            logger.info(f"Successfully patched pod metadata for {pod_name} in {namespace}")
            return True
        except ApiException as e:
            logger.error(f"Failed to patch pod metadata for {pod_name}: {e.status} {e.reason}")
            return False

    def get_pod_logs(
        self,
        namespace: str,
        pod_name: str,
        container_name: Optional[str] = None,
        tail_lines: int = 200,
    ) -> str:
        """Extracts container logs from the specified pod."""
        try:
            kwargs = {"name": pod_name, "namespace": namespace, "tail_lines": tail_lines}
            if container_name:
                kwargs["container"] = container_name
            logs = self.core_v1.read_namespaced_pod_log(**kwargs)
            return logs or ""
        except ApiException as e:
            logger.error(f"Failed to fetch logs for {pod_name} (container: {container_name}): {e.status} {e.reason}")
            return f"Error retrieving logs: {e.status} - {e.reason}"

    def apply_quarantine_network_policy(
        self,
        namespace: str,
        policy_name: str,
        pod_selector_labels: Dict[str, str],
    ) -> bool:
        """Creates or updates a zero-traffic Quarantine NetworkPolicy for the target pod."""
        policy_body = client.V1NetworkPolicy(
            api_version="networking.k8s.io/v1",
            kind="NetworkPolicy",
            metadata=client.V1ObjectMeta(
                name=policy_name,
                namespace=namespace,
                labels={
                    "app.kubernetes.io/managed-by": "falco-incident-response",
                    "security.incident/type": "quarantine",
                },
            ),
            spec=client.V1NetworkPolicySpec(
                pod_selector=client.V1LabelSelector(match_labels=pod_selector_labels),
                policy_types=["Ingress", "Egress"],
                ingress=[],
                egress=[],
            ),
        )

        try:
            self.networking_v1.create_namespaced_network_policy(
                namespace=namespace, body=policy_body
            )
            logger.info(f"Created quarantine NetworkPolicy '{policy_name}' in {namespace}")
            return True
        except ApiException as e:
            if e.status == 409:  # Conflict / Already exists
                try:
                    self.networking_v1.replace_namespaced_network_policy(
                        name=policy_name, namespace=namespace, body=policy_body
                    )
                    logger.info(f"Replaced existing quarantine NetworkPolicy '{policy_name}' in {namespace}")
                    return True
                except ApiException as replace_err:
                    logger.error(f"Failed to replace NetworkPolicy {policy_name}: {replace_err}")
                    return False
            logger.error(f"Failed to create quarantine NetworkPolicy {policy_name}: {e.status} {e.reason}")
            return False

    def list_quarantined_pods(self, namespace: Optional[str] = None) -> List[Dict[str, str]]:
        """Lists all pods labeled as quarantined."""
        try:
            label_selector = "security.incident/quarantined=true"
            if namespace:
                pod_list = self.core_v1.list_namespaced_pod(
                    namespace=namespace, label_selector=label_selector
                )
            else:
                pod_list = self.core_v1.list_pod_for_all_namespaces(
                    label_selector=label_selector
                )

            return [
                {
                    "name": pod.metadata.name,
                    "namespace": pod.metadata.namespace,
                    "status": pod.status.phase if pod.status else "Unknown",
                    "quarantined_at": pod.metadata.annotations.get(
                        "security.incident/timestamp", "unknown"
                    )
                    if pod.metadata.annotations
                    else "unknown",
                }
                for pod in pod_list.items
            ]
        except ApiException as e:
            logger.error(f"Failed to list quarantined pods: {e.status} {e.reason}")
            return []
