"""SIEM Event Formatter & Forwarder supporting CEF and Elastic Common Schema (ECS)."""

import json
from typing import Any, Dict


def format_cef_event(
    incident_id: str,
    rule_name: str,
    priority: str,
    namespace: str,
    pod_name: str,
    container_id: str,
    actions_taken: Dict[str, Any],
) -> str:
    """Formats incident containment details into standard Common Event Format (CEF).

    CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
    """
    severity_map = {
        "EMERGENCY": "10",
        "ALERT": "9",
        "CRITICAL": "8",
        "ERROR": "6",
        "WARNING": "4",
        "NOTICE": "2",
        "INFORMATIONAL": "1",
        "DEBUG": "0",
    }
    cef_severity = severity_map.get(priority.upper(), "5")
    quarantine_status = "quarantined" if actions_taken.get("isolated") else "pending"

    cef_line = (
        f"CEF:0|CloudNativeSecurity|FalcoResponseController|1.0|"
        f"K8S_THREAT_DETECTED|{rule_name}|{cef_severity}|"
        f"cs1={incident_id} cs1Label=IncidentID "
        f"cs2={namespace} cs2Label=KubernetesNamespace "
        f"cs3={pod_name} cs3Label=KubernetesPod "
        f"cs4={container_id} cs4Label=ContainerID "
        f"cs5={quarantine_status} cs5Label=ContainmentStatus "
        f"act=network_isolation"
    )
    return cef_line


def format_ecs_event(
    incident_id: str,
    rule_name: str,
    priority: str,
    namespace: str,
    pod_name: str,
    container_id: str,
    actions_taken: Dict[str, Any],
) -> Dict[str, Any]:
    """Formats incident containment details into Elastic Common Schema (ECS) v8 JSON."""
    return {
        "ecs": {"version": "8.11.0"},
        "event": {
            "kind": "alert",
            "category": ["intrusion_detection", "host"],
            "type": ["denied", "info"],
            "outcome": "success" if actions_taken.get("isolated") else "unknown",
            "action": "pod_quarantine",
            "reason": rule_name,
            "severity": 8 if priority.upper() == "CRITICAL" else 4,
        },
        "orchestrator": {
            "type": "kubernetes",
            "namespace": namespace,
            "resource": {
                "name": pod_name,
                "type": "pod",
            },
        },
        "container": {
            "id": container_id,
        },
        "labels": {
            "incident_id": incident_id,
            "security_incident_quarantined": str(actions_taken.get("isolated", False)).lower(),
            "falco_rule": rule_name,
        },
    }
