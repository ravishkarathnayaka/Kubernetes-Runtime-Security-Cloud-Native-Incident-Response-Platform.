"""Alert Dispatcher for Incident Response Notifications."""

import json
import logging
import os
from typing import Any, Dict, Optional
import requests

logger = logging.getLogger("response_controller.actions.alert_dispatcher")


def dispatch_alert(
    incident_id: str,
    rule_name: str,
    priority: str,
    namespace: str,
    pod_name: str,
    container_id: str,
    actions_taken: Dict[str, Any],
    webhook_url: Optional[str] = None,
) -> Dict[str, Any]:
    """Formats and dispatches structured security incident summaries.

    Args:
        incident_id: Unique incident tracking identifier.
        rule_name: Triggered Falco detection rule.
        priority: Falco alert priority.
        namespace: Target pod namespace.
        pod_name: Target pod name.
        container_id: Target container ID.
        actions_taken: Dictionary summarizing automated response actions.
        webhook_url: Optional Slack/Webhook endpoint for alerts.

    Returns:
        Structured notification payload.
    """
    alert_event = {
        "event_type": "SECURITY_INCIDENT_CONTAINED",
        "incident_id": incident_id,
        "rule": rule_name,
        "priority": priority,
        "target": {
            "namespace": namespace,
            "pod": pod_name,
            "container_id": container_id,
        },
        "response_actions": {
            "network_isolation": bool(actions_taken.get("isolated", False)),
            "labeled_and_annotated": bool(actions_taken.get("labeled", False)),
            "evidence_snapshot": int(actions_taken.get("evidence_files_count", 0)),
            "quarantine_policy": f"quarantine-{pod_name}",
        },
    }

    # Always log structured JSON to stdout for SIEM log collectors
    formatted_json = json.dumps(alert_event, indent=2)
    logger.info(f"INCIDENT NOTIFICATION DISPATCH:\n{formatted_json}")

    target_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL") or os.getenv("ALERT_WEBHOOK_URL")
    if target_url:
        try:
            slack_payload = {
                "text": f":rotating_light: *Automated Pod Quarantine Triggered*",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "🚨 Falco Threat Detected & Pod Contained",
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Incident ID:*\n`{incident_id}`"},
                            {"type": "mrkdwn", "text": f"*Priority:*\n`{priority}`"},
                            {"type": "mrkdwn", "text": f"*Namespace / Pod:*\n`{namespace}/{pod_name}`"},
                            {"type": "mrkdwn", "text": f"*Triggered Rule:*\n`{rule_name}`"},
                        ],
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"✅ *Actions Applied:*\n• Total Zero-Trust NetworkPolicy `quarantine-{pod_name}` applied\n• Pod metadata tagged `quarantined=true`\n• Forensic snapshot recorded ({actions_taken.get('evidence_files_count', 0)} files)",
                        },
                    },
                ],
            }
            resp = requests.post(target_url, json=slack_payload, timeout=5)
            logger.info(f"Dispatched Slack alert. Response status: {resp.status_code}")
        except Exception as e:
            logger.error(f"Failed to post alert to external webhook: {e}")

    return alert_event
