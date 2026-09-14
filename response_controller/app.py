"""FastAPI Incident Response Webhook Controller for Falco Alerts."""

import logging
import os
import re
import uuid
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

import time
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

from response_controller.actions.alert_dispatcher import dispatch_alert
from response_controller.actions.isolate_pod import isolate_pod
from response_controller.actions.label_pod import label_pod
from response_controller.actions.snapshot_evidence import snapshot_evidence
from response_controller.k8s_client import KubernetesClient

# Configure logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("response_controller.app")

app = FastAPI(
    title="Kubernetes Runtime Security Incident Response Controller",
    description="Automated pod quarantine and evidence collection engine powered by Falco eBPF alerts",
    version="1.0.0",
)

# Prometheus Metrics
FALCO_ALERTS_TOTAL = Counter(
    "falco_alerts_total", "Total Falco alerts processed by webhook", ["priority", "rule"]
)
CONTAINMENT_ACTIONS_TOTAL = Counter(
    "containment_actions_total", "Total automated containment actions taken", ["action", "namespace"]
)
CONTAINMENT_DURATION = Histogram(
    "containment_duration_seconds", "Duration of end-to-end containment lifecycle in seconds"
)

# Global client and in-memory store
k8s_client = KubernetesClient()
processed_incidents: List[Dict[str, Any]] = []

ACTIONABLE_PRIORITIES = {"EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING"}


def parse_alert_metadata(payload: Dict[str, Any]) -> Dict[str, str]:
    """Extracts namespace, pod name, container id, and rule details from Falco or Falcosidekick payload."""
    rule = payload.get("rule", "Unknown Rule")
    priority = str(payload.get("priority", "UNKNOWN")).upper()
    output_text = payload.get("output", "")
    output_fields = payload.get("output_fields", {}) or {}

    # Extract namespace
    namespace = (
        output_fields.get("k8s.ns.name")
        or output_fields.get("namespace")
        or output_fields.get("ka.target.namespace")
    )
    if not namespace and "ns=" in output_text:
        m = re.search(r"ns=([^\s\),]+)", output_text)
        if m:
            namespace = m.group(1)

    # Extract pod name
    pod_name = (
        output_fields.get("k8s.pod.name")
        or output_fields.get("pod")
        or output_fields.get("ka.target.name")
    )
    if not pod_name and "pod=" in output_text:
        m = re.search(r"pod=([^\s\),]+)", output_text)
        if m:
            pod_name = m.group(1)

    # Extract container id
    container_id = (
        output_fields.get("container.id")
        or output_fields.get("container_id")
        or output_fields.get("c_id")
    )
    if not container_id and "c_id=" in output_text:
        m = re.search(r"c_id=([^\s\),]+)", output_text)
        if m:
            container_id = m.group(1)

    return {
        "rule": rule,
        "priority": priority,
        "namespace": namespace or "",
        "pod_name": pod_name or "",
        "container_id": container_id or "unknown",
        "output": output_text,
    }


@app.get("/healthz")
def health_check():
    """Liveness and readiness probe endpoint."""
    return {"status": "ok", "controller": "falco-incident-response"}


@app.get("/metrics")
def metrics():
    """Prometheus metrics scrape endpoint."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/incidents")
def list_incidents():
    """Returns all incidents handled during controller runtime."""
    return {
        "total": len(processed_incidents),
        "incidents": processed_incidents,
    }


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str):
    """Retrieves a specific incident record."""
    for inc in processed_incidents:
        if inc.get("incident_id") == incident_id:
            return inc
    raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")


@app.post("/webhook", status_code=status.HTTP_200_OK)
async def receive_falco_alert(request: Request):
    """Webhook endpoint receiving Falco JSON alerts."""
    # Verify Webhook Authentication Token if configured
    expected_token = os.getenv("WEBHOOK_AUTH_TOKEN")
    if expected_token:
        auth_header = request.headers.get("Authorization", "")
        custom_token = request.headers.get("X-Falco-Token", "")
        token = ""
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        elif custom_token:
            token = custom_token.strip()

        if token != expected_token:
            logger.warning("Rejecting unauthorized webhook alert: invalid or missing authentication token")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing webhook authentication token",
            )

    try:
        payload = await request.json()
    except Exception as e:
        logger.error(f"Invalid JSON payload received: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    meta = parse_alert_metadata(payload)
    rule = meta["rule"]
    priority = meta["priority"]
    namespace = meta["namespace"]
    pod_name = meta["pod_name"]
    container_id = meta["container_id"]

    logger.info(f"Received alert: rule='{rule}' priority='{priority}' target='{namespace}/{pod_name}'")

    # Filter by priority
    if priority not in ACTIONABLE_PRIORITIES:
        logger.debug(f"Ignoring low-priority alert: {priority}")
        return {
            "status": "ignored",
            "reason": f"Priority {priority} is not actionable",
        }

    # Verify we have target pod information
    if not namespace or not pod_name:
        logger.warning("Alert missing namespace or pod name. Cannot execute targeted containment.")
        return {
            "status": "skipped",
            "reason": "Missing pod or namespace identifier",
            "details": meta,
        }

    # Don't quarantine security infrastructure or kube-system pods
    if namespace in ("kube-system", "falco", "falco-response"):
        logger.info(f"Skipping quarantine on critical system namespace: {namespace}")
        return {
            "status": "skipped",
            "reason": f"Namespace {namespace} is exempt from automated isolation",
        }

    incident_id = f"inc-{uuid.uuid4().hex[:8]}"
    logger.warning(
        f"🚨 INITIATING AUTOMATED INCIDENT RESPONSE for {namespace}/{pod_name} (Incident: {incident_id})"
    )

    FALCO_ALERTS_TOTAL.labels(priority=priority, rule=rule).inc()

    start_time = time.time()

    # 1. Collect Forensic Evidence
    evidence_bundle = snapshot_evidence(
        k8s_client=k8s_client,
        namespace=namespace,
        pod_name=pod_name,
        incident_id=incident_id,
        alert_payload=payload,
    )

    # 2. Apply Network Quarantine Policy
    isolated = isolate_pod(
        k8s_client=k8s_client,
        namespace=namespace,
        pod_name=pod_name,
        incident_id=incident_id,
    )

    # 3. Label & Annotate Pod for Observability
    labeled = label_pod(
        k8s_client=k8s_client,
        namespace=namespace,
        pod_name=pod_name,
        incident_id=incident_id,
        rule_name=rule,
        priority=priority,
    )

    CONTAINMENT_DURATION.observe(time.time() - start_time)
    if isolated:
        CONTAINMENT_ACTIONS_TOTAL.labels(action="isolate", namespace=namespace).inc()
    if labeled:
        CONTAINMENT_ACTIONS_TOTAL.labels(action="label", namespace=namespace).inc()

    # 4. Dispatch Notifications
    actions_taken = {
        "isolated": bool(isolated),
        "labeled": bool(labeled),
        "evidence_files_count": len(evidence_bundle.get("captured_files", [])),
    }

    event = dispatch_alert(
        incident_id=incident_id,
        rule_name=rule,
        priority=priority,
        namespace=namespace,
        pod_name=pod_name,
        container_id=container_id,
        actions_taken=actions_taken,
    )

    record = {
        "incident_id": incident_id,
        "timestamp": payload.get("time"),
        "rule": rule,
        "priority": priority,
        "target": {"namespace": namespace, "pod": pod_name, "container_id": container_id},
        "actions": actions_taken,
        "evidence": evidence_bundle,
    }
    processed_incidents.append(record)

    return {
        "status": "contained",
        "incident_id": incident_id,
        "actions_taken": actions_taken,
    }
