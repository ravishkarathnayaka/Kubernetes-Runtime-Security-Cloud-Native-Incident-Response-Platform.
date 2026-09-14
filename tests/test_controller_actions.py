"""Unit tests mocking Kubernetes API calls for automated containment controller actions."""

import json
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient
from kubernetes import client
from kubernetes.client.exceptions import ApiException

from response_controller.actions.alert_dispatcher import dispatch_alert
from response_controller.actions.isolate_pod import isolate_pod
from response_controller.actions.label_pod import label_pod
from response_controller.actions.snapshot_evidence import snapshot_evidence
from response_controller.app import app
from response_controller.k8s_client import KubernetesClient


@pytest.fixture
def mock_k8s_client():
    """Creates a KubernetesClient instance with mocked API clients."""
    core_mock = MagicMock(spec=client.CoreV1Api)
    core_mock.api_client = MagicMock()
    net_mock = MagicMock(spec=client.NetworkingV1Api)
    k8s = KubernetesClient(core_v1=core_mock, networking_v1=net_mock)
    return k8s


@pytest.fixture
def test_client():
    """Returns a FastAPI TestClient."""
    return TestClient(app)


# ---------------------------------------------------------------------------
# Test isolate_pod Action
# ---------------------------------------------------------------------------
def test_isolate_pod_success(mock_k8s_client):
    """Test applying quarantine NetworkPolicy successfully."""
    mock_k8s_client.networking_v1.create_namespaced_network_policy.return_value = MagicMock()

    success = isolate_pod(
        k8s_client=mock_k8s_client,
        namespace="demo",
        pod_name="test-pod-1",
        incident_id="inc-12345",
    )

    assert success is True
    mock_k8s_client.networking_v1.create_namespaced_network_policy.assert_called_once()
    call_args = mock_k8s_client.networking_v1.create_namespaced_network_policy.call_args
    assert call_args.kwargs["namespace"] == "demo"
    policy_body = call_args.kwargs["body"]
    assert policy_body.metadata.name == "quarantine-test-pod-1"
    assert policy_body.spec.policy_types == ["Ingress", "Egress"]
    assert policy_body.spec.ingress == []
    assert policy_body.spec.egress == []


def test_isolate_pod_conflict_replaces(mock_k8s_client):
    """Test that existing NetworkPolicy (HTTP 409) is replaced safely."""
    conflict_exc = ApiException(status=409, reason="Conflict")
    mock_k8s_client.networking_v1.create_namespaced_network_policy.side_effect = conflict_exc
    mock_k8s_client.networking_v1.replace_namespaced_network_policy.return_value = MagicMock()

    success = isolate_pod(
        k8s_client=mock_k8s_client,
        namespace="demo",
        pod_name="test-pod-conflict",
        incident_id="inc-9999",
    )

    assert success is True
    mock_k8s_client.networking_v1.replace_namespaced_network_policy.assert_called_once()


# ---------------------------------------------------------------------------
# Test label_pod Action
# ---------------------------------------------------------------------------
def test_label_pod_success(mock_k8s_client):
    """Test patching compromised pod metadata with quarantine tags."""
    mock_k8s_client.core_v1.patch_namespaced_pod.return_value = MagicMock()

    success = label_pod(
        k8s_client=mock_k8s_client,
        namespace="prod",
        pod_name="backend-api-xyz",
        incident_id="inc-abcde",
        rule_name="Unauthorized Service Account Token Access",
        priority="CRITICAL",
    )

    assert success is True
    mock_k8s_client.core_v1.patch_namespaced_pod.assert_called_once()
    call_kwargs = mock_k8s_client.core_v1.patch_namespaced_pod.call_args.kwargs
    assert call_kwargs["name"] == "backend-api-xyz"
    assert call_kwargs["namespace"] == "prod"
    body = call_kwargs["body"]
    assert body["metadata"]["labels"]["security.incident/quarantined"] == "true"
    assert body["metadata"]["annotations"]["security.incident/priority"] == "CRITICAL"


# ---------------------------------------------------------------------------
# Test snapshot_evidence Action
# ---------------------------------------------------------------------------
def test_snapshot_evidence(mock_k8s_client, tmp_path):
    """Test gathering forensic bundle (pod spec, container logs, alert context)."""
    # Mock pod object
    pod_mock = MagicMock(spec=client.V1Pod)
    pod_mock.metadata.name = "victim-pod"
    pod_mock.spec.node_name = "worker-node-1"
    container_mock = MagicMock()
    container_mock.name = "app"
    pod_mock.spec.containers = [container_mock]
    pod_mock.status.phase = "Running"
    pod_mock.status.pod_ip = "192.168.1.55"

    mock_k8s_client.core_v1.read_namespaced_pod.return_value = pod_mock
    mock_k8s_client.core_v1.read_namespaced_pod_log.return_value = "2026-09-14 12:00:00 Suspicious activity observed"
    mock_k8s_client.core_v1.api_client.sanitize_for_serialization.return_value = {
        "metadata": {"name": "victim-pod"}
    }

    alert_payload = {
        "rule": "Interactive Shell Spawned Inside Pod",
        "priority": "Warning",
        "output": "Shell opened",
    }

    evidence = snapshot_evidence(
        k8s_client=mock_k8s_client,
        namespace="default",
        pod_name="victim-pod",
        incident_id="inc-forensics-1",
        alert_payload=alert_payload,
        evidence_base_dir=str(tmp_path),
    )

    assert evidence["incident_id"] == "inc-forensics-1"
    assert evidence["pod_status"] == "Running"
    assert evidence["node_name"] == "worker-node-1"
    assert len(evidence["captured_files"]) >= 3

    # Verify log content written
    log_file = tmp_path / "inc-forensics-1" / "container_app.log"
    assert log_file.exists()
    assert "Suspicious activity observed" in log_file.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Test alert_dispatcher Action
# ---------------------------------------------------------------------------
def test_alert_dispatcher():
    """Test alert dispatcher formatting and external post."""
    with patch("requests.post") as mock_post:
        mock_post.return_value.status_code = 200

        result = dispatch_alert(
            incident_id="inc-777",
            rule_name="Interactive Shell Spawned Inside Pod",
            priority="WARNING",
            namespace="demo",
            pod_name="shell-pod",
            container_id="cont-1234",
            actions_taken={"isolated": True, "labeled": True, "evidence_files_count": 4},
            webhook_url="https://hooks.slack.com/services/mock/token",
        )

        assert result["event_type"] == "SECURITY_INCIDENT_CONTAINED"
        assert result["incident_id"] == "inc-777"
        assert result["response_actions"]["network_isolation"] is True
        mock_post.assert_called_once()


# ---------------------------------------------------------------------------
# Test FastAPI Webhook Endpoint
# ---------------------------------------------------------------------------
def test_healthz_endpoint(test_client):
    """Test health check endpoint."""
    response = test_client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_metrics_endpoint(test_client):
    """Test Prometheus metrics scrape endpoint."""
    response = test_client.get("/metrics")
    assert response.status_code == 200
    assert "falco_alerts_total" in response.text
    assert "containment_actions_total" in response.text


def test_webhook_low_priority_ignored(test_client):
    """Test that low-priority alerts (e.g. INFORMATIONAL) are ignored."""
    payload = {
        "rule": "System Metric Read",
        "priority": "Informational",
        "output": "Normal system read",
        "output_fields": {"k8s.ns.name": "demo", "k8s.pod.name": "demo-pod"},
    }
    response = test_client.post("/webhook", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ignored"


def test_webhook_system_namespace_exempt(test_client):
    """Test that kube-system or security namespaces are exempt from automated containment."""
    payload = {
        "rule": "Interactive Shell Spawned Inside Pod",
        "priority": "Warning",
        "output": "Shell opened in kube-system",
        "output_fields": {"k8s.ns.name": "kube-system", "k8s.pod.name": "coredns-1234"},
    }
    response = test_client.post("/webhook", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "skipped"


def test_webhook_containment_pipeline(test_client, tmp_path):
    """Test end-to-end containment triggered via webhook."""
    payload = {
        "rule": "Unauthorized Service Account Token Access",
        "priority": "Critical",
        "output": "CRITICAL: ServiceAccount token harvest detected (pod=compromised-app ns=finance c_id=abc12345)",
        "output_fields": {
            "k8s.ns.name": "finance",
            "k8s.pod.name": "compromised-app",
            "container.id": "abc12345",
        },
    }

    with patch("response_controller.app.isolate_pod", return_value=True), \
         patch("response_controller.app.label_pod", return_value=True), \
         patch("response_controller.app.snapshot_evidence", return_value={"captured_files": ["f1", "f2"]}):

        response = test_client.post("/webhook", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "contained"
        assert "incident_id" in data
        assert data["actions_taken"]["isolated"] is True
        assert data["actions_taken"]["labeled"] is True

        # Test incident retrieval
        inc_id = data["incident_id"]
        detail_resp = test_client.get(f"/incidents/{inc_id}")
        assert detail_resp.status_code == 200
        assert detail_resp.json()["incident_id"] == inc_id

        # Test list incidents
        list_resp = test_client.get("/incidents")
        assert list_resp.status_code == 200
        assert list_resp.json()["total"] >= 1


def test_incident_not_found(test_client):
    """Test fetching nonexistent incident returns 404."""
    response = test_client.get("/incidents/nonexistent-id-999")
    assert response.status_code == 404


def test_webhook_missing_target_skipped(test_client):
    """Test webhook with no pod/namespace information is skipped."""
    payload = {
        "rule": "Interactive Shell Spawned Inside Pod",
        "priority": "Critical",
        "output": "Some generic output without identifiers",
    }
    response = test_client.post("/webhook", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "skipped"


def test_webhook_regex_fallback_parsing(test_client):
    """Test parsing metadata from output string when output_fields is empty."""
    payload = {
        "rule": "Interactive Shell Spawned Inside Pod",
        "priority": "Critical",
        "output": "Notice: Interactive terminal spawned (user=root pod=injected-pod ns=staging c_id=docker123)",
    }
    with patch("response_controller.app.isolate_pod", return_value=True), \
         patch("response_controller.app.label_pod", return_value=True), \
         patch("response_controller.app.snapshot_evidence", return_value={"captured_files": []}):

        response = test_client.post("/webhook", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "contained"


def test_k8s_client_list_quarantined_pods(mock_k8s_client):
    """Test listing quarantined pods with CoreV1Api."""
    pod_item = MagicMock()
    pod_item.metadata.name = "isolated-pod"
    pod_item.metadata.namespace = "demo"
    pod_item.status.phase = "Running"
    pod_item.metadata.annotations = {"security.incident/timestamp": "2026-09-14T12:00:00Z"}

    pod_list_mock = MagicMock()
    pod_list_mock.items = [pod_item]
    mock_k8s_client.core_v1.list_namespaced_pod.return_value = pod_list_mock

    result = mock_k8s_client.list_quarantined_pods(namespace="demo")
    assert len(result) == 1
    assert result[0]["name"] == "isolated-pod"
    assert result[0]["status"] == "Running"


def test_webhook_token_auth_rejected(test_client, monkeypatch):
    """Test webhook with invalid or missing token when WEBHOOK_AUTH_TOKEN is set."""
    monkeypatch.setenv("WEBHOOK_AUTH_TOKEN", "secret-falco-token-123")
    payload = {"rule": "Test", "priority": "Critical"}
    response = test_client.post("/webhook", json=payload)
    assert response.status_code == 401
    assert "Invalid or missing" in response.json()["detail"]


def test_webhook_token_auth_accepted(test_client, monkeypatch):
    """Test webhook with valid Bearer token when WEBHOOK_AUTH_TOKEN is set."""
    monkeypatch.setenv("WEBHOOK_AUTH_TOKEN", "secret-falco-token-123")
    payload = {
        "rule": "System Metric",
        "priority": "Informational",
        "output": "Normal ping",
    }
    headers = {"Authorization": "Bearer secret-falco-token-123"}
    response = test_client.post("/webhook", json=payload, headers=headers)
    assert response.status_code == 200
    assert response.json()["status"] == "ignored"


