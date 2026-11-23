"""
Unit and integration tests for Guardian FastAPI Live Demo Server.
"""

from fastapi.testclient import TestClient
from guardian.server import app

client = TestClient(app)


def test_server_status_endpoint():
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert "groq_configured" in data
    assert "target_available" in data


def test_server_dashboard_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert "Software Supply Chain Guardian" in response.text


def test_server_results_endpoint():
    response = client.get("/api/results")
    assert response.status_code == 200
    data = response.json()
    assert "components" in data
    assert "findings" in data
    assert "agent_results" in data


def test_server_markdown_report_endpoint():
    response = client.get("/api/report/markdown")
    assert response.status_code == 200
    assert "Software Supply Chain Guardian" in response.text

