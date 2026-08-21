from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

SAFE_PREVIEW = {
    "target": "preview",
    "event": "pull_request",
    "ref": "refs/heads/feature-x",
    "workflow": {
        "trigger": "pull_request",
        "permissions": {"contents": "read", "packages": "write", "id-token": "none"},
        "testsPassed": True,
        "matrixComplete": True,
        "failFast": False,
        "actions": [
            {"owner": "actions", "name": "checkout", "ref": "v4"},
            {"owner": "docker", "name": "build-push-action", "ref": "a" * 40},
        ],
    },
    "image": {
        "multiStage": True,
        "runsAsRoot": False,
        "secretMode": "buildkit",
        "criticalVulnerabilities": 0,
        "digestPinned": True,
    },
}

SAFE_PRODUCTION = {
    "target": "production",
    "event": "push",
    "ref": "refs/heads/main",
    "workflow": {
        "trigger": "push",
        "permissions": {"contents": "read", "packages": "write", "id-token": "none"},
        "testsPassed": True,
        "matrixComplete": True,
        "failFast": False,
        "environmentApproval": True,
        "actions": [{"owner": "actions", "name": "checkout", "ref": "v4"}],
    },
    "image": {
        "multiStage": True,
        "runsAsRoot": False,
        "secretMode": "none",
        "criticalVulnerabilities": 0,
        "digestPinned": True,
    },
}


def post(payload):
    r = client.post("/release-gate", json=payload)
    assert r.status_code == 200
    return r.json()


def test_safe_preview_promotes():
    result = post(SAFE_PREVIEW)
    assert result["decision"] == "promote"
    assert result["violations"] == []


def test_safe_production_promotes():
    result = post(SAFE_PRODUCTION)
    assert result["decision"] == "promote"
    assert result["violations"] == []


def test_excess_permission_and_mutable_action():
    payload = {
        **SAFE_PREVIEW,
        "workflow": {
            **SAFE_PREVIEW["workflow"],
            "permissions": {
                "contents": "read",
                "packages": "write",
                "id-token": "none",
                "issues": "write",
            },
            "actions": [{"owner": "docker", "name": "build-push-action", "ref": "main"}],
        },
    }
    result = post(payload)
    assert result["decision"] == "block"
    assert set(result["violations"]) == {"EXCESS_PERMISSION", "MUTABLE_ACTION"}


def test_unsafe_pr_trigger():
    payload = {
        **SAFE_PREVIEW,
        "workflow": {**SAFE_PREVIEW["workflow"], "trigger": "pull_request_target"},
    }
    result = post(payload)
    assert "UNSAFE_PR_TRIGGER" in result["violations"]


def test_tests_incomplete():
    payload = {
        **SAFE_PREVIEW,
        "workflow": {**SAFE_PREVIEW["workflow"], "testsPassed": False},
    }
    result = post(payload)
    assert "TESTS_INCOMPLETE" in result["violations"]


def test_image_failures():
    payload = {
        **SAFE_PREVIEW,
        "image": {
            "multiStage": False,
            "runsAsRoot": True,
            "secretMode": "arg",
            "criticalVulnerabilities": 3,
            "digestPinned": False,
        },
    }
    result = post(payload)
    expected = {
        "SINGLE_STAGE_IMAGE",
        "ROOT_RUNTIME",
        "SECRET_IN_LAYER",
        "CRITICAL_CVE",
        "UNPINNED_IMAGE",
    }
    assert expected.issubset(set(result["violations"]))


def test_production_invalid_ref_and_no_approval():
    payload = {
        **SAFE_PRODUCTION,
        "event": "pull_request",
        "workflow": {**SAFE_PRODUCTION["workflow"], "environmentApproval": False},
    }
    result = post(payload)
    assert "INVALID_PRODUCTION_REF" in result["violations"]
    assert "APPROVAL_REQUIRED" in result["violations"]
