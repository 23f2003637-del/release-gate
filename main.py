import re
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional, Dict

app = FastAPI()

SHA_RE = re.compile(r"^[0-9a-f]{40}$")

REQUIRED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}


class ActionRef(BaseModel):
    owner: str
    name: str
    ref: str


class Workflow(BaseModel):
    trigger: str
    permissions: Dict[str, str]
    testsPassed: bool
    matrixComplete: bool
    failFast: bool
    actions: List[ActionRef]
    environmentApproval: Optional[bool] = False


class Image(BaseModel):
    multiStage: bool
    runsAsRoot: bool
    secretMode: str
    criticalVulnerabilities: int
    digestPinned: bool


class ReleaseGateRequest(BaseModel):
    target: str
    event: str
    ref: str
    workflow: Workflow
    image: Image


@app.get("/")
def root():
    return {"status": "ok", "service": "release-gate"}


@app.post("/release-gate")
def release_gate(req: ReleaseGateRequest):
    violations = []

    # 1. Least-privilege permissions
    if req.workflow.permissions != REQUIRED_PERMISSIONS:
        violations.append("EXCESS_PERMISSION")

    # 2. PR trigger safety
    if req.workflow.trigger == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")

    # 3. Tests / matrix / failFast
    if (
        not req.workflow.testsPassed
        or not req.workflow.matrixComplete
        or req.workflow.failFast
    ):
        violations.append("TESTS_INCOMPLETE")

    # 4. Action pinning
    mutable_found = False
    for action in req.workflow.actions:
        if action.owner == "actions":
            continue
        if not SHA_RE.match(action.ref):
            mutable_found = True
    if mutable_found:
        violations.append("MUTABLE_ACTION")

    # 5. Image checks
    if not req.image.multiStage:
        violations.append("SINGLE_STAGE_IMAGE")

    if req.image.runsAsRoot:
        violations.append("ROOT_RUNTIME")

    if req.image.secretMode not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if req.image.criticalVulnerabilities != 0:
        violations.append("CRITICAL_CVE")

    if not req.image.digestPinned:
        violations.append("UNPINNED_IMAGE")

    # 6. Production-only checks
    if req.target == "production":
        if not (req.event == "push" and req.ref == "refs/heads/main"):
            violations.append("INVALID_PRODUCTION_REF")
        if not req.workflow.environmentApproval:
            violations.append("APPROVAL_REQUIRED")

    decision = "promote" if not violations else "block"
    return {"decision": decision, "violations": violations}
