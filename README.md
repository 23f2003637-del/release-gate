# CI/CD Container Release Gate

FastAPI service implementing `POST /release-gate`, a deterministic policy
endpoint that decides whether a GitHub Actions run may promote a container
image, per the GA7 rules (least-privilege permissions, safe PR triggers,
complete test matrix, pinned actions, hardened Docker image, production
push-to-main + approval gate).

## Run locally

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

## Deploy to Render

1. Push this repo to GitHub (public repo).
2. On Render.com: New -> Web Service -> connect this repo.
3. Build command: `pip install -r requirements.txt`
4. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. Once live, your `serviceUrl` is `https://<your-service>.onrender.com`.

## GitHub Actions evidence

The workflow at `.github/workflows/release-gate.yml` is named
`TDS GA7 Release Gate`, runs on push to `main`, includes a step named
`TDS identity: 23f2003637@ds.study.iitm.ac.in`, and runs the pytest suite in
`test_release_gate.py` against the release-gate logic.

Submit the **workflow page URL** (not a run URL), e.g.:
`https://github.com/<OWNER>/<REPO>/actions/workflows/release-gate.yml`
