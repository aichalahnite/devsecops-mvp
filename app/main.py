import os
import shutil
import subprocess
import zipfile
import uuid
import json

import docker

from fastapi import FastAPI, UploadFile, File, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles


app = FastAPI()

# Docker client (to run scanner containers)
docker_client = docker.from_env()

# -----------------------------
# Static & Templates
# -----------------------------
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# -----------------------------
# Upload directory
# -----------------------------
UPLOAD_DIR = "/tmp/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


# -----------------------------
# Home Page
# -----------------------------
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {"request": request}
    )


# -----------------------------
# Scan Endpoint
# -----------------------------
@app.post("/scan", response_class=HTMLResponse)
async def scan_code(request: Request, file: UploadFile = File(...)):

    # Create unique scan folder
    scan_id = str(uuid.uuid4())
    project_path = os.path.join(UPLOAD_DIR, scan_id)
    os.makedirs(project_path, exist_ok=True)

    zip_path = os.path.join(project_path, "code.zip")

    # Save uploaded file
    with open(zip_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Extract ZIP safely
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(project_path)
    except zipfile.BadZipFile:
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "results": {"error": "Invalid ZIP file"}
            }
        )

    results = {}

    # =====================================================
    # 1️⃣ Run Bandit (Local Python SAST)
    # =====================================================
    bandit_proc = subprocess.run(
        ["bandit", "-r", project_path, "-f", "json", "--quiet"],
        capture_output=True,
        text=True
    )

    raw_output = bandit_proc.stdout
    json_start = raw_output.find("{")
    cleaned_output = raw_output[json_start:] if json_start != -1 else raw_output

    try:
        bandit_json = json.loads(cleaned_output)
    except json.JSONDecodeError:
        bandit_json = {
            "error": "Bandit failed to produce valid JSON",
            "raw_output": raw_output
        }

    # Build severity summary
    summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    if "results" in bandit_json:
        for issue in bandit_json["results"]:
            severity = issue.get("issue_severity", "LOW")
            if severity in summary:
                summary[severity] += 1

    bandit_json["summary_counts"] = summary
    results["bandit"] = bandit_json


    # =====================================================
    # 2️⃣ Run Gitleaks via Docker
    # =====================================================
    try:
        gitleaks_output = docker_client.containers.run(
            "zricethezav/gitleaks:latest",
            [
                "detect",
                "-s", "/scan",
                "-f", "json"
            ],
            volumes={
                project_path: {"bind": "/scan", "mode": "ro"}
            },
            remove=True,
            stdout=True,
            stderr=True
        )

        gitleaks_json = json.loads(gitleaks_output.decode())

    except Exception as e:
        gitleaks_json = {"error": str(e)}

    results["gitleaks"] = gitleaks_json


    # =====================================================
    # 3️⃣ Run Trivy via Docker
    # =====================================================
    try:
        trivy_output = docker_client.containers.run(
            "aquasec/trivy:latest",
            [
                "fs",
                "--security-checks", "vuln,config",
                "/scan",
                "--format", "json"
            ],
            volumes={
                project_path: {"bind": "/scan", "mode": "ro"}
            },
            remove=True,
            stdout=True,
            stderr=True
        )

        trivy_json = json.loads(trivy_output.decode())

    except Exception as e:
        trivy_json = {"error": str(e)}

    results["trivy"] = trivy_json


    # =====================================================
    # Render Results
    # =====================================================
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "results": results
        }
    )
