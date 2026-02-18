import os
import shutil
import subprocess
import zipfile
import uuid
import json
import time
from threading import Thread

import docker

from fastapi import FastAPI, UploadFile, File, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

# =====================================================
# App & Docker
# =====================================================
app = FastAPI()
docker_client = docker.from_env()

# =====================================================
# Static & Templates
# =====================================================
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# =====================================================
# Upload directory
# =====================================================
UPLOAD_DIR = "/tmp/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# =====================================================
# GLOBAL SCAN STATE (IN-MEMORY MVP)
# =====================================================
SCAN_STATE = {}

def init_scan_state(scan_id):
    SCAN_STATE[scan_id] = {
        "current": "waiting",
        "progress": 0,
        "steps": {
            "bandit": {"status": "pending"},
            "gitleaks": {"status": "pending"},
            "trivy": {"status": "pending"},
            "dast": {"status": "pending"},
        }
    }

# =====================================================
# HOME
# =====================================================
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# =====================================================
# START SCAN (SAVE FILE FIRST, THEN THREAD)
# =====================================================
@app.post("/scan")
async def start_scan(file: UploadFile = File(...)):
    scan_id = str(uuid.uuid4())
    init_scan_state(scan_id)

    scan_dir = os.path.join(UPLOAD_DIR, scan_id)
    os.makedirs(scan_dir, exist_ok=True)

    zip_path = os.path.join(scan_dir, "code.zip")

    # ✅ CRITICAL FIX: save file while request is open
    with open(zip_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    # ✅ pass FILE PATH to background thread
    Thread(
        target=run_pipeline,
        args=(scan_id, zip_path),
        daemon=True
    ).start()

    return JSONResponse({"scan_id": scan_id})

# =====================================================
# POLLING ENDPOINT
# =====================================================
@app.get("/scan-status/{scan_id}")
def scan_status(scan_id: str):
    return SCAN_STATE.get(scan_id, {"error": "Scan not found"})

# =====================================================
# PIPELINE ORCHESTRATOR
# =====================================================
def run_pipeline(scan_id: str, zip_path: str):
    total_start = time.monotonic()
    project_path = os.path.join(UPLOAD_DIR, scan_id)

    # -----------------------------
    # Extract ZIP
    # -----------------------------
    try:
        with zipfile.ZipFile(zip_path, "r") as z:
            z.extractall(project_path)
    except Exception as e:
        SCAN_STATE[scan_id]["current"] = "failed"
        SCAN_STATE[scan_id]["error"] = str(e)
        return

    steps = SCAN_STATE[scan_id]["steps"]

    def run_step(name, func):
        SCAN_STATE[scan_id]["current"] = name
        steps[name]["status"] = "running"
        start = time.monotonic()

        try:
            result = func(project_path)
            steps[name]["result"] = result
            steps[name]["status"] = "done"
        except Exception as e:
            steps[name]["status"] = "failed"
            steps[name]["error"] = str(e)
            return False

        steps[name]["time"] = round(time.monotonic() - start, 2)
        return True

    static_ok = True

    # -----------------------------
    # STATIC SCANS
    # -----------------------------
    static_ok &= run_step("bandit", run_bandit)
    SCAN_STATE[scan_id]["progress"] = 25

    static_ok &= run_step("gitleaks", run_gitleaks)
    SCAN_STATE[scan_id]["progress"] = 50

    static_ok &= run_step("trivy", run_trivy)
    SCAN_STATE[scan_id]["progress"] = 75

    # -----------------------------
    # DYNAMIC SCAN (ONLY IF STATIC OK)
    # -----------------------------
    if static_ok:
        run_step("dast", run_dast)
    else:
        steps["dast"]["status"] = "skipped"

    SCAN_STATE[scan_id]["progress"] = 100
    SCAN_STATE[scan_id]["total_time"] = round(
        time.monotonic() - total_start, 2
    )
    SCAN_STATE[scan_id]["current"] = "finished"

# =====================================================
# SCAN IMPLEMENTATIONS
# =====================================================
def run_bandit(path):
    proc = subprocess.run(
        ["bandit", "-r", path, "-f", "json", "--quiet"],
        capture_output=True,
        text=True
    )
    return json.loads(proc.stdout or "{}")

def run_gitleaks(path):
    out = docker_client.containers.run(
        "zricethezav/gitleaks:latest",
        ["detect", "-s", "/scan", "-f", "json"],
        volumes={path: {"bind": "/scan", "mode": "ro"}},
        remove=True
    )
    return json.loads(out.decode())

def run_trivy(path):
    out = docker_client.containers.run(
        "aquasec/trivy:latest",
        ["fs", "/scan", "--format", "json"],
        volumes={path: {"bind": "/scan", "mode": "ro"}},
        remove=True
    )
    return json.loads(out.decode())

def run_dast(path):
    # MVP placeholder (no live app yet)
    time.sleep(3)
    return {
        "status": "completed",
        "note": "DAST baseline placeholder (static passed)"
    }
