import os
import shutil
import subprocess
import zipfile
import uuid
import json
import time
import socket
from threading import Thread

import docker
import yaml
import requests

from fastapi import FastAPI, UploadFile, File, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

# =====================================================
# CONFIG
# =====================================================
UPLOAD_DIR = "/tmp/uploads"
SCAN_TIMEOUT = 300
NETWORK_NAME = "scanner_net"

os.makedirs(UPLOAD_DIR, exist_ok=True)

app = FastAPI()
docker_client = docker.from_env()

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# =====================================================
# GLOBAL STATE
# =====================================================
SCAN_STATE = {}

def init_scan(scan_id):
    SCAN_STATE[scan_id] = {
        "current": "waiting",
        "progress": 0,
        "containers": [],
        "cancelled": False,
        "score": None,
        "start_time": time.time(),
        "steps": {
            "bandit": {"status": "pending", "start": None, "end": None},
            "gitleaks": {"status": "pending", "start": None, "end": None},
            "trivy": {"status": "pending", "start": None, "end": None},
            "dast": {"status": "pending", "start": None, "end": None},
        }
    }

# =====================================================
# UTILITIES
# =====================================================
def get_random_port():
    s = socket.socket()
    s.bind(('', 0))
    port = s.getsockname()[1]
    s.close()
    return port

def compute_security_score(results):
    high = medium = low = 0
    for tool in results.values():
        if not tool.get("result"):
            continue
        data = tool["result"]
        if isinstance(data, dict):
            findings = data.get("results", []) or data.get("Matches", [])
            for f in findings:
                sev = str(f.get("severity", f.get("Severity", ""))).lower()
                if "high" in sev:
                    high += 1
                elif "medium" in sev:
                    medium += 1
                elif "low" in sev:
                    low += 1
    score = 100 - (high * 10 + medium * 5 + low * 2)
    return max(score, 0)

def cleanup_scan(scan_id):
    for c in SCAN_STATE[scan_id]["containers"]:
        try:
            container = docker_client.containers.get(c)
            container.remove(force=True)
        except:
            pass

# =====================================================
# PROJECT DETECTION (RECURSIVE)
# =====================================================
def detect_project_type(path):
    dockerfile_path = None
    compose_path = None

    for root, dirs, files in os.walk(path):
        if "docker-compose.yml" in files and not compose_path:
            compose_path = os.path.join(root, "docker-compose.yml")
        if "Dockerfile" in files and not dockerfile_path:
            dockerfile_path = os.path.join(root, "Dockerfile")
        if compose_path and dockerfile_path:
            break

    if compose_path:
        return "docker-compose", os.path.dirname(compose_path)
    elif dockerfile_path:
        return "dockerfile", os.path.dirname(dockerfile_path)
    else:
        return "source-code", path

# =====================================================
# ROUTES
# =====================================================
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/scan")
async def start_scan(file: UploadFile = File(...)):
    scan_id = str(uuid.uuid4())
    init_scan(scan_id)

    scan_dir = os.path.join(UPLOAD_DIR, scan_id)
    os.makedirs(scan_dir, exist_ok=True)

    zip_path = os.path.join(scan_dir, "code.zip")
    with open(zip_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    Thread(target=run_pipeline, args=(scan_id, zip_path), daemon=True).start()
    return {"scan_id": scan_id}

@app.get("/scan-status/{scan_id}")
def status(scan_id: str):
    state = SCAN_STATE.get(scan_id)
    if not state:
        return {"error": "Not found"}

    now = time.time()
    for name, step in state["steps"].items():
        if step["start"]:
            end_time = step["end"] if step["end"] else now
            step["duration"] = round(end_time - step["start"], 2)
        else:
            step["duration"] = 0

    state["total_duration"] = round(now - state["start_time"], 2)
    return state

@app.post("/cancel/{scan_id}")
def cancel(scan_id: str):
    if scan_id in SCAN_STATE:
        SCAN_STATE[scan_id]["cancelled"] = True
        cleanup_scan(scan_id)
        SCAN_STATE[scan_id]["current"] = "cancelled"
        return {"status": "cancelled"}
    return {"error": "Not found"}

# =====================================================
# PIPELINE
# =====================================================
def run_pipeline(scan_id, zip_path):
    start_time = time.time()
    project_path = os.path.join(UPLOAD_DIR, scan_id)

    try:
        with zipfile.ZipFile(zip_path, "r") as z:
            z.extractall(project_path)
    except Exception as e:
        SCAN_STATE[scan_id]["current"] = "failed"
        SCAN_STATE[scan_id]["error"] = str(e)
        return

    steps = SCAN_STATE[scan_id]["steps"]

    def run_step(name, func):
        if SCAN_STATE[scan_id]["cancelled"]:
            return False

        SCAN_STATE[scan_id]["current"] = name
        steps[name]["status"] = "running"
        steps[name]["start"] = time.time()

        try:
            result = func(project_path, scan_id)
            steps[name]["result"] = result
            steps[name]["status"] = "done"
        except Exception as e:
            steps[name]["status"] = "failed"
            steps[name]["error"] = str(e)
            return False
        finally:
            steps[name]["end"] = time.time()

        return True

    if not run_step("bandit", run_bandit): return
    SCAN_STATE[scan_id]["progress"] = 25

    if not run_step("gitleaks", run_gitleaks): return
    SCAN_STATE[scan_id]["progress"] = 50

    if not run_step("trivy", run_trivy): return
    SCAN_STATE[scan_id]["progress"] = 75

    if not run_step("dast", run_dast): return
    SCAN_STATE[scan_id]["progress"] = 100

    SCAN_STATE[scan_id]["score"] = compute_security_score(steps)
    SCAN_STATE[scan_id]["total_time"] = round(time.time() - start_time, 2)
    SCAN_STATE[scan_id]["current"] = "finished"

# =====================================================
# STATIC SCANS
# =====================================================
def run_bandit(path, scan_id):
    proc = subprocess.run(
        ["bandit", "-r", path, "-f", "json", "--quiet"],
        capture_output=True,
        text=True,
        timeout=60
    )
    return json.loads(proc.stdout or "{}")

def run_gitleaks(path, scan_id):
    out = docker_client.containers.run(
        "zricethezav/gitleaks:latest",
        ["detect", "-s", "/scan", "-f", "json"],
        volumes={path: {"bind": "/scan", "mode": "ro"}},
        remove=True,
        mem_limit="256m",
        nano_cpus=500000000
    )
    return json.loads(out.decode() or "{}")

def run_trivy(path, scan_id):
    out = docker_client.containers.run(
        "aquasec/trivy:latest",
        ["fs", "/scan", "--format", "json"],
        volumes={path: {"bind": "/scan", "mode": "ro"}},
        remove=True,
        mem_limit="256m",
        nano_cpus=500000000
    )
    return json.loads(out.decode() or "{}")

# =====================================================
# DAST SCAN (DYNAMIC)
# =====================================================
def run_dast(path, scan_id):
    project_type, target_path = detect_project_type(path)
    results = {}

    try:
        if project_type == "docker-compose":
            # Run docker-compose services
            subprocess.run(["docker-compose", "up", "-d"], cwd=target_path, check=True)
            compose_file = os.path.join(target_path, "docker-compose.yml")
            with open(compose_file) as f:
                compose = yaml.safe_load(f)

            services = []
            for name, svc in compose.get("services", {}).items():
                ports = svc.get("ports", [])
                for p in ports:
                    host_port = int(p.split(":")[0])
                    services.append({"name": name, "port": host_port})

            # Health check
            for svc in services:
                healthy = False
                for _ in range(30):
                    try:
                        r = requests.get(f"http://localhost:{svc['port']}", timeout=1)
                        if r.status_code < 500:
                            healthy = True
                            break
                    except:
                        time.sleep(1)
                if not healthy:
                    results[svc["name"]] = {"error": "Service did not start in time"}

            # Run ZAP per service
            for svc in services:
                if "error" in results.get(svc["name"], {}):
                    continue
                zap_output = docker_client.containers.run(
                    "owasp/zap2docker-stable",
                    [
                        "zap-baseline.py",
                        "-t", f"http://host.docker.internal:{svc['port']}",
                        "-J", f"{svc['name']}_report.json"
                    ],
                    network_mode="host",
                    remove=True,
                    mem_limit="512m",
                    nano_cpus=800000000
                )
                try:
                    results[svc["name"]] = json.loads(zap_output.decode())
                except:
                    results[svc["name"]] = {"raw": zap_output.decode()}

            # Cleanup docker-compose
            subprocess.run(["docker-compose", "down"], cwd=target_path, check=True)

        elif project_type == "dockerfile":
            # Single Dockerfile
            image_tag = f"temp_image_{scan_id}"
            container_name = f"temp_container_{scan_id}"
            docker_client.images.build(path=target_path, tag=image_tag)
            container = docker_client.containers.run(
                image_tag,
                name=container_name,
                detach=True,
                network=NETWORK_NAME,
                mem_limit="512m",
                nano_cpus=800000000
            )
            SCAN_STATE[scan_id]["containers"].append(container_name)

            # Health check
            healthy = False
            for _ in range(30):
                container.reload()
                if container.status == "exited":
                    raise Exception("Target container exited unexpectedly")
                try:
                    requests.get(f"http://{container_name}:8000", timeout=1)
                    healthy = True
                    break
                except:
                    time.sleep(1)
            if not healthy:
                raise Exception("Target container did not become ready in time")

            zap_output = docker_client.containers.run(
                "owasp/zap2docker-stable",
                [
                    "zap-baseline.py",
                    "-t", f"http://{container_name}:8000",
                    "-J", "report.json"
                ],
                network=NETWORK_NAME,
                remove=True,
                mem_limit="512m",
                nano_cpus=800000000
            )
            try:
                results["target"] = json.loads(zap_output.decode())
            except:
                results["target"] = {"raw": zap_output.decode()}

            # Cleanup
            try:
                docker_client.containers.get(container_name).remove(force=True)
            except:
                pass
            try:
                docker_client.images.remove(image_tag, force=True)
            except:
                pass

        else:
            results["error"] = "No Dockerfile or docker-compose.yml found; cannot run DAST"

        return results

    except Exception as e:
        return {"error": str(e)}
