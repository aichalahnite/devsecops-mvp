import os
import shutil
import subprocess
import zipfile
import uuid
import json
import time
import socket
from threading import Thread
from io import BytesIO

import docker
import requests
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from fastapi import FastAPI, UploadFile, File, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

# =====================================================
# CONFIG
# =====================================================
UPLOAD_DIR = "/tmp/uploads"
SCAN_TIMEOUT = 300
NETWORK_NAME = "scanner_net"
COMMON_WEB_PORTS = [80, 8000, 5000, 3000]

os.makedirs(UPLOAD_DIR, exist_ok=True)

app = FastAPI()
docker_client = docker.from_env()

# Ensure network exists
try:
    docker_client.networks.get(NETWORK_NAME)
except docker.errors.NotFound:
    docker_client.networks.create(NETWORK_NAME, driver="bridge")

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
        "end_time": None,
        "total_duration": None,
        "steps": {
            "bandit": {"status": "pending", "start_time": None, "duration": None},
            "gitleaks": {"status": "pending", "start_time": None, "duration": None},
            "trivy": {"status": "pending", "start_time": None, "duration": None},
            "dast": {"status": "pending", "start_time": None, "duration": None},
        }
    }

# =====================================================
# UTILITIES
# =====================================================
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

        if isinstance(data, dict) and "site" in data:
            for site in data.get("site", []):
                for alert in site.get("alerts", []):
                    risk = alert.get("riskdesc", "").lower()
                    if "high" in risk:
                        high += 1
                    elif "medium" in risk:
                        medium += 1
                    elif "low" in risk:
                        low += 1

    score = 100 - (high * 10 + medium * 5 + low * 2)
    return max(score, 0)

def generate_pdf_report(scan_data):
    """Generate a PDF report from scan results."""
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=1  # Center
    )
    story.append(Paragraph("DevSecOps Security Scan Report", title_style))
    story.append(Spacer(1, 12))

    # Summary section
    summary_style = styles['Heading2']
    story.append(Paragraph("Scan Summary", summary_style))
    story.append(Spacer(1, 12))

    score = scan_data.get('score', 'N/A')
    duration = scan_data.get('total_duration', 'N/A')
    start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(scan_data.get('start_time', time.time())))

    summary_data = [
        ['Security Score', f'{score}/100'],
        ['Scan Duration', f'{duration} seconds'],
        ['Start Time', start_time],
        ['Status', scan_data.get('current', 'Unknown')]
    ]

    summary_table = Table(summary_data, colWidths=[200, 300])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))

    # Results section
    story.append(Paragraph("Detailed Results", styles['Heading2']))
    story.append(Spacer(1, 12))

    steps = scan_data.get('steps', {})
    for tool_name, tool_data in steps.items():
        story.append(Paragraph(f"{tool_name.upper()} Results", styles['Heading3']))
        story.append(Spacer(1, 6))

        status = tool_data.get('status', 'Unknown')
        duration = tool_data.get('duration', 'N/A')

        tool_info = f"Status: {status} | Duration: {duration}s"
        story.append(Paragraph(tool_info, styles['Normal']))
        story.append(Spacer(1, 6))

        result = tool_data.get('result')
        if result:
            # Convert result to formatted text
            result_text = json.dumps(result, indent=2)
            # Truncate if too long
            if len(result_text) > 2000:
                result_text = result_text[:2000] + "\n... (truncated)"
            story.append(Paragraph(f"<pre>{result_text}</pre>", styles['Normal']))
        else:
            story.append(Paragraph("No results available", styles['Normal']))

        story.append(Spacer(1, 12))

    doc.build(story)
    buffer.seek(0)
    return buffer

def cleanup_scan(scan_id):
    for c in SCAN_STATE[scan_id]["containers"]:
        try:
            docker_client.containers.get(c).remove(force=True)
        except:
            pass

# =====================================================
# PROJECT DETECTION
# =====================================================
def detect_all_targets(path):
    targets = []
    for root, _, files in os.walk(path):
        if "Dockerfile" in files:
            targets.append(root)
    return targets

# =====================================================
# ENV FILE HANDLING (NEW)
# =====================================================
def find_env_file(base_path):
    """
    Recursively find the closest .env file, ignoring dependency dirs.
    """
    ignore_dirs = {".git", "__pycache__", "venv", ".venv", "node_modules"}
    candidates = []

    for root, dirs, files in os.walk(base_path):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]

        if ".env" in files:
            depth = root.count(os.sep)
            candidates.append((depth, os.path.join(root, ".env")))

    if not candidates:
        return None

    candidates.sort(key=lambda x: x[0])
    return candidates[0][1]

def load_env_file(env_path):
    env = {}
    if not env_path or not os.path.exists(env_path):
        return env

    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            env[key.strip()] = value.strip().strip('"').strip("'")
    return env

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
    scan_data = SCAN_STATE.get(scan_id)
    if not scan_data:
        return {"error": "Not found"}
    
    # Return a copy with current elapsed time if scan is still running
    response_data = scan_data.copy()
    if scan_data.get("end_time") is None:
        response_data["total_duration"] = round(time.time() - scan_data["start_time"], 2)
    
    # Calculate current duration for running steps
    current_time = time.time()
    for step_name, step_data in response_data["steps"].items():
        if step_data["status"] == "running" and step_data["start_time"]:
            response_data["steps"][step_name]["duration"] = round(current_time - step_data["start_time"], 2)
    
    return response_data

@app.post("/cancel/{scan_id}")
def cancel(scan_id: str):
    if scan_id in SCAN_STATE:
        SCAN_STATE[scan_id]["cancelled"] = True
        cleanup_scan(scan_id)
        SCAN_STATE[scan_id]["current"] = "cancelled"
        return {"status": "cancelled"}
    return {"error": "Not found"}

@app.get("/download-pdf/{scan_id}")
def download_pdf(scan_id: str):
    scan_data = SCAN_STATE.get(scan_id)
    if not scan_data:
        return {"error": "Scan not found"}

    if scan_data.get("current") != "finished":
        return {"error": "Scan not completed yet"}

    pdf_buffer = generate_pdf_report(scan_data)

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=security-scan-{scan_id}.pdf"}
    )

# =====================================================
# PIPELINE
# =====================================================
def run_pipeline(scan_id, zip_path):
    project_path = os.path.join(UPLOAD_DIR, scan_id)

    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(project_path)

    def run_step(name, func):
        SCAN_STATE[scan_id]["current"] = name
        SCAN_STATE[scan_id]["steps"][name]["status"] = "running"
        start = time.time()
        SCAN_STATE[scan_id]["steps"][name]["start_time"] = start

        result = func(project_path, scan_id)

        SCAN_STATE[scan_id]["steps"][name].update({
            "status": "done",
            "duration": round(time.time() - start, 2),
            "result": result
        })

    run_step("bandit", run_bandit)
    SCAN_STATE[scan_id]["progress"] = 25

    run_step("gitleaks", run_gitleaks)
    SCAN_STATE[scan_id]["progress"] = 50

    run_step("trivy", run_trivy)
    SCAN_STATE[scan_id]["progress"] = 75

    run_step("dast", run_dast)
    SCAN_STATE[scan_id]["progress"] = 100

    SCAN_STATE[scan_id]["score"] = compute_security_score(SCAN_STATE[scan_id]["steps"])
    SCAN_STATE[scan_id]["end_time"] = time.time()
    SCAN_STATE[scan_id]["total_duration"] = round(
        SCAN_STATE[scan_id]["end_time"] - SCAN_STATE[scan_id]["start_time"], 2
    )
    SCAN_STATE[scan_id]["current"] = "finished"

    cleanup_scan(scan_id)

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
        remove=True
    )
    return json.loads(out.decode() or "{}")

def run_trivy(path, scan_id):
    out = docker_client.containers.run(
        "aquasec/trivy:latest",
        ["fs", "/scan", "--format", "json"],
        volumes={path: {"bind": "/scan", "mode": "ro"}},
        remove=True
    )
    return json.loads(out.decode() or "{}")

# =====================================================
# DAST — FIXED, HARDENED, ENV-AWARE
# =====================================================
def run_dast(path, scan_id):
    targets = detect_all_targets(path)
    results = {}

    if not targets:
        return {"error": "No Dockerfile found"}

    # 🔐 ENV discovery (once per scan)
    env_path = find_env_file(path)
    project_env = load_env_file(env_path)

    if env_path:
        print(f"[DAST] Using .env file: {env_path}")
        print(f"[DAST] Loaded env keys: {list(project_env.keys())}")
    else:
        print("[DAST] No .env file found")

    default_env = {"ENV": "production"}
    merged_env = {**default_env, **project_env}

    for idx, target_path in enumerate(targets, 1):
        label = f"target_{idx}"
        image_tag = f"{label}_img_{scan_id}"
        container_name = f"{label}_ctr_{scan_id}"

        try:
            docker_client.images.build(path=target_path, tag=image_tag)

            container = docker_client.containers.run(
                image_tag,
                name=container_name,
                detach=True,
                network=NETWORK_NAME,
                environment=merged_env
            )

            SCAN_STATE[scan_id]["containers"].append(container_name)
            time.sleep(5)
            container.reload()

            exposed = container.attrs["Config"].get("ExposedPorts")

            if not exposed:
                results[label] = {
                    "info": "Non-HTTP service detected",
                    "logs": container.logs().decode()
                }
                container.remove(force=True)
                docker_client.images.remove(image_tag, force=True)
                continue

            detected_port = None
            for _ in range(30):
                for p in COMMON_WEB_PORTS:
                    try:
                        s = socket.create_connection((container_name, p), timeout=2)
                        s.close()
                        detected_port = p
                        break
                    except:
                        pass
                if detected_port:
                    break
                time.sleep(1)

            if not detected_port:
                results[label] = {
                    "error": "Service did not become reachable",
                    "logs": container.logs().decode()
                }
                container.remove(force=True)
                docker_client.images.remove(image_tag, force=True)
                continue

            target_url = f"http://{container_name}:{detected_port}"

            zap = docker_client.containers.run(
                "owasp/zap2docker-stable",
                ["zap-baseline.py", "-t", target_url, "-J", "/zap/wrk/report.json"],
                network=NETWORK_NAME,
                volumes={target_path: {"bind": "/zap/wrk", "mode": "rw"}},
                detach=True
            )

            zap.wait(timeout=SCAN_TIMEOUT)
            zap_logs = zap.logs().decode()

            report_file = os.path.join(target_path, "report.json")
            report = json.load(open(report_file)) if os.path.exists(report_file) else {}

            results[label] = {
                "port": detected_port,
                "zap_logs": zap_logs,
                "report": report
            }

            zap.remove(force=True)
            container.remove(force=True)
            docker_client.images.remove(image_tag, force=True)

        except Exception as e:
            results[label] = {"error": str(e)}
            try:
                container.remove(force=True)
                docker_client.images.remove(image_tag, force=True)
            except:
                pass

    return results
