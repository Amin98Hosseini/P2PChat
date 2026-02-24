#!/usr/bin/env python3
"""Start P2PChat TCP server + web client backend together.

Usage:
  python run_all.py
  python run_all.py --host 0.0.0.0 --web-port 8000
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run P2PChat server and web backend together")
    parser.add_argument("--host", default="0.0.0.0", help="Web app bind host (default: 0.0.0.0)")
    parser.add_argument("--web-port", type=int, default=8000, help="Web app port (default: 8000)")
    return parser


def spawn_processes(repo_root: Path, host: str, web_port: int) -> list[subprocess.Popen]:
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    server_cmd = [sys.executable, "ServerCode.py"]
    web_cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "web_client.web_app:app",
        "--host",
        host,
        "--port",
        str(web_port),
    ]

    print("[launcher] Starting chat server (ServerCode.py default port is 12345)...")
    server_proc = subprocess.Popen(server_cmd, cwd=str(repo_root), env=env)

    print(f"[launcher] Starting web app on http://{host}:{web_port} ...")
    web_proc = subprocess.Popen(web_cmd, cwd=str(repo_root), env=env)

    return [server_proc, web_proc]


def terminate_all(processes: list[subprocess.Popen], timeout: float = 5.0) -> None:
    for proc in processes:
        if proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass

    deadline = time.time() + timeout
    for proc in processes:
        while proc.poll() is None and time.time() < deadline:
            time.sleep(0.1)

    for proc in processes:
        if proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass


def main() -> int:
    args = build_parser().parse_args()

    repo_root = Path(__file__).resolve().parent
    if not (repo_root / "ServerCode.py").exists():
        print("[launcher] Error: ServerCode.py not found next to run_all.py")
        return 1

    processes = spawn_processes(repo_root, args.host, args.web_port)

    try:
        while True:
            for proc in processes:
                code = proc.poll()
                if code is not None:
                    print(f"[launcher] A process exited early with code {code}. Stopping all.")
                    terminate_all(processes)
                    return code if code != 0 else 1
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[launcher] Ctrl+C received. Stopping processes...")
        terminate_all(processes)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
