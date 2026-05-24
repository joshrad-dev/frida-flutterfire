#!/usr/bin/env python3
import argparse
import base64
import json
import os
import pty
import re
import select
import signal
import subprocess
import sys
from datetime import datetime
from pathlib import Path


MARKER = "__FIREBASE_TRACE_FILE__ "
DEFAULT_OUT_PREFIX = "firebase-trace-output"


def default_output_dir() -> str:
    return f"{DEFAULT_OUT_PREFIX}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"


def safe_file_name(name: str) -> str:
    name = os.path.basename(name or "trace.bin")
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return name or "trace.bin"


def build_frida_command(args: argparse.Namespace) -> list[str]:
    cmd = ["frida"]

    if args.usb:
        cmd.append("-U")
    if args.remote:
        cmd.extend(["-H", args.remote])

    if isinstance(args.spawn, str) and args.spawn:
        args.target = args.spawn

    if args.spawn:
        cmd.extend(["-f", args.target])
        if args.pause:
            cmd.append("--pause")
    else:
        cmd.extend(["-n", args.target])

    cmd.extend(["-l", args.script])
    return cmd


def write_payload(out_dir: Path, payload: dict) -> Path:
    file_name = safe_file_name(payload.get("fileName"))
    path = out_dir / file_name

    content = payload.get("content", "")
    encoding = payload.get("encoding")
    if encoding in ("base64", "base64-utf8"):
        data = base64.b64decode(content)
    else:
        data = str(content).encode("utf-8")

    path.write_bytes(data)
    return path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run firebase-trace.js with Frida and write trace artifacts from the host process."
    )
    parser.add_argument("-n", "--target", default="App Name", help="process name or bundle id")
    parser.add_argument("-l", "--script", default="firebase-trace.js", help="Frida agent script")
    parser.add_argument(
        "-o",
        "--out",
        default=None,
        help=f"host output directory; defaults to {DEFAULT_OUT_PREFIX}-YYYYMMDD-HHMMSS",
    )
    parser.add_argument("-U", "--usb", action="store_true", help="attach to USB device")
    parser.add_argument("-H", "--remote", help="connect to remote frida-server host")
    parser.add_argument(
        "-f",
        "--spawn",
        nargs="?",
        const=True,
        default=False,
        metavar="BUNDLE_ID",
        help="spawn target instead of attaching by name; optionally pass the bundle id",
    )
    parser.add_argument("--pause", action="store_true", help="leave spawned process paused after injecting")
    parser.add_argument("--no-pause", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-pty", action="store_true", help="do not run frida under a pseudo-terminal")
    args = parser.parse_args()

    out_dir = Path(args.out or default_output_dir()).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    script = Path(args.script).expanduser()
    if not script.exists():
        print(f"script not found: {script}", file=sys.stderr)
        return 2
    args.script = str(script.resolve())

    cmd = build_frida_command(args)
    print(f"[host] writing trace files to {out_dir}", flush=True)
    print(f"[host] running: {' '.join(cmd)}", flush=True)

    master_fd = None
    if args.no_pty:
        proc = subprocess.Popen(
            cmd,
            stdin=sys.stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    else:
        master_fd, slave_fd = pty.openpty()
        proc = subprocess.Popen(
            cmd,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
        )
        os.close(slave_fd)

    def stop(_signum, _frame):
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    def handle_line(raw_line: str):
        line = raw_line.rstrip("\r\n")
        if MARKER in line:
            prefix, marker_payload = line.split(MARKER, 1)
            if prefix.strip():
                print(prefix, flush=True)
            try:
                payload = json.loads(marker_payload)
                path = write_payload(out_dir, payload)
                print(f"[host-write] {path}", flush=True)
            except Exception as exc:
                print(f"[host-write-error] {exc}: {marker_payload[:500]}", file=sys.stderr, flush=True)
        else:
            print(line, flush=True)

    if args.no_pty:
        assert proc.stdout is not None
        for raw_line in proc.stdout:
            handle_line(raw_line)
    else:
        buffer = ""
        assert master_fd is not None
        while proc.poll() is None:
            readable, _, _ = select.select([master_fd], [], [], 0.2)
            if not readable:
                continue
            try:
                chunk = os.read(master_fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            buffer += chunk.decode("utf-8", errors="replace")
            while "\n" in buffer:
                raw_line, buffer = buffer.split("\n", 1)
                handle_line(raw_line)
        if buffer:
            handle_line(buffer)
        os.close(master_fd)

    code = proc.wait()
    print(f"[host] frida exited with code {code}", flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
