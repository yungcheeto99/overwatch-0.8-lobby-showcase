"""Prepare a folder-local Python environment, then run the fixed lobby CLI."""
from __future__ import annotations

import os
from pathlib import Path
import struct
import subprocess
import sys

from ow08.packet_log import console_color


ROOT = Path(__file__).resolve().parent
DEPENDENCIES = ("cryptography>=42",)


def environment():
    # Keep user Python settings from redirecting the folder-local environment.
    env = os.environ.copy()
    for name in ("PYTHONHOME", "PYTHONPATH"):
        env.pop(name, None)
    return env


def main():
    arguments = sys.argv[1:]
    if len(arguments) >= 3 and arguments[1].casefold() == "--python":
        # The batch file already selected this interpreter before Python ran.
        arguments = arguments[:1] + arguments[3:]
    if any(argument.casefold() == "--python" for argument in arguments):
        raise ValueError('--python must be the first option after the batch filename')
    if sys.version_info < (3, 11) or struct.calcsize("P") != 8 or sys.platform != "win32":
        raise ValueError("Use Windows x64 Python 3.11 or newer")
    env = environment()
    if "--help" in arguments or "-h" in arguments:
        return subprocess.call([sys.executable, "-u", "-m", "ow08", *arguments], cwd=ROOT, env=env)
    title = "Overwatch 0.8.0.24919"
    if console_color():
        title = f"\x1b[38;2;249;158;26m{title}\x1b[39m"
    print(f"{title} lobby showcase", flush=True)
    python = ROOT / ".venv" / "Scripts" / "python.exe"
    if not python.exists():
        print(f"Setup: creating the local Python environment at {ROOT / '.venv'}...", flush=True)
        subprocess.run([sys.executable, "-m", "venv", str(ROOT / ".venv")], cwd=ROOT, env=env, check=True)
    probe = subprocess.run([str(python), "-c",
        "import cryptography; assert int(cryptography.__version__.split('.')[0]) >= 42"],
        cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if probe.returncode:
        print("Setup: installing Python dependencies...", flush=True)
        subprocess.run([str(python), "-m", "pip", "install", "--disable-pip-version-check",
                        "--only-binary=:all:", *DEPENDENCIES],
                       cwd=ROOT, env=env, check=True)
    if "--setup-only" in arguments:
        print(f"Setup ready: {python}", flush=True)
        return 0
    with subprocess.Popen([str(python), "-u", "-m", "ow08", *arguments], cwd=ROOT, env=env) as runtime:
        try:
            return runtime.wait()
        except KeyboardInterrupt:
            # Ctrl+C reaches the runtime in this console too. Give its account,
            # launcher and socket cleanup time to finish before force stopping.
            try:
                return runtime.wait(timeout=15)
            except subprocess.TimeoutExpired:
                runtime.terminate()
                runtime.wait()
                return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Setup failed: {error}", file=sys.stderr)
        print("Use Windows x64 Python 3.11+ with pip. Dependency installation needs internet access.\n"
              "For an offline setup, install " + " ".join(DEPENDENCIES) +
              " into .venv with pip before launching.", file=sys.stderr)
        sys.exit(2)
