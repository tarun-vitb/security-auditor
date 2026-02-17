import tempfile
import subprocess
import shutil
import os
import sys
import logging

logger = logging.getLogger("security-auditor")

# How long to wait for git clone before giving up (seconds)
CLONE_TIMEOUT_SECONDS = 60

# --- Error messages ---
MSG_TOO_LARGE = "Repository too large for demo version. Please try a smaller repository."


def _kill_process_tree(pid: int) -> None:
    """Kill a process and all its children (Windows-safe)."""
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True,
        )
    else:
        import signal
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except ProcessLookupError:
            pass


def clone_repo(repo_url: str) -> str:
    """
    Clone a GitHub repository to a temporary directory using subprocess.

    - Sets GIT_TERMINAL_PROMPT=0 so git never hangs waiting for credentials.
    - Enforces a short timeout and kills the entire process tree on expiry.
    - On ANY failure, raises RuntimeError (caller shows a single fallback msg).
    """
    temp_dir = tempfile.mkdtemp(prefix="security_audit_")

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"       # never prompt for password
    env["GIT_ASKPASS"] = ""                 # disable askpass helpers too

    cmd = ["git", "clone", "--depth", "1", repo_url, temp_dir]

    # Use CREATE_NEW_PROCESS_GROUP on Windows so we can kill the tree
    creation_flags = 0
    if sys.platform == "win32":
        creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        creationflags=creation_flags,
    )

    try:
        stdout, stderr = proc.communicate(timeout=CLONE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        logger.warning("git clone timed out after %ds for %s", CLONE_TIMEOUT_SECONDS, repo_url)
        _kill_process_tree(proc.pid)
        proc.wait()
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise RuntimeError("Clone timed out")

    if proc.returncode != 0:
        logger.info("git clone failed (exit %d): %s", proc.returncode, stderr.strip())
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise RuntimeError("Clone failed")

    return temp_dir


def cleanup_repo(repo_path: str) -> None:
    """Remove the cloned repository directory."""
    if repo_path and os.path.exists(repo_path):
        shutil.rmtree(repo_path, ignore_errors=True)
