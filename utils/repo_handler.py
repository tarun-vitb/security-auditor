import tempfile
import shutil
import os
from git import Repo


def clone_repo(repo_url: str) -> str:
    """Clone a GitHub repository to a temporary directory."""
    temp_dir = tempfile.mkdtemp(prefix="security_audit_")
    try:
        Repo.clone_from(repo_url, temp_dir, depth=1)
        return temp_dir
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise RuntimeError(f"Failed to clone repository: {e}")


def cleanup_repo(repo_path: str) -> None:
    """Remove the cloned repository directory."""
    if repo_path and os.path.exists(repo_path):
        shutil.rmtree(repo_path, ignore_errors=True)
