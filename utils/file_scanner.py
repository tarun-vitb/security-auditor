import os
import logging
from typing import List, Dict, Any

logger = logging.getLogger("security-auditor")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SUPPORTED_EXTENSIONS = {'.py', '.js', '.ts', '.jsx', '.tsx'}

# Extensions to always skip (binary, minified, lock files, etc.)
SKIP_EXTENSIONS = {
    '.min.js', '.lock', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
    '.pdf', '.map', '.woff', '.woff2', '.ttf', '.eot',
    '.pyc', '.pyo', '.so', '.dll', '.exe', '.bin',
    '.mp3', '.mp4', '.wav', '.avi', '.mov',
}

# Directories to always skip
IGNORED_DIRS = {
    'node_modules', 'venv', '.venv', '.tox', '__pycache__',
    '.git', '.idea', '.vscode', '.next', '.nuxt',
    'build', 'dist', 'out', 'target',
    'vendor', 'coverage', '__pypackages__',
    '.mypy_cache', '.pytest_cache', '.cache',
    'test_samples', 'tests',
}

# --- Limits ---
MAX_FILES_INITIAL = 150          # Files to actually read & scan
MAX_TOTAL_FILES   = 800          # Max files to index in tree walk
HARD_TREE_CAP     = 10_000       # Stop walking tree after this many entries
MAX_FILE_SIZE     = 500 * 1024   # 500 KB per file — skip larger


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------
def scan_files(repo_path: str) -> Dict[str, Any]:
    """
    Walk the repo tree and collect code files.

    Returns:
        {
            "files":         List[Dict]   — up to MAX_FILES_INITIAL with content loaded,
            "total_found":   int          — total code files discovered in the tree,
            "was_truncated": bool         — True if we hit any limit,
        }
    """
    code_paths: List[str] = []      # relative paths of ALL discovered code files
    tree_entries_seen = 0           # total fs entries walked (dirs + files)
    hit_tree_cap = False

    # ── Phase 1: Walk tree, collect code-file paths (no content yet) ──
    for root, dirs, filenames in os.walk(repo_path):
        # Prune ignored directories IN-PLACE so os.walk won't descend
        dirs[:] = [
            d for d in dirs
            if d not in IGNORED_DIRS and not d.startswith('.')
        ]

        for filename in filenames:
            tree_entries_seen += 1
            if tree_entries_seen >= HARD_TREE_CAP:
                hit_tree_cap = True
                break

            ext = os.path.splitext(filename)[1].lower()

            # Skip heavy/binary extensions
            if ext in SKIP_EXTENSIONS:
                continue
            # Also skip .min.js specifically (double-extension check)
            if filename.endswith('.min.js'):
                continue

            if ext in SUPPORTED_EXTENSIONS:
                filepath = os.path.join(root, filename)
                rel = os.path.relpath(filepath, repo_path)
                code_paths.append(rel)

                # Stop indexing beyond MAX_TOTAL_FILES
                if len(code_paths) >= MAX_TOTAL_FILES:
                    hit_tree_cap = True
                    break

        if hit_tree_cap:
            break

    total_found = len(code_paths)
    was_truncated = total_found > MAX_FILES_INITIAL or hit_tree_cap

    # ── Phase 2: Read content for the first MAX_FILES_INITIAL files ──
    files_to_scan = code_paths[:MAX_FILES_INITIAL]
    loaded: List[Dict] = []

    for rel_path in files_to_scan:
        abs_path = os.path.join(repo_path, rel_path)
        try:
            size = os.path.getsize(abs_path)
            if size > MAX_FILE_SIZE:
                continue  # silently skip oversized files

            with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            ext = os.path.splitext(rel_path)[1].lower()
            loaded.append({
                'path': rel_path,
                'content': content,
                'extension': ext,
            })
        except Exception:
            continue

    logger.info(
        "scan_files: total_found=%d, loaded=%d, truncated=%s",
        total_found, len(loaded), was_truncated,
    )

    return {
        "files": loaded,
        "total_found": total_found,
        "was_truncated": was_truncated,
    }
