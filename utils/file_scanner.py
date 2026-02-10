import os
from typing import List, Dict


SUPPORTED_EXTENSIONS = {'.py', '.js', '.ts'}


def scan_files(repo_path: str) -> List[Dict]:
    """Scan repository for .py, .js, .ts files and return their content."""
    files = []
    
    for root, _, filenames in os.walk(repo_path):
        # Skip hidden directories and node_modules
        if any(part.startswith('.') or part == 'node_modules' for part in root.split(os.sep)):
            continue
            
        for filename in filenames:
            ext = os.path.splitext(filename)[1].lower()
            if ext in SUPPORTED_EXTENSIONS:
                filepath = os.path.join(root, filename)
                relative_path = os.path.relpath(filepath, repo_path)
                
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    files.append({
                        'path': relative_path,
                        'content': content,
                        'extension': ext
                    })
                except Exception:
                    continue
    
    return files
