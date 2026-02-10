import re
from typing import List, Dict

# Patterns for detecting hardcoded secrets
SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\'][a-zA-Z0-9]{16,}["\']', 'API Key'),
    (r'(?i)(secret|password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}["\']', 'Password/Secret'),
    (r'(?i)(token|auth[_-]?token|access[_-]?token)\s*[=:]\s*["\'][a-zA-Z0-9_\-\.]{20,}["\']', 'Token'),
    (r'(?i)AKIA[0-9A-Z]{16}', 'AWS Access Key'),
    (r'(?i)(aws[_-]?secret|secret[_-]?key)\s*[=:]\s*["\'][a-zA-Z0-9/+=]{40}["\']', 'AWS Secret Key'),
    (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', 'Private Key'),
    (r'(?i)(mysql|postgres|mongodb|redis)://[^"\'\s]+:[^"\'\s]+@', 'Database Connection String'),
    (r'(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}', 'Bearer Token'),
    (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Access Token'),
    (r'sk-[a-zA-Z0-9]{48}', 'OpenAI API Key'),
]


def detect_secrets(files: List[Dict]) -> List[Dict]:
    """Scan files for hardcoded secrets."""
    findings = []
    
    for file_info in files:
        content = file_info['content']
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern, secret_type in SECRET_PATTERNS:
                matches = re.finditer(pattern, line)
                for match in matches:
                    # Mask the actual secret value
                    matched_text = match.group(0)
                    masked = matched_text[:10] + '***REDACTED***'
                    
                    findings.append({
                        'file': file_info['path'],
                        'line': line_num,
                        'type': secret_type,
                        'severity': 'HIGH',
                        'matched': masked,
                        'explanation': f"Potential {secret_type} found. Hardcoded secrets should be stored in environment variables or a secrets manager."
                    })
    
    return findings
