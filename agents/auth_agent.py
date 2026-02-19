import re
from typing import List, Dict

# Route patterns for different frameworks
ROUTE_PATTERNS = [
    # FastAPI/Flask routes
    (r'@(app|router)\.(get|post|put|delete|patch)\s*\(\s*["\'][^"\']*["\']', 'Python'),
    # Express.js routes  
    (r'(app|router)\.(get|post|put|delete|patch)\s*\(\s*["\'][^"\']+["\']', 'JavaScript'),
    # NestJS/decorators
    (r'@(Get|Post|Put|Delete|Patch)\s*\(\s*["\']?[^)]*["\']?\s*\)', 'TypeScript'),
]

# Auth decorator/middleware patterns
AUTH_PATTERNS = [
    # Python decorators
    r'@(require|login_required|authenticated|auth|jwt_required|token_required|permission|protected)',
    r'@(Depends\s*\(\s*\w*auth|Depends\s*\(\s*\w*token|Depends\s*\(\s*get_current_user)',
    # JS/TS middleware
    r'(isAuthenticated|requireAuth|authMiddleware|verifyToken|authenticate)\s*[,\)]',
    r'(passport\.authenticate|jwt\.verify)',
    # Guards (NestJS)
    r'@(UseGuards|AuthGuard)',
]

# File-level auth middleware patterns (protects ALL routes in the file)
FILE_LEVEL_AUTH_PATTERNS = [
    r'router\.use\s*\(\s*(authenticate|authMiddleware|protect)',
    r'app\.use\s*\(\s*(authenticate|authMiddleware|protect)',
]

# Sensitive operations that should require auth
SENSITIVE_OPS = [
    r'(?i)(delete|remove|drop|update|create|insert|modify|admin|user|password|payment|checkout)',
]


def detect_missing_auth(files: List[Dict]) -> List[Dict]:
    """Scan files for endpoints potentially missing authentication."""
    findings = []
    
    for file_info in files:
        content = file_info['content']
        
        # Check for file-level auth middleware (e.g. router.use(authenticate))
        file_has_auth = any(
            re.search(pat, content, re.IGNORECASE)
            for pat in FILE_LEVEL_AUTH_PATTERNS
        )
        if file_has_auth:
            continue  # All routes in this file are authenticated
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            line_num = i + 1
            
            # Check if this line defines a route
            for route_pattern, framework in ROUTE_PATTERNS:
                route_match = re.search(route_pattern, line, re.IGNORECASE)
                if route_match:
                    # Look for auth in surrounding context (5 lines before and after)
                    context_start = max(0, i - 5)
                    context_end = min(len(lines), i + 5)
                    context = '\n'.join(lines[context_start:context_end])
                    
                    # Check if any auth pattern exists in context
                    has_auth = any(re.search(auth_pat, context, re.IGNORECASE) 
                                   for auth_pat in AUTH_PATTERNS)
                    
                    # Check if route handles sensitive operations
                    is_sensitive = any(re.search(sens_pat, line, re.IGNORECASE) 
                                       for sens_pat in SENSITIVE_OPS)
                    
                    # Flag if no auth and either: POST/PUT/DELETE/PATCH or sensitive op
                    method_match = re.search(r'\.(post|put|delete|patch)', line, re.IGNORECASE)
                    is_mutating = method_match is not None
                    
                    if not has_auth and (is_mutating or is_sensitive):
                        severity = 'HIGH' if is_sensitive else 'MEDIUM'
                        findings.append({
                            'file': file_info['path'],
                            'line': line_num,
                            'type': 'Missing Authentication',
                            'severity': severity,
                            'endpoint': route_match.group(0)[:80],
                            'framework': framework,
                            'explanation': f"This endpoint appears to lack authentication middleware. {'It performs sensitive operations that should require authentication.' if is_sensitive else 'Mutating endpoints (POST/PUT/DELETE/PATCH) should typically require authentication.'}"
                        })
    
    return findings
