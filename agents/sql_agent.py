import re
from typing import List, Dict

# Patterns for detecting SQL injection vulnerabilities
SQL_PATTERNS = [
    # String concatenation with SQL keywords
    (r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\s+.*\+\s*[a-zA-Z_][a-zA-Z0-9_]*', 
     'String concatenation in SQL query'),
    
    # f-strings with SQL
    (r'(?i)f["\'].*?(SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*?\{[^}]+\}.*?["\']',
     'f-string interpolation in SQL query'),
    
    # .format() with SQL
    (r'(?i)["\'].*?(SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*?["\']\.format\s*\(',
     '.format() in SQL query'),
    
    # % formatting with SQL
    (r'(?i)["\'].*?(SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*?%s.*?["\'].*?%',
     '% formatting in SQL query'),
    
    # execute() with string concatenation
    (r'(?i)\.execute\s*\(\s*["\'].*?\+',
     'String concatenation in execute()'),
    
    # cursor.execute with f-string
    (r'(?i)\.execute\s*\(\s*f["\']',
     'f-string in execute()'),
    
    # query() with user input patterns
    (r'(?i)\.query\s*\(\s*["\'].*?\$\{',
     'Template literal with variable in query()'),
    
    # Raw query with concatenation (JS/TS)
    (r'(?i)(raw|query)\s*\(\s*`.*?\$\{',
     'Template literal interpolation in raw query'),
]


def detect_sql_injection(files: List[Dict]) -> List[Dict]:
    """Scan files for potential SQL injection vulnerabilities."""
    findings = []
    
    for file_info in files:
        content = file_info['content']
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('*'):
                continue
            
            for pattern, vuln_type in SQL_PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        'file': file_info['path'],
                        'line': line_num,
                        'type': 'SQL Injection',
                        'severity': 'CRITICAL',
                        'code_snippet': line.strip()[:100],
                        'vulnerability': vuln_type,
                        'explanation': f"{vuln_type} detected. Use parameterized queries or prepared statements instead of string interpolation to prevent SQL injection attacks."
                    })
    
    return findings
