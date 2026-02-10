"""
Comparison Testing Script
Compares our LangGraph security auditor against Bandit and Semgrep.
"""
import os
import subprocess
import json
from pathlib import Path
from graph_workflow import run_security_graph_single

# Test samples directory
SAMPLES_DIR = Path(__file__).parent / "test_samples"


def run_our_tool(filepath: Path) -> int:
    """Run our LangGraph auditor on a file."""
    with open(filepath, 'r', encoding='utf-8') as f:
        code = f.read()
    
    result = run_security_graph_single(code, str(filepath))
    
    # Count total findings
    total = 0
    for category, findings in result.items():
        if category != "_summary" and isinstance(findings, list):
            total += len(findings)
    
    return total


def run_bandit(filepath: Path) -> int:
    """Run Bandit on a Python file."""
    if not filepath.suffix == '.py':
        return -1  # Bandit only works on Python
    
    try:
        result = subprocess.run(
            ['bandit', '-f', 'json', '-q', str(filepath)],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.stdout:
            data = json.loads(result.stdout)
            return len(data.get('results', []))
        return 0
    except FileNotFoundError:
        return -2  # Bandit not installed
    except Exception:
        return 0


def run_semgrep(filepath: Path) -> int:
    """Run Semgrep with auto rules on a file."""
    try:
        result = subprocess.run(
            ['semgrep', '--config', 'auto', '--json', '-q', str(filepath)],
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.stdout:
            data = json.loads(result.stdout)
            return len(data.get('results', []))
        return 0
    except FileNotFoundError:
        return -2  # Semgrep not installed
    except Exception:
        return 0


def main():
    print("=" * 70)
    print("SECURITY TOOL COMPARISON TEST")
    print("=" * 70)
    print()
    
    # Collect results
    results = []
    our_total = 0
    bandit_total = 0
    semgrep_total = 0
    
    # Get all test files
    test_files = list(SAMPLES_DIR.glob("*.py")) + \
                 list(SAMPLES_DIR.glob("*.js")) + \
                 list(SAMPLES_DIR.glob("*.ts"))
    
    for filepath in sorted(test_files):
        filename = filepath.name
        
        # Run our tool
        our_count = run_our_tool(filepath)
        our_total += our_count
        
        # Run Bandit (Python only)
        bandit_count = run_bandit(filepath)
        if bandit_count >= 0:
            bandit_total += bandit_count
        
        # Run Semgrep
        semgrep_count = run_semgrep(filepath)
        if semgrep_count >= 0:
            semgrep_total += semgrep_count
        
        results.append({
            'file': filename,
            'our_tool': our_count,
            'bandit': bandit_count if bandit_count >= 0 else 'N/A',
            'semgrep': semgrep_count if semgrep_count >= 0 else 'N/A'
        })
    
    # Print comparison table
    print("COMPARISON TABLE")
    print("-" * 70)
    print(f"{'File':<35} | {'Our Tool':>10} | {'Bandit':>10} | {'Semgrep':>10}")
    print("-" * 70)
    
    for r in results:
        bandit_str = str(r['bandit']) if r['bandit'] != -2 else 'Not Installed'
        semgrep_str = str(r['semgrep']) if r['semgrep'] != -2 else 'Not Installed'
        print(f"{r['file']:<35} | {r['our_tool']:>10} | {bandit_str:>10} | {semgrep_str:>10}")
    
    print("-" * 70)
    print(f"{'TOTAL':<35} | {our_total:>10} | {bandit_total:>10} | {semgrep_total:>10}")
    print("-" * 70)
    
    # Print summary
    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Our Tool detected: {our_total} issues")
    print(f"Bandit detected:   {bandit_total} issues (Python only)")
    print(f"Semgrep detected:  {semgrep_total} issues")
    print()
    
    if our_total > bandit_total and our_total > semgrep_total:
        print("✓ Our LangGraph auditor found THE MOST vulnerabilities!")
    elif our_total >= bandit_total and our_total >= semgrep_total:
        print("✓ Our tool performs on par with or better than traditional tools.")
    
    print()
    print("Note: Our tool scans Python, JavaScript, and TypeScript.")
    print("      Bandit only scans Python files.")
    print("      Results may vary based on rule configurations.")


if __name__ == "__main__":
    main()
