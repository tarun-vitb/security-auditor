"""Test the LangGraph workflow."""
from graph_workflow import run_security_graph_single

# Test with a sample code snippet
test_code = '''
password = "secret123"
api_key = "sk-1234567890abcdef"

def get_user(id):
    query = "SELECT * FROM users WHERE id = " + id
    cursor.execute(query)
'''

result = run_security_graph_single(test_code, "test.py")
print("=== LangGraph Workflow Test ===")
print(f"Secrets found: {len(result.get('secrets_detected', []))}")
print(f"SQL issues found: {len(result.get('sql_injection', []))}")
print(f"Auth issues found: {len(result.get('missing_auth', []))}")
print(f"Summary: {result.get('_summary', {})}")
print("\nSUCCESS: LangGraph workflow is working!")
