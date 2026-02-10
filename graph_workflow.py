"""
LangGraph orchestration layer for security agents.
Wraps existing agents into a graph workflow.
"""
from typing import TypedDict, List, Dict, Any
from langgraph.graph import Graph, END

# Import existing agent logic
from agents.secrets_agent import detect_secrets
from agents.sql_agent import detect_sql_injection
from agents.auth_agent import detect_missing_auth


# Shared state schema
class SecurityState(TypedDict):
    files: List[Dict]  # List of {path, content, extension}
    findings: Dict[str, List[Dict]]  # Aggregated findings


# Node functions - wrap existing agents
def secrets_node(state: SecurityState) -> SecurityState:
    """Run secrets detection agent."""
    findings = detect_secrets(state["files"])
    state["findings"]["secrets_detected"] = findings
    return state


def sql_node(state: SecurityState) -> SecurityState:
    """Run SQL injection detection agent."""
    findings = detect_sql_injection(state["files"])
    state["findings"]["sql_injection"] = findings
    return state


def auth_node(state: SecurityState) -> SecurityState:
    """Run missing auth detection agent."""
    findings = detect_missing_auth(state["files"])
    state["findings"]["missing_auth"] = findings
    return state


def aggregator_node(state: SecurityState) -> SecurityState:
    """Aggregate and finalize findings."""
    # Count totals
    total = sum(len(f) for f in state["findings"].values())
    state["findings"]["_summary"] = {
        "total_findings": total,
        "secrets_count": len(state["findings"].get("secrets_detected", [])),
        "sql_count": len(state["findings"].get("sql_injection", [])),
        "auth_count": len(state["findings"].get("missing_auth", []))
    }
    return state


# Build the graph
def build_security_graph() -> Graph:
    """Build LangGraph workflow for security scanning."""
    workflow = Graph()
    
    # Add nodes
    workflow.add_node("secrets_agent", secrets_node)
    workflow.add_node("sql_agent", sql_node)
    workflow.add_node("auth_agent", auth_node)
    workflow.add_node("aggregator", aggregator_node)
    
    # Define flow: start → secrets → sql → auth → aggregator → end
    workflow.set_entry_point("secrets_agent")
    workflow.add_edge("secrets_agent", "sql_agent")
    workflow.add_edge("sql_agent", "auth_agent")
    workflow.add_edge("auth_agent", "aggregator")
    workflow.add_edge("aggregator", END)
    
    return workflow.compile()


# Main entry point
def run_security_graph(files: List[Dict]) -> Dict[str, List[Dict]]:
    """
    Run the security scanning graph.
    
    Args:
        files: List of file dicts with {path, content, extension}
    
    Returns:
        Dict of findings from all agents
    """
    # Initialize state
    initial_state: SecurityState = {
        "files": files,
        "findings": {
            "secrets_detected": [],
            "sql_injection": [],
            "missing_auth": []
        }
    }
    
    # Build and run graph
    graph = build_security_graph()
    final_state = graph.invoke(initial_state)
    
    return final_state["findings"]


# Convenience function for single file
def run_security_graph_single(code: str, filename: str) -> Dict[str, List[Dict]]:
    """
    Run security scan on a single file.
    
    Args:
        code: File content
        filename: File name/path
    
    Returns:
        Dict of findings
    """
    import os
    ext = os.path.splitext(filename)[1].lower()
    
    files = [{
        "path": filename,
        "content": code,
        "extension": ext
    }]
    
    return run_security_graph(files)
