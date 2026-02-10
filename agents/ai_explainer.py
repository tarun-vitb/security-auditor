"""
AI Explainer using Groq API.
Generates vulnerability explanations using Llama3 or Mixtral.
"""
import os
from typing import Dict, List
from dotenv import load_dotenv
from groq import Groq

# Load environment variables
load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None


def generate_ai_explanation(vulnerability: str, code_snippet: str) -> Dict[str, str]:
    """Generate AI explanation for a vulnerability using Groq."""
    if not client:
        return {
            "ai_risk": "AI explanation unavailable (GROQ_API_KEY not set)",
            "ai_exploit": "",
            "ai_fix": ""
        }
    
    prompt = f"""Analyze this security vulnerability in under 80 words total:

Type: {vulnerability}
Code: {code_snippet[:200]}

Respond in exactly this format:
RISK: [Why this is dangerous - 1-2 sentences]
EXPLOIT: [How attacker exploits it - 1-2 sentences]
FIX: [Secure code fix example - brief]"""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are a security expert. Be concise."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=200
        )
        
        text = response.choices[0].message.content.strip()
        
        # Parse response
        result = {"ai_risk": "", "ai_exploit": "", "ai_fix": ""}
        
        for line in text.split('\n'):
            line = line.strip()
            if line.startswith('RISK:'):
                result["ai_risk"] = line[5:].strip()
            elif line.startswith('EXPLOIT:'):
                result["ai_exploit"] = line[8:].strip()
            elif line.startswith('FIX:'):
                result["ai_fix"] = line[4:].strip()
        
        return result
        
    except Exception as e:
        return {
            "ai_risk": f"AI explanation failed: {str(e)[:50]}",
            "ai_exploit": "",
            "ai_fix": ""
        }


def enhance_findings_with_ai(findings: Dict[str, List[Dict]]) -> Dict[str, List[Dict]]:
    """Add AI explanations to all findings."""
    enhanced = {}
    
    for category, items in findings.items():
        if category == "_summary":
            enhanced[category] = items
            continue
            
        enhanced[category] = []
        for finding in items:
            # Get code snippet from finding
            code = finding.get('code_snippet') or finding.get('matched') or finding.get('endpoint', '')
            vuln_type = finding.get('type') or finding.get('vulnerability', category)
            
            # Get AI explanation
            ai_explanation = generate_ai_explanation(vuln_type, code)
            
            # Merge AI explanation into finding
            enhanced_finding = {**finding, **ai_explanation}
            enhanced[category].append(enhanced_finding)
    
    return enhanced
