import os
from dotenv import load_dotenv
import google.generativeai as genai
from typing import Dict, List

# Load environment variables from .env file
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)


def get_ai_explanation(vuln_type: str, code_snippet: str) -> Dict[str, str]:
    """Get AI explanation for a vulnerability from Gemini."""
    if not GEMINI_API_KEY:
        return {
            "ai_risk": "AI explanation unavailable (GEMINI_API_KEY not set)",
            "ai_exploit": "",
            "ai_fix": ""
        }
    
    prompt = f"""Analyze this security vulnerability in under 80 words total:

Type: {vuln_type}
Code: {code_snippet[:200]}

Respond in exactly this format:
RISK: [Why this is dangerous - 1-2 sentences]
EXPLOIT: [How attacker exploits it - 1-2 sentences]  
FIX: [Secure code fix example - brief]"""

    try:
        model = genai.GenerativeModel('gemini-2.0-flash')
        response = model.generate_content(prompt)
        text = response.text.strip()
        
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
        enhanced[category] = []
        for finding in items:
            # Get code snippet from finding
            code = finding.get('code_snippet') or finding.get('matched') or finding.get('endpoint', '')
            vuln_type = finding.get('type') or finding.get('vulnerability', category)
            
            # Get AI explanation
            ai_explanation = get_ai_explanation(vuln_type, code)
            
            # Merge AI explanation into finding
            enhanced_finding = {**finding, **ai_explanation}
            enhanced[category].append(enhanced_finding)
    
    return enhanced
