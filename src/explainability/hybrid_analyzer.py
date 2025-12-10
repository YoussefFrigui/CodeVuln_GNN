"""
Hybrid GNN + LLM Vulnerability Analyzer

This module combines the GNN model's structural analysis with LLM's semantic
understanding to provide more accurate vulnerability detection.

Architecture:
    ┌─────────────────┐
    │   User Code     │
    └────────┬────────┘
             │
    ┌────────▼────────┐     ┌─────────────────┐
    │   GNN Model     │────▶│ Structural Score │
    │ (AST Patterns)  │     │   (Fast, 0-1)    │
    └─────────────────┘     └────────┬─────────┘
             │                       │
    ┌────────▼────────┐     ┌────────▼─────────┐
    │   LLM Analysis  │────▶│  Semantic Score  │
    │ (Code Context)  │     │  (Thorough, 0-1) │
    └─────────────────┘     └────────┬─────────┘
                                     │
                            ┌────────▼─────────┐
                            │  Combined Score  │
                            │  + Explanation   │
                            └──────────────────┘

The hybrid approach solves:
1. GNN false positives on complex safe code (LLM corrects)
2. GNN false negatives on subtle vulnerabilities (LLM catches)
3. Provides human-readable explanations for all predictions
"""

import os
import re
import ast
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum

# Try to import google genai
try:
    from google import genai
    from google.genai import types
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False


class RiskLevel(Enum):
    """Vulnerability risk levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


@dataclass
class HybridAnalysisResult:
    """Result from hybrid GNN + LLM analysis."""
    # Scores
    gnn_score: float              # GNN vulnerability score (0-1)
    llm_score: float              # LLM vulnerability score (0-1)
    combined_score: float         # Weighted combination
    
    # Verdicts
    gnn_verdict: str              # "vulnerable" or "safe"
    llm_verdict: str              # "vulnerable" or "safe"
    final_verdict: str            # Combined verdict
    
    # Analysis
    risk_level: RiskLevel
    confidence: float             # Confidence in the prediction
    agreement: bool               # Whether GNN and LLM agree
    
    # Explanations
    llm_reasoning: str            # LLM's detailed reasoning
    detected_patterns: List[str]  # Specific vulnerability patterns found
    recommendations: List[str]    # Security recommendations
    fixed_code: str               # Complete fixed code example
    
    # Metadata
    analysis_method: str          # "hybrid", "gnn_only", or "llm_only"


class HybridVulnerabilityAnalyzer:
    """
    Combines GNN structural analysis with LLM semantic analysis
    for more accurate vulnerability detection.
    
    LLM is the dominant scorer - it provides the final score and verdict.
    GNN provides initial signal but LLM has authority to override.
    """
    
    # Prompt for LLM to score vulnerability - focused on critical issues only
    SCORING_PROMPT = """You are an expert security auditor. Analyze this Python code for REAL security vulnerabilities.

## Code to Analyze
```python
{code}
```

## Your Task
Focus ONLY on actual exploitable security vulnerabilities. Ignore code complexity, style issues, or theoretical concerns.

**CRITICAL vulnerabilities to detect:**
- SQL Injection: String concatenation in SQL queries
- Command Injection: User input in os.system(), subprocess, eval(), exec()
- Insecure Deserialization: pickle.loads(), yaml.load() with untrusted data
- Path Traversal: User input in file paths without sanitization
- XSS: User input rendered as HTML without escaping
- Hardcoded Secrets: Passwords, API keys, tokens in source code
- Weak Cryptography: MD5, SHA1 for passwords, weak encryption

**NOT vulnerabilities (mark as SAFE):**
- Using subprocess/os with hardcoded safe commands
- Complex code structure or many imports
- ML/AI libraries (torch, tensorflow, numpy, pandas)
- Standard library usage without security issues
- Test files or configuration code

## Response Format (EXACT format required):

VULNERABILITY_SCORE: [0.0-1.0]
VERDICT: [VULNERABLE/SAFE]
RISK_LEVEL: [CRITICAL/HIGH/MEDIUM/LOW/SAFE]

KEY_ISSUES:
[If vulnerable: List each specific issue on a new line starting with "- ". Be brief and specific, e.g., "- SQL Injection in user query function via string concatenation"]
[If safe: Write "None - Code appears secure"]

DETAILED_SUMMARY:
[3-5 sentences explaining your analysis. Describe what the code does, what security patterns you identified (good or bad), and why you reached your verdict. Be specific about line numbers or function names if relevant.]

RECOMMENDATIONS:
[If vulnerable: List specific text recommendations on new lines starting with "- ". Explain what needs to be fixed and why.]
[If safe: Write "None needed - Continue following secure coding practices"]

FIXED_CODE:
[If vulnerable: Provide the COMPLETE corrected version of the code with the vulnerabilities fixed. Include all imports and functions. The code should be ready to copy-paste and use. Wrap in triple backticks with python.]
[If safe: Write "No fix needed - code is secure"]
"""

    def __init__(
        self, 
        api_key: Optional[str] = None,
        model: str = "gemini-2.5-pro",
        gnn_weight: float = 0.15,   # GNN provides signal but LLM dominates
        llm_weight: float = 0.85,   # LLM is the authoritative scorer
    ):
        """
        Initialize the hybrid analyzer.
        
        Args:
            api_key: Google Gemini API key
            model: Gemini model to use
            gnn_weight: Weight for GNN score (default 0.15 - minimal influence)
            llm_weight: Weight for LLM score (default 0.85 - dominant)
        """
        self.model = model
        self.gnn_weight = gnn_weight
        self.llm_weight = llm_weight
        
        # Normalize weights
        total = gnn_weight + llm_weight
        self.gnn_weight = gnn_weight / total
        self.llm_weight = llm_weight / total
        
        if not GENAI_AVAILABLE:
            self.client = None
            return
        
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        
        if self.api_key:
            self.client = genai.Client(api_key=self.api_key)
        else:
            self.client = None
    
    def _parse_llm_response(self, response_text: str) -> Dict[str, Any]:
        """Parse structured response from LLM."""
        result = {
            "score": 0.5,
            "verdict": "SAFE",
            "risk_level": "LOW",
            "key_issues": [],
            "summary": "",
            "recommendations": [],
            "fixed_code": "",  # New field for the fixed code example
            "vulnerabilities": [],  # Alias for key_issues (backwards compat)
            "reasoning": "",  # Alias for summary (backwards compat)
        }
        
        try:
            lines = response_text.strip().split('\n')
            current_section = None
            current_content = []
            in_code_block = False
            code_block_content = []
            
            for line in lines:
                stripped = line.strip()
                
                # Handle code blocks for FIXED_CODE section
                if current_section == "fixed_code":
                    if stripped.startswith("```") and in_code_block:
                        # End of code block
                        in_code_block = False
                        result["fixed_code"] = "\n".join(code_block_content)
                        code_block_content = []
                        current_section = None
                        continue
                    elif stripped.startswith("```"):
                        # Start of code block (might be ```python or just ```)
                        in_code_block = True
                        continue
                    elif in_code_block:
                        code_block_content.append(line.rstrip())  # Preserve indentation
                        continue
                    elif stripped.lower() in ["no fix needed - code is secure", "no fix needed", "none"]:
                        result["fixed_code"] = ""
                        current_section = None
                        continue
                    elif stripped and not stripped.startswith("```"):
                        # Code without backticks - some LLMs do this
                        code_block_content.append(line.rstrip())
                        continue
                
                # Check for section headers
                if stripped.startswith("VULNERABILITY_SCORE:"):
                    self._save_section(result, current_section, current_content)
                    current_section = None
                    current_content = []
                    score_str = stripped.replace("VULNERABILITY_SCORE:", "").strip()
                    score_str = re.sub(r'[^\d.]', '', score_str.split('/')[0].split('%')[0])
                    if score_str:
                        score = float(score_str)
                        if score > 1:
                            score = score / 100
                        result["score"] = min(1.0, max(0.0, score))
                
                elif stripped.startswith("VERDICT:"):
                    self._save_section(result, current_section, current_content)
                    current_section = None
                    current_content = []
                    verdict = stripped.replace("VERDICT:", "").strip().upper()
                    result["verdict"] = "VULNERABLE" if "VULN" in verdict else "SAFE"
                
                elif stripped.startswith("RISK_LEVEL:"):
                    self._save_section(result, current_section, current_content)
                    current_section = None
                    current_content = []
                    risk = stripped.replace("RISK_LEVEL:", "").strip().upper()
                    if "CRITICAL" in risk:
                        result["risk_level"] = "CRITICAL"
                    elif "HIGH" in risk:
                        result["risk_level"] = "HIGH"
                    elif "MEDIUM" in risk or "MODERATE" in risk:
                        result["risk_level"] = "MEDIUM"
                    elif "LOW" in risk:
                        result["risk_level"] = "LOW"
                    else:
                        result["risk_level"] = "SAFE"
                
                elif stripped.startswith("KEY_ISSUES:"):
                    self._save_section(result, current_section, current_content)
                    current_section = "key_issues"
                    current_content = []
                    # Check if there's content on the same line
                    rest = stripped.replace("KEY_ISSUES:", "").strip()
                    if rest and rest.lower() not in ["none", "n/a", "none - code appears secure"]:
                        current_content.append(rest)
                
                elif stripped.startswith("DETAILED_SUMMARY:"):
                    self._save_section(result, current_section, current_content)
                    current_section = "summary"
                    current_content = []
                    rest = stripped.replace("DETAILED_SUMMARY:", "").strip()
                    if rest:
                        current_content.append(rest)
                
                elif stripped.startswith("RECOMMENDATIONS:"):
                    self._save_section(result, current_section, current_content)
                    current_section = "recommendations"
                    current_content = []
                    rest = stripped.replace("RECOMMENDATIONS:", "").strip()
                    if rest and rest.lower() not in ["none", "none needed", "n/a", "none needed - continue following secure coding practices"]:
                        current_content.append(rest)
                
                elif stripped.startswith("FIXED_CODE:"):
                    self._save_section(result, current_section, current_content)
                    current_section = "fixed_code"
                    current_content = []
                    code_block_content = []
                    in_code_block = False
                    rest = stripped.replace("FIXED_CODE:", "").strip()
                    if rest and rest.lower() in ["no fix needed - code is secure", "no fix needed", "none"]:
                        result["fixed_code"] = ""
                        current_section = None
                
                # Also handle old format for backwards compatibility
                elif stripped.startswith("BRIEF_EXPLANATION:"):
                    self._save_section(result, current_section, current_content)
                    current_section = "summary"
                    current_content = []
                    rest = stripped.replace("BRIEF_EXPLANATION:", "").strip()
                    if rest:
                        current_content.append(rest)
                
                elif stripped.startswith("REASONING:"):
                    self._save_section(result, current_section, current_content)
                    current_section = "summary"
                    current_content = []
                    rest = stripped.replace("REASONING:", "").strip()
                    if rest:
                        current_content.append(rest)
                
                elif stripped.startswith("VULNERABILITIES_FOUND:"):
                    self._save_section(result, current_section, current_content)
                    current_section = "key_issues"
                    current_content = []
                    rest = stripped.replace("VULNERABILITIES_FOUND:", "").strip()
                    if rest and rest.lower() not in ["none", "n/a"]:
                        current_content.append(rest)
                
                elif current_section and current_section != "fixed_code":
                    # Continue collecting content for current section
                    if stripped.startswith("-") or stripped.startswith("•"):
                        item = stripped.lstrip("-•").strip()
                        if item and item.lower() not in ["none", "n/a", "none needed"]:
                            current_content.append(item)
                    elif stripped:
                        current_content.append(stripped)
            
            # Save final section
            self._save_section(result, current_section, current_content)
            
            # Handle case where code block wasn't closed
            if current_section == "fixed_code" and code_block_content:
                result["fixed_code"] = "\n".join(code_block_content)
            
            # Set backwards compatibility aliases
            result["vulnerabilities"] = result["key_issues"]
            result["reasoning"] = result["summary"]
        
        except Exception as e:
            print(f"Error parsing LLM response: {e}")
        
        return result
    
    def _save_section(self, result: Dict, section: str, content: List[str]):
        """Save accumulated content to the appropriate result field."""
        if not section or not content:
            return
        
        if section == "key_issues":
            result["key_issues"] = [c for c in content if c.lower() not in ["none", "n/a", "none - code appears secure"]]
        elif section == "summary":
            result["summary"] = " ".join(content)
        elif section == "recommendations":
            result["recommendations"] = [c for c in content if c.lower() not in ["none", "none needed", "n/a"]]
    
    def _get_llm_analysis(self, code: str, gnn_score: float) -> Dict[str, Any]:
        """Get LLM's vulnerability analysis - LLM analyzes independently."""
        if self.client is None:
            return {
                "success": False,
                "error": "LLM not available",
                "score": gnn_score,  # Fall back to GNN score
                "verdict": "VULNERABLE" if gnn_score > 0.5 else "SAFE",
                "risk_level": "UNKNOWN",
                "reasoning": "LLM analysis unavailable - using GNN only",
                "vulnerabilities": [],
                "recommendations": [],
            }
        
        # LLM analyzes independently - no GNN bias in prompt
        prompt = self.SCORING_PROMPT.format(code=code)
        
        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.1,  # Very low temperature for consistent scoring
                    max_output_tokens=8192,
                )
            )
            
            parsed = self._parse_llm_response(response.text)
            parsed["success"] = True
            parsed["raw_response"] = response.text
            return parsed
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "score": 0.5,
                "verdict": "UNKNOWN",
                "risk_level": "UNKNOWN",
                "reasoning": f"LLM analysis failed: {str(e)}",
                "vulnerabilities": [],
                "recommendations": [],
            }
    
    def _calculate_combined_score(
        self, 
        gnn_score: float, 
        llm_score: float,
        gnn_verdict: str,
        llm_verdict: str,
    ) -> Tuple[float, str, float]:
        """
        Calculate final score - LLM is the dominant scorer.
        
        The LLM score is the primary output. GNN only provides a small adjustment.
        
        Returns:
            Tuple of (final_score, final_verdict, confidence)
        """
        # LLM is dominant (85%), GNN provides minor adjustment (15%)
        final_score = (self.llm_weight * llm_score) + (self.gnn_weight * gnn_score)
        
        # LLM verdict is authoritative
        llm_says_vuln = llm_score > 0.5 or llm_verdict.upper() == "VULNERABLE"
        
        # If LLM is confident, use its verdict directly
        if llm_score >= 0.7 or llm_score <= 0.3:
            # High confidence from LLM - trust it completely
            final_score = llm_score
            confidence = abs(llm_score - 0.5) * 2  # 0-1 scale
        else:
            # LLM uncertain - blend with GNN but still favor LLM
            confidence = 0.5  # Medium confidence when uncertain
        
        # Final verdict based on score
        final_verdict = "VULNERABLE" if final_score > 0.5 else "SAFE"
        
        return final_score, final_verdict, confidence
    
    def _determine_risk_level(self, combined_score: float, llm_risk: str) -> RiskLevel:
        """Determine final risk level."""
        # Map LLM risk string to enum
        llm_risk_map = {
            "CRITICAL": RiskLevel.CRITICAL,
            "HIGH": RiskLevel.HIGH,
            "MEDIUM": RiskLevel.MEDIUM,
            "LOW": RiskLevel.LOW,
            "SAFE": RiskLevel.SAFE,
        }
        llm_risk_enum = llm_risk_map.get(llm_risk.upper(), RiskLevel.MEDIUM)
        
        # Score-based risk
        if combined_score >= 0.8:
            score_risk = RiskLevel.CRITICAL
        elif combined_score >= 0.6:
            score_risk = RiskLevel.HIGH
        elif combined_score >= 0.4:
            score_risk = RiskLevel.MEDIUM
        elif combined_score >= 0.2:
            score_risk = RiskLevel.LOW
        else:
            score_risk = RiskLevel.SAFE
        
        # Take the higher risk between score and LLM assessment
        risk_order = [RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        score_idx = risk_order.index(score_risk)
        llm_idx = risk_order.index(llm_risk_enum)
        
        return risk_order[max(score_idx, llm_idx)]
    
    def analyze(self, code: str, gnn_result: Dict[str, Any]) -> HybridAnalysisResult:
        """
        Perform hybrid GNN + LLM vulnerability analysis.
        
        Args:
            code: Python code to analyze
            gnn_result: GNN analysis result with keys:
                - vulnerability_score: float (0-1)
                - is_vulnerable: bool
                - confidence: float
        
        Returns:
            HybridAnalysisResult with combined analysis
        """
        gnn_score = gnn_result.get("vulnerability_score", 0.5)
        gnn_verdict = "VULNERABLE" if gnn_result.get("is_vulnerable", False) else "SAFE"
        
        # Get LLM analysis
        llm_result = self._get_llm_analysis(code, gnn_score)
        
        if llm_result["success"]:
            llm_score = llm_result["score"]
            llm_verdict = llm_result["verdict"]
            analysis_method = "hybrid"
        else:
            # Fallback to GNN only
            llm_score = gnn_score
            llm_verdict = gnn_verdict
            analysis_method = "gnn_only"
        
        # Calculate combined score
        combined_score, final_verdict, confidence = self._calculate_combined_score(
            gnn_score, llm_score, gnn_verdict, llm_verdict
        )
        
        # Determine risk level
        risk_level = self._determine_risk_level(combined_score, llm_result.get("risk_level", "MEDIUM"))
        
        # Check agreement
        agreement = (gnn_verdict == llm_verdict)
        
        return HybridAnalysisResult(
            gnn_score=gnn_score,
            llm_score=llm_score,
            combined_score=combined_score,
            gnn_verdict=gnn_verdict,
            llm_verdict=llm_verdict,
            final_verdict=final_verdict,
            risk_level=risk_level,
            confidence=confidence,
            agreement=agreement,
            llm_reasoning=llm_result.get("summary", "") or llm_result.get("reasoning", ""),
            detected_patterns=llm_result.get("key_issues", []) or llm_result.get("vulnerabilities", []),
            recommendations=llm_result.get("recommendations", []),
            fixed_code=llm_result.get("fixed_code", ""),
            analysis_method=analysis_method,
        )
    
    def analyze_quick(self, code: str, gnn_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Quick analysis returning a simple dictionary (for Streamlit integration).
        
        Returns dict with keys matching current app.py expectations plus hybrid additions.
        """
        result = self.analyze(code, gnn_result)
        
        return {
            # Original GNN fields (for backwards compatibility)
            "is_vulnerable": result.final_verdict == "VULNERABLE",
            "vulnerability_score": result.combined_score,
            "confidence": result.confidence,
            "safe_score": 1 - result.combined_score,
            
            # Hybrid analysis fields
            "gnn_score": result.gnn_score,
            "llm_score": result.llm_score,
            "combined_score": result.combined_score,
            "gnn_verdict": result.gnn_verdict,
            "llm_verdict": result.llm_verdict,
            "final_verdict": result.final_verdict,
            "risk_level": result.risk_level.value,
            "agreement": result.agreement,
            
            # New detailed fields
            "key_issues": result.detected_patterns,      # Brief list of issues
            "summary": result.llm_reasoning,             # Detailed summary
            "recommendations": result.recommendations,    # How to fix
            "fixed_code": result.fixed_code,             # Complete fixed code example
            
            # Backwards compatibility aliases
            "llm_reasoning": result.llm_reasoning,
            "detected_patterns": result.detected_patterns,
            "analysis_method": result.analysis_method,
        }


# Convenience function
def hybrid_analyze(
    code: str,
    gnn_vulnerability_score: float,
    gnn_is_vulnerable: bool,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Quick function for hybrid vulnerability analysis.
    
    Args:
        code: Python code to analyze
        gnn_vulnerability_score: GNN's vulnerability score (0-1)
        gnn_is_vulnerable: GNN's verdict
        api_key: Optional Gemini API key
    
    Returns:
        Analysis result dictionary
    """
    analyzer = HybridVulnerabilityAnalyzer(api_key=api_key)
    return analyzer.analyze_quick(
        code=code,
        gnn_result={
            "vulnerability_score": gnn_vulnerability_score,
            "is_vulnerable": gnn_is_vulnerable,
        }
    )


if __name__ == "__main__":
    # Test the hybrid analyzer
    print("Testing Hybrid Vulnerability Analyzer")
    print("=" * 50)
    
    # Test case 1: Obvious vulnerability
    vuln_code = '''
import pickle

def load_data(data):
    return pickle.loads(data)
'''
    
    # Test case 2: Safe complex code (like model.py)
    safe_code = '''
import torch
import torch.nn as nn

class MyModel(nn.Module):
    def __init__(self, input_dim, hidden_dim):
        super().__init__()
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, 1)
    
    def forward(self, x):
        x = torch.relu(self.fc1(x))
        return self.fc2(x)
'''
    
    analyzer = HybridVulnerabilityAnalyzer()
    
    print("\n--- Test 1: Pickle Deserialization ---")
    result1 = analyzer.analyze_quick(
        vuln_code,
        {"vulnerability_score": 1.0, "is_vulnerable": True}
    )
    print(f"GNN Score: {result1['gnn_score']:.1%}")
    print(f"LLM Score: {result1['llm_score']:.1%}")
    print(f"Combined Score: {result1['combined_score']:.1%}")
    print(f"Final Verdict: {result1['final_verdict']}")
    print(f"Agreement: {result1['agreement']}")
    print(f"Reasoning: {result1['llm_reasoning']}")
    
    print("\n--- Test 2: Safe PyTorch Model ---")
    result2 = analyzer.analyze_quick(
        safe_code,
        {"vulnerability_score": 0.95, "is_vulnerable": True}  # GNN false positive
    )
    print(f"GNN Score: {result2['gnn_score']:.1%}")
    print(f"LLM Score: {result2['llm_score']:.1%}")
    print(f"Combined Score: {result2['combined_score']:.1%}")
    print(f"Final Verdict: {result2['final_verdict']}")
    print(f"Agreement: {result2['agreement']}")
    print(f"Reasoning: {result2['llm_reasoning']}")
