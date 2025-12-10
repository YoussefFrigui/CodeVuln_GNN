"""
🛡️ CodeVuln - AI-Powered Code Vulnerability Scanner
Professional Demo Interface with GNN + LLM Hybrid Analysis

A modern Streamlit application for detecting and explaining security
vulnerabilities in Python code using Graph Neural Networks and LLMs.

Usage: streamlit run app_demo.py
"""

import os
import sys
import ast
from pathlib import Path

# Set environment variable to avoid OpenMP issues
os.environ['KMP_DUPLICATE_LIB_OK'] = 'TRUE'

import streamlit as st
import torch
import yaml

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.modeling.model import VulnerabilityGNN
from src.data_processing.graph_utils import code_to_pyg_graph

# Import Hybrid Analyzer
try:
    from src.explainability.hybrid_analyzer import HybridVulnerabilityAnalyzer
    HYBRID_AVAILABLE = True
except ImportError:
    HYBRID_AVAILABLE = False

# ============================================================================
# Page Configuration & Styling
# ============================================================================

st.set_page_config(
    page_title="Code Vulnerability Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap');
    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        background: #101322 !important;
    }
    .stApp {
        background: #101322 !important;
    }
    .main .block-container {
        padding: 2.5rem 2.5rem 2rem 2.5rem;
        max-width: 1400px;
        background: #101322 !important;
    }
    .custom-header {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        margin-bottom: 2.5rem;
    }
    .custom-header h2 {
        color: #fff;
        font-size: 1.35rem;
        font-weight: 700;
        margin: 0;
        letter-spacing: 0.01em;
    }
    .section-title {
        color: #fff;
        font-size: 2.2rem;
        font-weight: 700;
        margin-bottom: 0.5rem;
        margin-top: 0.5rem;
        letter-spacing: -0.01em;
    }
    .section-desc {
        color: #b3b8d0;
        font-size: 1.05rem;
        margin-bottom: 2.2rem;
    }
    .input-label {
        color: #b3b8d0;
        font-size: 1rem;
        font-weight: 500;
        margin-bottom: 0.5rem;
    }
    .custom-card-results {
        background: #181c2f !important;
        border-radius: 18px;
        padding: 2.2rem 2rem 2rem 2rem;
        box-shadow: 0 2px 16px 0 rgba(16,19,34,0.08);
        border: 1.5px dashed #23263a;
        min-height: 320px;
        display: block;
    }
    .stTextArea textarea {
        background: #14172b !important;
        color: #e5e7ef !important;
        border: 1.5px solid #23263a !important;
        border-radius: 10px !important;
        font-size: 1.1rem !important;
        min-height: 220px !important;
    }
    .stTextArea textarea:focus {
        border-color: #2563eb !important;
        box-shadow: 0 0 0 2px #2563eb33 !important;
    }
    .stSelectbox > div > div {
        background: #14172b !important;
        color: #e5e7ef !important;
        border: 1.5px solid #23263a !important;
        border-radius: 8px !important;
    }
    .stSelectbox label {
        color: #b3b8d0 !important;
    }
    .stButton > button {
        width: 100%;
    }
    .placeholder-results {
        color: #b3b8d0;
        text-align: center;
        font-size: 1.1rem;
        margin-top: 1.5rem;
    }
    .placeholder-icon {
        font-size: 2.5rem;
        color: #3b82f6;
        margin-bottom: 0.5rem;
    }
    .vulnerable-result {
        background: #7f1d1d !important;
        color: #fecaca !important;
        border-left: 4px solid #dc2626 !important;
        padding: 1.2rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
    .safe-result {
        background: #1d4d2d !important;
        color: #86efac !important;
        border-left: 4px solid #22c55e !important;
        padding: 1.2rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
    .issue-box {
        background: #2d1f1f !important;
        border-left: 4px solid #f87171 !important;
        padding: 0.75rem 1rem;
        border-radius: 6px;
        margin: 0.5rem 0;
        color: #fca5a5 !important;
    }
    .rec-box {
        background: #1f2d3d !important;
        border-left: 4px solid #60a5fa !important;
        padding: 1rem 1.25rem;
        border-radius: 8px;
        margin: 0.75rem 0;
        color: #bfdbfe !important;
    }
    .rec-box ul {
        margin: 0;
        padding-left: 1.25rem;
    }
    .rec-box li {
        color: #bfdbfe !important;
        margin-bottom: 0.5rem;
    }
    /* Style the results container using Streamlit container */
    .results-box {
        background: #181c2f !important;
        border-radius: 18px;
        padding: 2rem;
        border: 1.5px solid #23263a;
        min-height: 320px;
    }
    .stSpinner > div {
        background: transparent !important;
    }
    #MainMenu, footer, header { visibility: hidden; }
</style>
""", unsafe_allow_html=True)


# ============================================================================
# Model Loading & Analysis Functions
# ============================================================================

@st.cache_resource
def load_model():
    """Load the trained GNN model."""
    try:
        with open('configs/base_config.yaml', 'r') as f:
            config = yaml.safe_load(f)
        
        model = VulnerabilityGNN(
            num_node_features=config["model"]["num_node_features"],
            hidden_channels=config["model"]["hidden_channels"],
            num_classes=config["model"]["num_classes"],
            dropout=config["model"]["dropout"],
            gcn_layers=config["model"]["gcn_layers"],
            gat_heads=config["model"]["gat_heads"],
            use_batch_norm=config["model"].get("use_batch_norm", True),
            use_residual=config["model"].get("use_residual", True),
        )
        
        model_path = config["output"]["model_save_path"]
        if os.path.exists(model_path):
            model.load_state_dict(torch.load(model_path, map_location='cpu', weights_only=False))
            model.eval()
            return model, config, True
        return model, config, False
    except Exception as e:
        st.error(f"Error loading model: {e}")
        return None, None, False


def analyze_with_gnn(code: str, model, config) -> dict:
    """Run GNN analysis on code."""
    pyg_graph = code_to_pyg_graph(
        code=code,
        label=0,
        max_nodes=config["dataset"]["max_nodes_per_graph"],
        num_node_features=config["model"]["num_node_features"],
    )
    
    if pyg_graph is None:
        return {"error": True, "message": "Failed to parse code"}
    
    with torch.no_grad():
        batch = torch.zeros(pyg_graph.x.size(0), dtype=torch.long)
        output = model(pyg_graph.x, pyg_graph.edge_index, batch)
        probabilities = torch.softmax(output, dim=1)
        
        return {
            "error": False,
            "vulnerability_score": probabilities[0][1].item(),
            "is_vulnerable": probabilities[0][1].item() > 0.35,
        }


def get_ast_info(code: str) -> dict:
    """Extract AST information."""
    try:
        tree = ast.parse(code)
        
        node_counts = {}
        for node in ast.walk(tree):
            node_type = type(node).__name__
            node_counts[node_type] = node_counts.get(node_type, 0) + 1
        
        functions = [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(f"{node.module}")
        
        classes = [node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
        
        return {
            "success": True,
            "node_counts": node_counts,
            "total_nodes": sum(node_counts.values()),
            "functions": functions,
            "imports": list(set(imports)),
            "classes": classes,
        }
    except SyntaxError as e:
        return {
            "success": False,
            "error": f"Syntax Error: {e.msg} at line {e.lineno}",
        }


# ============================================================================
# Example Code Snippets
# ============================================================================

DEMO_EXAMPLES = {
    "SQL Injection (Vulnerable)": {
        "code": '''def get_user_data(user_id):
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    return cursor.fetchall()''',
        "vulnerable": True
    },
    "Command Injection (Vulnerable)": {
        "code": '''import os

def process_file(filename):
    os.system("cat " + filename)''',
        "vulnerable": True
    },
    "Path Traversal (Vulnerable)": {
        "code": '''def download_file(filename):
    file_path = "/uploads/" + filename
    with open(file_path, 'rb') as f:
        return f.read()''',
        "vulnerable": True
    },
    "Pickle Deserialization (Vulnerable)": {
        "code": '''import pickle

def load_user_session(data):
    return pickle.loads(data)''',
        "vulnerable": True
    },
    "Parameterized Query (Safe)": {
        "code": '''def get_user_data(user_id):
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
    return cursor.fetchall()''',
        "vulnerable": False
    },
    "Subprocess with List Args (Safe)": {
        "code": '''import subprocess

def run_command(user_input):
    subprocess.run(["ls", "-la", user_input], check=True)''',
        "vulnerable": False
    },
}

# ============================================================================
# Main Application
# ============================================================================

def main():
    model, config, model_loaded = load_model()
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")

    # --- Custom Header ---
    st.markdown("""
        <div class="custom-header">
            <svg width="28" height="28" viewBox="0 0 28 28" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="28" height="28" rx="8" fill="#23263a"/><path d="M8.5 14C8.5 11.5147 10.5147 9.5 13 9.5C15.4853 9.5 17.5 11.5147 17.5 14C17.5 16.4853 15.4853 18.5 13 18.5C10.5147 18.5 8.5 16.4853 8.5 14Z" fill="#2563eb"/><path d="M13 4C7.47715 4 3 8.47715 3 14C3 19.5228 7.47715 24 13 24C18.5228 24 23 19.5228 23 14C23 8.47715 18.5228 4 13 4ZM13 22C8.02944 22 4 17.9706 4 13C4 8.02944 8.02944 4 13 4C17.9706 4 22 8.02944 22 13C22 17.9706 17.9706 22 13 22Z" fill="#2563eb"/></svg>
            <h2>Code Vulnerability Detector</h2>
        </div>
    """, unsafe_allow_html=True)

    # --- Main Two-Column Layout ---
    col_left, col_right = st.columns([1.25, 1])

    with col_left:
        st.markdown('<div class="section-title">Analyze Your Code</div>', unsafe_allow_html=True)
        st.markdown('<div class="section-desc">Paste your code below, select an example, and get an instant vulnerability report.</div>', unsafe_allow_html=True)
        
        with st.container():
            st.markdown('<div class="input-label">Language</div>', unsafe_allow_html=True)
            st.selectbox("Language", ["Python"], index=0, key="lang_select", label_visibility="collapsed")
            
            st.markdown('<div class="input-label" style="margin-top:1.2rem;">Load Example</div>', unsafe_allow_html=True)
            selected_example = st.selectbox(
                "Load example",
                ["Select an example..."] + list(DEMO_EXAMPLES.keys()),
                label_visibility="collapsed",
                key="example_select"
            )
            
            # Initialize session state for code input if not exists
            if "code_input" not in st.session_state:
                st.session_state.code_input = ""
            
            # Load example code into session state when selected
            if selected_example != "Select an example...":
                st.session_state.code_input = DEMO_EXAMPLES[selected_example]["code"]
            
            st.markdown('<div class="input-label" style="margin-top:1.2rem;">Code Input</div>', unsafe_allow_html=True)
            code_input = st.text_area(
                "Paste your code here...",
                value=st.session_state.code_input,
                height=260,
                placeholder="Paste your Python code here...",
                label_visibility="collapsed"
            )
            
            # Update session state when user types in the text area
            st.session_state.code_input = code_input
            
            analyze_clicked = st.button("Analyze Code", key="analyze_btn", use_container_width=True)

    with col_right:
        st.markdown('<div class="section-title">Analysis Results</div>', unsafe_allow_html=True)
        
        # Build results HTML content
        results_html = ""
        
        if not analyze_clicked:
            results_html = '<div style="text-align:center;padding:2rem 0;"><div style="color:#b3b8d0;font-size:1.1rem;">Results will appear here after analysis.<br/><br/>Paste your code and click "Analyze Code" to begin.</div></div>'
        elif analyze_clicked and not code_input.strip():
            results_html = '<div style="color:#b3b8d0;text-align:center;padding:2rem;">Please enter code to analyze.</div>'
        elif analyze_clicked and code_input.strip():
            if not model_loaded:
                results_html = '<div style="color:#b3b8d0;text-align:center;padding:2rem;">Model not loaded.</div>'
            else:
                with st.spinner("Analyzing code..."):
                    # GNN Analysis
                    gnn_result = analyze_with_gnn(code_input, model, config)
                    if gnn_result.get("error"):
                        results_html = f'<div style="color:#b3b8d0;text-align:center;padding:2rem;">{gnn_result.get("message", "Analysis failed")}</div>'
                    else:
                        vuln_score = gnn_result["vulnerability_score"]
                        is_vulnerable = gnn_result["is_vulnerable"]
                        risk_level = "Critical" if vuln_score > 0.8 else "High" if vuln_score > 0.6 else "Medium" if vuln_score > 0.4 else "Low"
                        
                        # Hybrid Analysis (GNN + LLM)
                        hybrid_result = None
                        if HYBRID_AVAILABLE and api_key:
                            try:
                                analyzer = HybridVulnerabilityAnalyzer(api_key=api_key)
                                hybrid_result = analyzer.analyze_quick(code_input, gnn_result)
                            except Exception:
                                pass
                        
                        if hybrid_result:
                            vuln_score = hybrid_result["vulnerability_score"]
                            is_vulnerable = hybrid_result["is_vulnerable"]
                            risk_level = hybrid_result["risk_level"]
                        
                        # Build result HTML
                        results_html = f'<div style="color:#fff;font-size:1.2rem;font-weight:600;margin-bottom:0.5rem;">Vulnerability Score: <span style="color:#2563eb">{vuln_score*100:.0f}%</span></div>'
                        results_html += f'<div style="color:#b3b8d0;font-size:1.05rem;margin-bottom:1.2rem;">Risk Level: <span style="color:#2563eb;font-weight:600">{risk_level}</span></div>'
                        
                        if is_vulnerable:
                            results_html += '<div style="background:#7f1d1d;color:#fecaca;border-left:4px solid #dc2626;padding:1.2rem;border-radius:8px;margin:1rem 0;"><strong>Vulnerabilities Detected</strong><br/>Security issues were found in this code.</div>'
                        else:
                            results_html += '<div style="background:#1d4d2d;color:#86efac;border-left:4px solid #22c55e;padding:1.2rem;border-radius:8px;margin:1rem 0;"><strong>No Issues Found</strong><br/>The code appears to follow secure practices.</div>'
                        
                        # Add hybrid analysis details if available
                        if hybrid_result:
                            key_issues = hybrid_result.get("key_issues") or hybrid_result.get("detected_patterns", [])
                            if key_issues:
                                valid_issues = [i for i in key_issues if i and i.lower() not in ["none", "n/a", ""]]
                                if valid_issues:
                                    results_html += '<hr style="background:#23263a;border:none;height:1px;margin:1rem 0;">'
                                    results_html += '<div style="color:#fff;font-weight:600;margin:1rem 0 0.5rem;">Security Issues</div>'
                                    for issue in valid_issues:
                                        results_html += f'<div style="background:#2d1f1f;border-left:4px solid #f87171;padding:0.75rem 1rem;border-radius:6px;margin:0.5rem 0;color:#fca5a5;">{issue}</div>'
                            
                            summary = hybrid_result.get("summary") or hybrid_result.get("llm_reasoning", "")
                            if summary:
                                results_html += '<hr style="background:#23263a;border:none;height:1px;margin:1rem 0;">'
                                results_html += f'<div style="color:#b3b8d0;font-size:0.9rem;line-height:1.6;">{summary}</div>'
                            
                            recommendations = hybrid_result.get("recommendations", [])
                            if recommendations:
                                valid_recs = [r for r in recommendations if r and r.lower() not in ["none", "none needed", "n/a", ""]]
                                if valid_recs:
                                    results_html += '<hr style="background:#23263a;border:none;height:1px;margin:1rem 0;">'
                                    results_html += '<div style="color:#fff;font-weight:600;margin:1rem 0 0.5rem;">Recommendations</div>'
                                    for rec in valid_recs:
                                        rec_text = rec.strip()
                                        if rec_text.startswith(("- ", "• ", "* ")):
                                            rec_text = rec_text[2:]
                                        results_html += f'<div style="background:#1f2d3d;border-left:4px solid #60a5fa;padding:1rem 1.25rem;border-radius:8px;margin:0.75rem 0;color:#bfdbfe;">• {rec_text}</div>'
        
        # Render entire results box as single HTML block
        full_html = '<div class="results-box">' + results_html + '</div>'
        st.markdown(full_html, unsafe_allow_html=True)
        
        # Handle fixed code separately (needs st.code for syntax highlighting)
        if analyze_clicked and code_input.strip() and model_loaded:
            gnn_result = analyze_with_gnn(code_input, model, config)
            if not gnn_result.get("error") and HYBRID_AVAILABLE and api_key:
                try:
                    analyzer = HybridVulnerabilityAnalyzer(api_key=api_key)
                    hybrid_result = analyzer.analyze_quick(code_input, gnn_result)
                    fixed_code = hybrid_result.get("fixed_code", "") if hybrid_result else ""
                    if fixed_code and fixed_code.strip() and fixed_code.strip().lower() not in ["no fix needed - code is secure", "no fix needed", "none"]:
                        st.markdown('<div style="color:#fff;font-weight:600;margin:1rem 0 0.5rem;">Fixed Code</div>', unsafe_allow_html=True)
                        st.code(fixed_code.strip(), language="python")
                except Exception:
                    pass

    # --- Footer ---
    st.markdown("""
        <div style="text-align: center; color: #4b5563; font-size: 0.95rem; padding-top: 2.5rem; margin-top: 2.5rem;">

        </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
