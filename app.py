"""
🔒 Python Code Vulnerability Scanner

A Streamlit application for detecting security vulnerabilities in Python code
using Graph Neural Networks (GNN) trained on AST representations.

Features:
- GNN-based vulnerability detection
- LLM-powered explainability (Google Gemini)
- RAG-like architecture for detailed explanations

Usage: streamlit run app.py
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
import networkx as nx

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.modeling.model import VulnerabilityGNN
from src.data_processing.graph_utils import code_to_pyg_graph, NODE_TYPES

# Import LLM explainer
try:
    from src.explainability.llm_explainer import VulnerabilityExplainer
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    print("Warning: LLM explainer not available")


# ============================================================================
# Configuration & Model Loading
# ============================================================================

@st.cache_resource
def load_model():
    """Load the trained GNN model."""
    try:
        # Load config
        with open('configs/base_config.yaml', 'r') as f:
            config = yaml.safe_load(f)
        
        # Initialize model with all parameters
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
        
        # Load trained weights
        model_path = config["output"]["model_save_path"]
        if os.path.exists(model_path):
            model.load_state_dict(torch.load(model_path, map_location='cpu', weights_only=False))
            model.eval()
            return model, config, True
        else:
            return model, config, False
    except Exception as e:
        st.error(f"Error loading model: {e}")
        return None, None, False


def get_llm_explainer(api_key: str = None):
    """Get LLM explainer instance."""
    if not LLM_AVAILABLE:
        return None
    
    # Use provided key or check environment
    key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not key:
        return None
    
    return VulnerabilityExplainer(api_key=key)


def analyze_code(code: str, model, config) -> dict:
    """
    Analyze Python code for vulnerabilities.
    
    Returns:
        dict with keys: is_vulnerable, confidence, details
    """
    # Get threshold from session state or use default
    threshold = st.session_state.get('detection_threshold', 0.35)
    
    # Convert code to graph
    pyg_graph = code_to_pyg_graph(
        code=code,
        label=0,  # Placeholder
        max_nodes=config["dataset"]["max_nodes_per_graph"],
        num_node_features=config["model"]["num_node_features"],
    )
    
    if pyg_graph is None:
        return {
            "error": True,
            "message": "Failed to parse code. Please check for syntax errors.",
            "is_vulnerable": None,
            "confidence": 0,
        }
    
    # Run inference
    with torch.no_grad():
        # Create batch tensor (single graph)
        batch = torch.zeros(pyg_graph.x.size(0), dtype=torch.long)
        
        output = model(pyg_graph.x, pyg_graph.edge_index, batch)
        probabilities = torch.softmax(output, dim=1)
        
        vuln_probability = probabilities[0][1].item()
        
        # Use threshold instead of argmax for more sensitive detection
        is_vulnerable = vuln_probability > threshold
        confidence = vuln_probability if is_vulnerable else probabilities[0][0].item()
    
    return {
        "error": False,
        "is_vulnerable": is_vulnerable,
        "confidence": confidence,
        "vulnerability_score": vuln_probability,
        "safe_score": probabilities[0][0].item(),
        "num_nodes": pyg_graph.x.size(0),
        "num_edges": pyg_graph.edge_index.size(1),
    }


def get_ast_info(code: str) -> dict:
    """Extract AST information for visualization."""
    try:
        tree = ast.parse(code)
        
        # Count node types
        node_counts = {}
        for node in ast.walk(tree):
            node_type = type(node).__name__
            node_counts[node_type] = node_counts.get(node_type, 0) + 1
        
        # Get function definitions
        functions = [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
        
        # Get imports
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(f"{node.module}.{', '.join(alias.name for alias in node.names)}")
        
        # Get class definitions
        classes = [node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
        
        return {
            "success": True,
            "node_counts": node_counts,
            "total_nodes": sum(node_counts.values()),
            "functions": functions,
            "imports": imports,
            "classes": classes,
        }
    except SyntaxError as e:
        return {
            "success": False,
            "error": f"Syntax Error: {e.msg} at line {e.lineno}",
        }


# ============================================================================
# Example Vulnerable Code Snippets
# ============================================================================

EXAMPLE_CODES = {
    "SQL Injection": '''def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()
''',
    "Command Injection": '''import os

def run_command(user_input):
    os.system("ls " + user_input)
''',
    "Path Traversal": '''def read_file(filename):
    with open("/data/" + filename, "r") as f:
        return f.read()
''',
    "Hardcoded Credentials": '''def connect_db():
    password = "admin123"
    connection = mysql.connect(
        host="localhost",
        user="root",
        password=password
    )
    return connection
''',
    "Insecure Deserialization": '''import pickle

def load_data(data):
    return pickle.loads(data)
''',
    "Safe Code Example": '''def calculate_sum(numbers: list) -> int:
    """Calculate the sum of a list of numbers safely."""
    if not isinstance(numbers, list):
        raise TypeError("Input must be a list")
    return sum(numbers)
''',
    "XSS Vulnerability": '''from flask import Flask, request

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    return f"<h1>Hello, {name}!</h1>"
''',
    "Weak Cryptography": '''import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
''',
}


# ============================================================================
# Streamlit UI
# ============================================================================

def main():
    st.set_page_config(
        page_title="🔒 Python Vulnerability Scanner",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    
    # Custom CSS
    st.markdown("""
        <style>
        .vulnerable-box {
            padding: 20px;
            border-radius: 10px;
            background-color: #ffebee;
            border-left: 5px solid #f44336;
        }
        .safe-box {
            padding: 20px;
            border-radius: 10px;
            background-color: #e8f5e9;
            border-left: 5px solid #4caf50;
        }
        .metric-box {
            padding: 15px;
            border-radius: 8px;
            background-color: #f5f5f5;
            text-align: center;
        }
        .stProgress > div > div > div > div {
            background-color: #1976d2;
        }
        </style>
    """, unsafe_allow_html=True)
    
    # Header
    st.title("🔒 Python Code Vulnerability Scanner")
    st.markdown("""
        **Analyze your Python code for security vulnerabilities using Graph Neural Networks.**
        
        This tool uses a GNN model trained on Abstract Syntax Tree (AST) representations 
        to detect potential security issues in your code.
    """)
    
    # Load model
    model, config, model_loaded = load_model()
    
    # Sidebar
    with st.sidebar:
        st.header("ℹ️ About")
        st.markdown("""
            This scanner uses a **Graph Neural Network (GNN)** trained on:
            - 4,000+ vulnerable code examples
            - 20,000+ safe code examples
            - 200+ unique CWE types
            
            **How it works:**
            1. Your code is parsed into an AST
            2. AST is converted to a graph
            3. GNN analyzes the graph structure
            4. Model predicts vulnerability likelihood
        """)
        
        st.divider()
        
        st.header("📊 Model Status")
        if model_loaded:
            st.success("✅ Model loaded successfully")
            st.info(f"""
                **Architecture:**
                - GCN Layers: {config['model']['gcn_layers']}
                - GAT Heads: {config['model']['gat_heads']}
                - Hidden Channels: {config['model']['hidden_channels']}
            """)
        else:
            st.warning("⚠️ Model not found. Using untrained model.")
            st.info("Run `python run_pipeline.py --step train` to train the model.")
        
        st.divider()
        
        st.header("🎯 Vulnerability Types")
        st.markdown("""
            The model can detect:
            - 🔴 SQL Injection (CWE-89)
            - 🔴 Command Injection (CWE-78)
            - 🔴 Path Traversal (CWE-22)
            - 🔴 XSS (CWE-79)
            - 🔴 Insecure Deserialization (CWE-502)
            - 🔴 Hardcoded Credentials (CWE-798)
            - 🔴 Weak Cryptography (CWE-327)
            - And 190+ more CWE types...
        """)
        
        st.divider()
        
        st.header("⚙️ Detection Settings")
        detection_threshold = st.slider(
            "Detection Sensitivity",
            min_value=0.1,
            max_value=0.9,
            value=0.35,
            step=0.05,
            help="Lower values = more sensitive (catches more vulnerabilities but may have false positives). Higher values = more conservative."
        )
        st.caption(f"Current: Flag as vulnerable if score > {detection_threshold:.0%}")
        
        st.divider()
        
        # LLM Explainability Settings
        st.header("🤖 AI Explainability")
        
        enable_llm = st.checkbox(
            "Enable LLM Explanations",
            value=True,
            help="Use Google Gemini to generate detailed explanations"
        )
        
        if enable_llm:
            # Check for existing API key in environment
            env_api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
            
            if env_api_key:
                st.success("✅ API key found in environment")
                api_key = env_api_key
            else:
                api_key = st.text_input(
                    "Gemini API Key",
                    type="password",
                    help="Get your API key from https://makersuite.google.com/app/apikey"
                )
            
            if api_key:
                st.session_state.gemini_api_key = api_key
            
            if not LLM_AVAILABLE:
                st.warning("⚠️ Install google-genai: `pip install google-genai`")
    
    # Store threshold in session state
    st.session_state.detection_threshold = detection_threshold
    st.session_state.enable_llm = enable_llm
    
    # Main content
    tab1, tab2, tab3 = st.tabs(["🔍 Scan Code", "📚 Examples", "📈 Batch Analysis"])
    
    # Initialize session state for code input
    if "code_input" not in st.session_state:
        st.session_state.code_input = ""
    if "last_example" not in st.session_state:
        st.session_state.last_example = "-- Select an example --"
    
    # Tab 1: Code Scanner
    with tab1:
        col1, col2 = st.columns([3, 2])
        
        with col1:
            st.subheader("📝 Enter Your Python Code")
            
            # Example selector dropdown
            example_options = ["-- Select an example --"] + list(EXAMPLE_CODES.keys())
            selected_example = st.selectbox(
                "📚 Load an example:",
                options=example_options,
                index=example_options.index(st.session_state.last_example) if st.session_state.last_example in example_options else 0
            )
            
            # Update code when example selection changes
            if selected_example != st.session_state.last_example:
                st.session_state.last_example = selected_example
                if selected_example != "-- Select an example --":
                    st.session_state.code_input = EXAMPLE_CODES[selected_example]
                st.rerun()
            
            code_input = st.text_area(
                "Paste your Python code here:",
                value=st.session_state.code_input,
                height=400,
                placeholder="def my_function():\n    # Your code here\n    pass",
            )
            
            # Update session state when user types
            if code_input != st.session_state.code_input:
                st.session_state.code_input = code_input
            
            col_btn1, col_btn2 = st.columns(2)
            with col_btn1:
                analyze_button = st.button("🔍 Analyze Code", type="primary", use_container_width=True)
            with col_btn2:
                clear_button = st.button("🗑️ Clear", use_container_width=True)
            
            if clear_button:
                st.session_state.code_input = ""
                st.session_state.last_example = "-- Select an example --"
                st.rerun()
        
        with col2:
            st.subheader("📊 Analysis Results")
            
            if analyze_button and code_input.strip():
                if model is None:
                    st.error("❌ Model not loaded. Cannot analyze code.")
                else:
                    with st.spinner("Analyzing code..."):
                        result = analyze_code(code_input, model, config)
                        ast_info = get_ast_info(code_input)
                    
                    if result.get("error"):
                        st.error(f"❌ {result['message']}")
                        if not ast_info.get("success"):
                            st.code(ast_info.get("error", "Unknown parsing error"))
                    else:
                        # Display main result
                        if result["is_vulnerable"]:
                            st.markdown("""
                                <div class="vulnerable-box">
                                    <h3>⚠️ POTENTIALLY VULNERABLE</h3>
                                    <p>This code may contain security vulnerabilities.</p>
                                </div>
                            """, unsafe_allow_html=True)
                        else:
                            st.markdown("""
                                <div class="safe-box">
                                    <h3>✅ LIKELY SAFE</h3>
                                    <p>No obvious vulnerabilities detected.</p>
                                </div>
                            """, unsafe_allow_html=True)
                        
                        st.divider()
                        
                        # Metrics
                        col_m1, col_m2 = st.columns(2)
                        with col_m1:
                            st.metric(
                                "Vulnerability Score",
                                f"{result['vulnerability_score']*100:.1f}%",
                                delta=None,
                            )
                        with col_m2:
                            st.metric(
                                "Confidence",
                                f"{result['confidence']*100:.1f}%",
                            )
                        
                        # Progress bar
                        st.progress(result['vulnerability_score'], text="Vulnerability likelihood")
                        
                        st.divider()
                        
                        # AST Info
                        if ast_info.get("success"):
                            st.subheader("🌳 Code Structure")
                            
                            col_a1, col_a2 = st.columns(2)
                            with col_a1:
                                st.metric("AST Nodes", ast_info["total_nodes"])
                            with col_a2:
                                st.metric("Graph Edges", result["num_edges"])
                            
                            if ast_info["functions"]:
                                st.write("**Functions:**", ", ".join(ast_info["functions"]))
                            if ast_info["classes"]:
                                st.write("**Classes:**", ", ".join(ast_info["classes"]))
                            if ast_info["imports"]:
                                st.write("**Imports:**", ", ".join(ast_info["imports"][:5]))
                            
                            # Node type distribution
                            with st.expander("📊 AST Node Distribution"):
                                sorted_counts = sorted(ast_info["node_counts"].items(), 
                                                      key=lambda x: x[1], reverse=True)[:10]
                                for node_type, count in sorted_counts:
                                    st.write(f"- {node_type}: {count}")
                        
                        # LLM Explanation Section
                        st.divider()
                        st.subheader("🤖 AI-Powered Explanation")
                        
                        if st.session_state.get("enable_llm", True) and LLM_AVAILABLE:
                            api_key = st.session_state.get("gemini_api_key")
                            
                            if api_key:
                                with st.spinner("🔮 Generating detailed explanation..."):
                                    explainer = get_llm_explainer(api_key)
                                    if explainer:
                                        explanation_result = explainer.explain(
                                            code=code_input,
                                            gnn_result={
                                                "is_vulnerable": result["is_vulnerable"],
                                                "vulnerability_score": result["vulnerability_score"],
                                            }
                                        )
                                        
                                        if explanation_result.get("success"):
                                            st.markdown(explanation_result["explanation"])
                                            
                                            # Show detected patterns
                                            with st.expander("🔍 Detected Patterns (RAG Context)"):
                                                ctx = explanation_result.get("context", {})
                                                if ctx.get("dangerous_patterns"):
                                                    st.write("**Vulnerability Patterns:**")
                                                    for p in ctx["dangerous_patterns"]:
                                                        st.write(f"- {p['type']}: {p['description']}")
                                                if ctx.get("user_inputs"):
                                                    st.write(f"**User Input Sources:** {', '.join(ctx['user_inputs'])}")
                                                if ctx.get("string_operations"):
                                                    st.write(f"**String Operations:** {', '.join(ctx['string_operations'])}")
                                        else:
                                            # Show fallback explanation
                                            st.warning("⚠️ LLM explanation unavailable. Showing pattern-based analysis:")
                                            st.markdown(explanation_result.get("fallback_explanation", "No explanation available."))
                                    else:
                                        st.warning("Could not initialize explainer.")
                            else:
                                st.info("💡 Add your Gemini API key in the sidebar to get AI-powered explanations.")
                        elif not LLM_AVAILABLE:
                            st.info("💡 Install `google-genai` package to enable AI explanations.")
                        else:
                            st.info("💡 Enable LLM explanations in the sidebar for detailed analysis.")
            
            elif analyze_button:
                st.warning("⚠️ Please enter some code to analyze.")
            else:
                st.info("👈 Enter code on the left and click **Analyze Code**")
    
    # Tab 2: Examples
    with tab2:
        st.subheader("📚 Example Code Snippets")
        st.markdown("Try these examples to see how the scanner works:")
        
        example_cols = st.columns(2)
        
        for idx, (name, code) in enumerate(EXAMPLE_CODES.items()):
            with example_cols[idx % 2]:
                with st.expander(f"{'🔴' if 'Safe' not in name else '🟢'} {name}"):
                    st.code(code, language="python")
                    if st.button(f"Analyze", key=f"example_{idx}"):
                        if model is not None:
                            result = analyze_code(code, model, config)
                            if not result.get("error"):
                                if result["is_vulnerable"]:
                                    st.error(f"⚠️ Vulnerable ({result['vulnerability_score']*100:.1f}%)")
                                else:
                                    st.success(f"✅ Safe ({result['safe_score']*100:.1f}%)")
                            else:
                                st.error(result["message"])
                        else:
                            st.warning("Model not loaded")
    
    # Tab 3: Batch Analysis
    with tab3:
        st.subheader("📈 Batch File Analysis")
        st.markdown("Upload Python files to analyze multiple files at once.")
        
        uploaded_files = st.file_uploader(
            "Upload Python files",
            type=["py"],
            accept_multiple_files=True,
        )
        
        if uploaded_files and model is not None:
            if st.button("🔍 Analyze All Files", type="primary"):
                results = []
                progress_bar = st.progress(0)
                
                for idx, file in enumerate(uploaded_files):
                    code = file.read().decode("utf-8")
                    result = analyze_code(code, model, config)
                    result["filename"] = file.name
                    results.append(result)
                    progress_bar.progress((idx + 1) / len(uploaded_files))
                
                # Summary
                st.divider()
                vulnerable_count = sum(1 for r in results if r.get("is_vulnerable"))
                safe_count = sum(1 for r in results if r.get("is_vulnerable") == False)
                error_count = sum(1 for r in results if r.get("error"))
                
                col_s1, col_s2, col_s3 = st.columns(3)
                with col_s1:
                    st.metric("🔴 Vulnerable", vulnerable_count)
                with col_s2:
                    st.metric("🟢 Safe", safe_count)
                with col_s3:
                    st.metric("⚠️ Errors", error_count)
                
                # Details
                st.divider()
                st.subheader("📋 Detailed Results")
                
                for result in results:
                    if result.get("error"):
                        st.warning(f"⚠️ **{result['filename']}**: {result['message']}")
                    elif result["is_vulnerable"]:
                        st.error(f"🔴 **{result['filename']}**: Vulnerable ({result['vulnerability_score']*100:.1f}%)")
                    else:
                        st.success(f"🟢 **{result['filename']}**: Safe ({result['safe_score']*100:.1f}%)")
        
        elif uploaded_files and model is None:
            st.warning("⚠️ Model not loaded. Cannot analyze files.")
    
    # Footer
    st.divider()
    st.markdown("""
        <div style="text-align: center; color: gray; padding: 20px;">
            <p>🔒 Python Vulnerability Scanner | Powered by Graph Neural Networks</p>
            <p>⚠️ This tool provides suggestions only. Always conduct thorough security reviews.</p>
        </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
