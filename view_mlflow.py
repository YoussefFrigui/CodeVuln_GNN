"""
MLflow UI Launcher

This script launches the MLflow tracking UI to view experiment results.
Run this script and open the provided URL in your browser to explore:
- Experiment runs and their metrics
- Model parameters and hyperparameters
- Training curves and comparisons
- Logged artifacts (models, confusion matrices, configs)

Usage:
    python view_mlflow.py

The UI will be available at: http://localhost:5000
"""

import subprocess
import sys
import os

def main():
    # Read tracking URI from config
    import yaml
    try:
        with open('configs/base_config.yaml', 'r') as f:
            config = yaml.safe_load(f)
        tracking_uri = config.get('mlflow', {}).get('tracking_uri', 'outputs/mlruns')
    except Exception as e:
        print(f"Warning: Could not read config file. Using default tracking URI.")
        tracking_uri = 'outputs/mlruns'
    
    # Check if tracking directory exists
    if not os.path.exists(tracking_uri):
        print(f"❌ MLflow tracking directory not found: {tracking_uri}")
        print(f"ℹ️  Run training first to generate MLflow data:")
        print(f"   python run_pipeline.py --step train")
        sys.exit(1)
    
    print(f"🚀 Starting MLflow UI...")
    print(f"📂 Tracking URI: {tracking_uri}")
    print(f"🌐 Open in browser: http://localhost:5000")
    print(f"\n⌨️  Press Ctrl+C to stop the server\n")
    
    try:
        # Launch MLflow UI
        subprocess.run([
            sys.executable, "-m", "mlflow", "ui",
            "--backend-store-uri", tracking_uri,
            "--host", "0.0.0.0",
            "--port", "5000"
        ])
    except KeyboardInterrupt:
        print("\n\n✅ MLflow UI stopped")
    except Exception as e:
        print(f"\n❌ Error launching MLflow UI: {e}")
        print(f"ℹ️  Make sure MLflow is installed: pip install mlflow")
        sys.exit(1)

if __name__ == "__main__":
    main()
