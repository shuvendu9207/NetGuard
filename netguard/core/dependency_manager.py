"""
Dependency Manager
Auto-installs required packages globally on first run.
"""

import subprocess
import sys

REQUIRED_PACKAGES = [
    "scapy",
    "pyyaml",
    "scikit-learn",
    "numpy",
    "pandas",
    "colorama",
    "jinja2",
    "requests",
]


def ensure_dependencies():
    missing = []
    for pkg in REQUIRED_PACKAGES:
        import_name = {
            "pyyaml":       "yaml",
            "scikit-learn": "sklearn",
        }.get(pkg, pkg)
        try:
            __import__(import_name)
        except ImportError:
            missing.append(pkg)

    if missing:
        print(f"[NetGuard] Installing: {', '.join(missing)}")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install"] + missing
        )
        print("[NetGuard] Done.")
