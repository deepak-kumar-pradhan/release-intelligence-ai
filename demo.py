#!/usr/bin/env python3
"""
Demo script for Release Intelligence System with real tools.
Set environment variables for live demo.
"""

import os
import sys
from pathlib import Path

# Add src to path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from src.workflow.ri_workflow import SecurityReviewWorkflow

def main():
    # Example services for demo
    services = [
        {"service_name": "web-service", "release_version": "main"},
        {"service_name": "api-service", "release_version": "v2.1"}
    ]

    print("Initializing Release Intelligence Workflow...")
    workflow = SecurityReviewWorkflow()

    print("Running security review...")
    result = workflow.orchestrate(services=services, hitl_approved=True)

    print(f"Review Status: {result.get('status', 'Unknown')}")
    print("Demo completed. Check reports/ for PDF attestation.")

if __name__ == "__main__":
    main()