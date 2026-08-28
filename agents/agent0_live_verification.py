"""
Agent 0 — Live Application Verification Lane Orchestrator
------------------------------------------------------------
Executes dynamic security scans and protocol verification suites against an EXPLICITLY authorized client target:
  - Validates engagement authorization & scope confirmation.
  - Logs engagement audit details (target, engagement ID, operator, timestamp).
  - Sub-step 1: OWASP ZAP baseline dynamic scan & CWE-to-Control mapping.
  - Sub-step 2: Pytest protocol verification suite execution.
  - Sub-step 3: Merges and normalizes evidence into unified schema (evidence_type: "dynamic_scan").

CLI Usage:
    python agents/agent0_live_verification.py \
        --authorized-target "https://staging.clientapp.example/" \
        --engagement-id "fleetbase_2026_q3" \
        --frameworks nist_800_63b,owasp_asvs_v5 \
        --scope-confirm
"""

import os
import sys
import json
import time
import yaml
import argparse
import subprocess
from typing import Dict, List, Any

AGENTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(AGENTS_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

LOG_DIR = os.path.join(PROJECT_ROOT, "logs")
CONFIG_DIR = os.path.join(PROJECT_ROOT, "config")
MAPPING_FILE = os.path.join(CONFIG_DIR, "control_mapping.yaml")
AUDIT_LOG_FILE = os.path.join(LOG_DIR, "live_verification_audit.log")

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)


def log_audit_event(engagement_id: str, target: str, operator: str, status: str, details: str):
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    entry = {
        "timestamp": timestamp,
        "engagement_id": engagement_id,
        "target": target,
        "operator": operator,
        "status": status,
        "details": details
    }
    with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[{timestamp}] AUDIT LOG: Engagement='{engagement_id}' | Target='{target}' | Status={status}")


def load_control_mappings() -> Dict[str, Any]:
    if not os.path.exists(MAPPING_FILE):
        return {}
    with open(MAPPING_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
        return data.get("cwe_mappings", {})


def run_zap_baseline_substep(target_url: str, engagement_id: str, mappings: Dict[str, Any]) -> List[Dict[str, Any]]:
    print("\n--- Sub-step 1: Running OWASP ZAP Baseline Scan ---")
    zap_output_json = os.path.join(PROJECT_ROOT, "zap_raw.json")
    normalized_findings = []

    # Check docker availability for zap-baseline.py
    docker_check = subprocess.run(["which", "docker"], capture_output=True, text=True)
    if docker_check.returncode != 0:
        print("[WARNING] Docker daemon is not available on host system. Skipping ZAP container scan.")
        return normalized_findings

    zap_cmd = [
        "docker", "run", "--rm", "-v", f"{PROJECT_ROOT}:/zap/wrk/:rw",
        "owasp/zap2docker-stable", "zap-baseline.py",
        "-t", target_url,
        "-J", "zap_raw.json"
    ]
    try:
        print(f"[ZAP] Launching: {' '.join(zap_cmd)}")
        subprocess.run(zap_cmd, check=False, timeout=300)
        
        if os.path.exists(zap_output_json):
            with open(zap_output_json, "r", encoding="utf-8") as f:
                zap_data = json.load(f)
            
            site_alerts = zap_data.get("site", [])
            for site in site_alerts:
                alerts = site.get("alerts", [])
                for idx, alert in enumerate(alerts):
                    cweid = str(alert.get("cweid", "unmapped"))
                    cwe_key = f"CWE-{cweid}" if cweid != "unmapped" else "unmapped"
                    
                    mapped_controls = mappings.get(cweid, {})
                    status = "FAIL" if alert.get("riskcode", "0") in ["2", "3"] else "PARTIAL"
                    
                    normalized_findings.append({
                        "control_id": mapped_controls.get("asvs") or mapped_controls.get("nist_csf") or cwe_key,
                        "framework": "zap_cwe_map",
                        "status": status,
                        "evidence_type": "dynamic_scan",
                        "evidence_source": f"zap_raw.json#alert_{idx+1}",
                        "evidence_summary": f"[{alert.get('name')}] {alert.get('desc')} (URL: {alert.get('url')})",
                        "engagement_id": engagement_id,
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    })
            print(f"[OK] Parsed {len(normalized_findings)} dynamic findings from ZAP scan.")
    except Exception as exc:
        print(f"[ERROR] ZAP scan error: {exc}")
        
    return normalized_findings


def run_pytest_protocol_substep(target_url: str, engagement_id: str) -> List[Dict[str, Any]]:
    print("\n--- Sub-step 2: Running Pytest Protocol Verification Suite ---")
    protocol_report_json = os.path.join(PROJECT_ROOT, "protocol_raw.json")
    normalized_findings = []

    env = os.environ.copy()
    env["VERIFICATION_TARGET_URL"] = target_url

    pytest_cmd = [
        sys.executable, "-m", "pytest",
        "tests/protocol_verification/",
        "--json-report",
        f"--json-report-file={protocol_report_json}"
    ]

    try:
        print(f"[Pytest] Launching protocol verification suite against {target_url}...")
        subprocess.run(pytest_cmd, env=env, check=False)

        if os.path.exists(protocol_report_json):
            with open(protocol_report_json, "r", encoding="utf-8") as f:
                report_data = json.load(f)

            tests = report_data.get("tests", [])
            for test in tests:
                nodeid = test.get("nodeid", "")
                outcome = test.get("outcome", "unknown").upper()

                outcome_str = str(outcome).upper()
                if outcome_str == "PASSED":
                    status = "PASS"
                elif outcome_str == "FAILED":
                    status = "FAIL"
                else:  # SKIPPED, XFAIL, UNKNOWN
                    status = "NO_DATA"
                summary_msg = test.get("call", {}).get("longrepr", "Test passed successfully.") if outcome == "FAILED" else f"Test {nodeid} executed with outcome {outcome}."

                normalized_findings.append({
                    "control_id": nodeid.split("::")[-1],
                    "framework": "protocol_verification",
                    "status": status,
                    "evidence_type": "dynamic_scan",
                    "evidence_source": f"protocol_raw.json#{nodeid}",
                    "evidence_summary": str(summary_msg)[:300],
                    "engagement_id": engagement_id,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                })
            print(f"[OK] Parsed {len(normalized_findings)} protocol test results from pytest report.")
    except Exception as exc:
        print(f"[ERROR] Pytest execution error: {exc}")

    return normalized_findings


def main():
    parser = argparse.ArgumentParser(description="Agent 0 Live Application Verification Orchestrator")
    parser.add_argument("--authorized-target", required=True, help="Target URL explicitly authorized for this engagement")
    parser.add_argument("--engagement-id", required=True, help="Unique engagement identifier (e.g. client_2026_q3)")
    parser.add_argument("--frameworks", default="nist_800_63b,owasp_asvs_v5", help="Comma-separated frameworks")
    parser.add_argument("--scope-confirm", action="store_true", help="Explicit confirmation of authorized target scope")
    parser.add_argument("--operator", default="cli_user", help="Operator identity triggering verification")

    args = parser.parse_args()

    # Scope confirmation safeguard
    if not getattr(args, "scope_confirm", False):
        log_audit_event(args.engagement_id, args.authorized_target, args.operator, "REFUSED", "Missing explicit --scope-confirm flag.")
        print("\n❌ [ERROR] Explicit scope confirmation is REQUIRED. Please rerun with --scope-confirm.")
        sys.exit(1)

    print("============================================================")
    print(" Agent 0 — Live Application Verification Lane")
    print(f" Target         : {args.authorized_target}")
    print(f" Engagement ID  : {args.engagement_id}")
    print(f" Frameworks     : {args.frameworks}")
    print(f" Scope Confirmed: YES")
    print("============================================================\n")

    log_audit_event(args.engagement_id, args.authorized_target, args.operator, "STARTED", "Scope confirmed and verification initialized.")

    mappings = load_control_mappings()
    zap_results = run_zap_baseline_substep(args.authorized_target, args.engagement_id, mappings)
    pytest_results = run_pytest_protocol_substep(args.authorized_target, args.engagement_id)

    combined_evidence = zap_results + pytest_results
    unified_report_file = os.path.join(PROJECT_ROOT, "unified_verification_findings.json")

    with open(unified_report_file, "w", encoding="utf-8") as f:
        json.dump(combined_evidence, f, indent=2)

    log_audit_event(args.engagement_id, args.authorized_target, args.operator, "COMPLETED", f"Generated {len(combined_evidence)} verified findings.")
    print(f"\n✅ [OK] Live verification complete! Unified evidence saved to '{unified_report_file}'.")


if __name__ == "__main__":
    main()
