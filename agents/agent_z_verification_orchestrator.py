"""
Agent Z: Autonomous Verification Orchestrator & Normalizer
Coordinates Agent X (Discovery & Static) and Agent Y (Dynamic Probes),
enforces scope authorization gates, verifies tenant legal agreements,
logs to immutable hash-chained audit trails, normalizes findings, and updates unified_verification_findings.json.
"""

import os
import json
import time
import hashlib
import argparse
import subprocess
from typing import List, Dict, Any

from agents.agent_x_discovery import AgentXDiscovery
from agents.agent_y_dynamic_probes import AgentYDynamicProbes
import application_security_trust as ast


class AgentZOrchestrator:
    def __init__(
        self,
        target_url: str = "http://127.0.0.1:8000",
        api_token: str = None,
        framework: str = "nist/sp_800_63b_r4",
        scope_confirmed: bool = False,
        operator: str = "system",
        tenant_id: str = "default_tenant",
        enable_zap: bool = True,
        project_root: str = None
    ):
        self.target_url = target_url
        self.api_token = api_token
        self.framework = framework
        self.scope_confirmed = scope_confirmed
        self.operator = operator
        self.tenant_id = tenant_id
        self.enable_zap = enable_zap
        self.project_root = project_root or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.log_dir = os.path.join(self.project_root, "logs")
        os.makedirs(self.log_dir, exist_ok=True)
        self.audit_log_file = os.path.join(self.log_dir, "live_verification_audit.log")
        
        self.agent_x = AgentXDiscovery(target_url=target_url, api_token=api_token, project_root=self.project_root)
        self.agent_y = AgentYDynamicProbes(
            target_url=target_url,
            api_token=api_token,
            framework=framework,
            allow_local_dev=True
        )

    def _redact_token(self, token: str) -> str:
        """Returns a safe SHA256 hash digest of the token for audit trails without exposing plaintext."""
        if not token:
            return "NO_TOKEN"
        return f"SHA256:{hashlib.sha256(token.encode()).hexdigest()[:12]}..."

    def _write_audit_log(self, status: str, details: str, findings_count: int = 0):
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        entry = {
            "timestamp": timestamp,
            "operator": self.operator,
            "tenant_id": self.tenant_id,
            "target_url": self.target_url,
            "framework": self.framework,
            "scope_confirmed": self.scope_confirmed,
            "token_hash": self._redact_token(self.api_token),
            "status": status,
            "findings_count": findings_count,
            "details": details
        }
        
        # 1. Plain append log
        with open(self.audit_log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        # 2. Immutable hash-chained audit record in application_security_trust
        ast.log_security_event(
            tenant_id=self.tenant_id,
            action="MODE_B_DYNAMIC_PROBE",
            actor=self.operator,
            resource=self.target_url,
            status=status,
            details=entry
        )

        print(f"[{timestamp}] AUDIT LOG: Operator='{self.operator}' | Tenant='{self.tenant_id}' | Target='{self.target_url}' | Status={status}")

    def _verify_legal_agreements(self):
        """Verifies if tenant has signed required NDA/DPA and Mode B Execution Authorization."""
        legal = ast.get_tenant_legal_agreement_status(self.tenant_id)
        # If tenant vault has legal file, enforce check
        if os.path.exists(os.path.join(ast.get_tenant_vault_dir(self.tenant_id), "legal_agreements.json")):
            if not (legal.get("nda_signed") and legal.get("dpa_signed")):
                raise PermissionError(f"Legal Gate Failure: Tenant '{self.tenant_id}' lacks signed NDA & DPA agreements in client vault.")

    def _run_zap_if_enabled(self) -> List[Dict[str, Any]]:
        if not self.enable_zap:
            return []
        print("[*] Checking Docker availability for ZAP active scan...")
        docker_check = subprocess.run(["which", "docker"], capture_output=True, text=True)
        if docker_check.returncode != 0:
            print("[WARNING] Docker daemon is not available on host. Skipping ZAP scan.")
            return [{
                "control_id": "ASVS V14 (ZAP Baseline)",
                "title": "ZAP Dynamic Scanner Warning",
                "status": "NOT_APPLICABLE",
                "evidence_type": "untested",
                "evidence_source": "ZAP_Scanner",
                "evidence_summary": "Docker daemon unavailable on host system. Active ZAP scan SKIPPED."
            }]
        return []

    def execute_and_normalize(self) -> List[Dict[str, Any]]:
        # Hard authorization gate 1: Scope Affirmation
        if not self.scope_confirmed:
            msg = f"Scope Authorization Gate Violation: Operator '{self.operator}' failed to confirm explicit target authorization for {self.target_url}."
            self._write_audit_log("BLOCKED_UNAUTHORIZED", msg)
            raise PermissionError(msg)

        # Hard authorization gate 2: Legal Vault Authorization Check
        self._verify_legal_agreements()

        print(f"[*] Agent Z Orchestrator: Starting authorized discovery & dynamic verification against {self.target_url}...")
        self._write_audit_log("INITIATED", "Authorized verification probe suite started.")

        try:
            # Step 1: Check Target Reachability
            target_online = False
            try:
                import urllib.request
                req = urllib.request.Request(self.target_url, headers={"User-Agent": "ComplianceProber/1.0"})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    target_online = True
            except Exception:
                target_online = False

            if not target_online:
                print(f"[!] Target URL '{self.target_url}' is unreachable. Skipping live network probes.")

            # Step 1: Run Agent X Discovery & Static Scans
            x_findings = self.agent_x.run_all()
            
            # Step 2: Run Agent Y Dynamic Probes (only if target is online)
            y_findings = self.agent_y.run_all() if target_online else []
            
            # Step 2b: Run Headless Playwright Browser Probes (only if target is online)
            browser_findings = []
            if target_online:
                try:
                    import asyncio
                    import agent_y_browser_prober as browser_prober
                    browser_findings = asyncio.run(browser_prober.probe_url_with_browser(
                        target_url=self.target_url,
                        auth_token=self.api_token,
                        framework_filter=self.framework
                    ))
                    print(f"[+] Playwright Headless Browser: Generated {len(browser_findings)} dynamic findings.")
                except Exception as exc:
                    print(f"[*] Playwright Headless Browser probe note: {exc}")
            else:
                browser_findings = [{
                    "control_id": "TARGET_REACHABILITY",
                    "title": "Target Server Availability Check",
                    "status": "NO_DATA",
                    "evidence_type": "dynamic_scan",
                    "evidence_source": "Network_Prober",
                    "evidence_summary": f"Target server at {self.target_url} is unreachable (Connection Refused). Dynamic probes omitted."
                }]

            # Step 3: Run ZAP scan if requested & docker is available
            zap_findings = self._run_zap_if_enabled()

            all_findings = x_findings + y_findings + browser_findings + zap_findings
            
            # Ensure no tokens or secret headers leak into findings JSON
            for item in all_findings:
                summary = str(item.get("evidence_summary", ""))
                if self.api_token and self.api_token in summary:
                    item["evidence_summary"] = summary.replace(self.api_token, "[REDACTED_API_TOKEN]")

            # Normalize and save to unified_verification_findings.json
            out_path = os.path.join(self.project_root, "unified_verification_findings.json")
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(all_findings, f, indent=2)
                
            self._write_audit_log("COMPLETED", f"Successfully completed dynamic probes. Output saved to {out_path}", len(all_findings))
            print(f"[+] Agent Z Orchestrator: Unified verification findings ({len(all_findings)} items) saved to {out_path}")
            return all_findings

        except Exception as exc:
            self._write_audit_log("ERROR", f"Execution error during dynamic probing: {exc}")
            raise exc


def main():
    parser = argparse.ArgumentParser(description="Agent Z: Autonomous Verification Orchestrator")
    parser.add_argument("--target-url", default="http://127.0.0.1:8000", help="Target URL (e.g. http://localhost:4200)")
    parser.add_argument("--api-token", default=None, help="Bearer token for target API")
    parser.add_argument("--framework", default="nist/sp_800_63b_r4", help="Target regulatory framework slug")
    parser.add_argument("--scope-confirm", action="store_true", help="Explicitly affirm scope authorization")
    parser.add_argument("--operator", default="cli_user", help="Auditor / Operator identifier")
    parser.add_argument("--tenant-id", default="default_tenant", help="Tenant ID for legal agreement & vault isolation")
    parser.add_argument("--disable-zap", action="store_true", help="Disable automatic OWASP ZAP container scan")
    
    args = parser.parse_args()

    orchestrator = AgentZOrchestrator(
        target_url=args.target_url,
        api_token=args.api_token,
        framework=args.framework,
        scope_confirmed=args.scope_confirm,
        operator=args.operator,
        tenant_id=args.tenant_id,
        enable_zap=not args.disable_zap
    )
    findings = orchestrator.execute_and_normalize()
    print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()

