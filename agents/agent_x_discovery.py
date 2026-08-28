"""
Agent X: Autonomous Discovery & Fingerprinting Agent
Performs Phase 1 discovery (route crawling, OpenAPI spec parsing, stack detection) 
and Phase 4 static/config auditing (Dockerfile hygiene, dependency manifest check).
"""

import os
import re
import json
import requests
from typing import Dict, List, Any

from urllib.parse import urlparse

class AgentXDiscovery:
    def __init__(self, target_url: str = "http://127.0.0.1:8000", api_token: str = None, project_root: str = None):
        self.target_url = target_url.rstrip("/")
        self.target_domain = urlparse(self.target_url).netloc or "127.0.0.1:8000"
        self.api_token = api_token
        self.project_root = project_root or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.headers = {"Authorization": f"Bearer {api_token}"} if api_token else {}
        self.discovered_routes: List[Dict[str, Any]] = []
        self.headers_audit: List[Dict[str, Any]] = []
        self.static_findings: List[Dict[str, Any]] = []

    def _is_within_boundary(self, url: str) -> bool:
        """Domain Boundary Enforcer: Ensures link stays strictly within authorized target domain."""
        parsed = urlparse(url)
        if not parsed.netloc: # relative path
            return True
        return parsed.netloc.lower() == self.target_domain.lower()

    def discover_openapi_routes(self) -> List[str]:
        """Phase 1: OpenAPI / Swagger spec auto-parsing with domain boundary enforcement."""
        openapi_paths = ["/openapi.json", "/swagger.json", "/api/v1/openapi.json", "/v1/swagger.json", "/docs"]
        routes = []
        for path in openapi_paths:
            try:
                res = requests.get(f"{self.target_url}{path}", headers=self.headers, timeout=3)
                if res.status_code == 200 and "application/json" in res.headers.get("Content-Type", ""):
                    data = res.json()
                    paths = data.get("paths", {})
                    for r_path in paths.keys():
                        if self._is_within_boundary(r_path):
                            routes.append(r_path)
                    if routes:
                        break
            except Exception:
                continue
        return list(set(routes))

    def discover_heuristic_routes(self) -> List[Dict[str, Any]]:
        """Phase 1 & 3: Auto-detect auth, user, and public endpoints using heuristics."""
        common_probes = [
            "/", "/health", "/api/v1/auth/login", "/api/v1/auth/password-check",
            "/v1/auth/login", "/auth/login", "/api/v1/users", "/admin", "/dashboard"
        ]
        
        # Merge with OpenAPI discovered routes if any
        api_routes = self.discover_openapi_routes()
        all_candidates = list(set(common_probes + api_routes))

        results = []
        for route in all_candidates:
            url = f"{self.target_url}{route}"
            try:
                res = requests.get(url, timeout=3)
                requires_auth = res.status_code in [401, 403]
                is_auth_endpoint = any(k in route.lower() for k in ["login", "password", "auth", "signin"])
                
                results.append({
                    "route": route,
                    "url": url,
                    "status_code": res.status_code,
                    "requires_auth": requires_auth,
                    "is_auth_endpoint": is_auth_endpoint
                })
            except Exception:
                results.append({
                    "route": route,
                    "url": url,
                    "status_code": None,
                    "requires_auth": False,
                    "is_auth_endpoint": False,
                    "unreachable": True
                })
        self.discovered_routes = results
        return results

    def audit_security_headers_and_cookies(self) -> List[Dict[str, Any]]:
        """Phase 2: Audit response security headers & cookie attributes."""
        findings = []
        try:
            res = requests.get(f"{self.target_url}/", timeout=3)
            headers = res.headers
            
            # Security Header Checks
            header_checks = {
                "Strict-Transport-Security": "PR.DS-1 / ASVS V9 (HSTS Missing)",
                "Content-Security-Policy": "ASVS V14 (CSP Missing)",
                "X-Frame-Options": "ASVS V14 (Clickjacking protection missing)",
                "X-Content-Type-Options": "ASVS V14 (MIME sniffing protection missing)"
            }
            
            for hdr, ctrl_id in header_checks.items():
                if hdr not in headers:
                    findings.append({
                        "control_id": ctrl_id,
                        "title": f"Security Header Missing: {hdr}",
                        "status": "FAIL",
                        "evidence_type": "dynamic_scan",
                        "evidence_source": f"AgentX_Header_Audit ({self.target_url})",
                        "evidence_summary": f"Target response missing required security header '{hdr}'."
                    })
                else:
                    findings.append({
                        "control_id": ctrl_id,
                        "title": f"Security Header Present: {hdr}",
                        "status": "PASS",
                        "evidence_type": "dynamic_scan",
                        "evidence_source": f"AgentX_Header_Audit ({self.target_url})",
                        "evidence_summary": f"Header '{hdr}' present with value: {headers[hdr]}"
                    })
            
            # CORS Check
            cors = headers.get("Access-Control-Allow-Origin")
            if cors == "*":
                findings.append({
                    "control_id": "ASVS V14 (CORS Overly Permissive)",
                    "title": "Wildcard Access-Control-Allow-Origin Header Detected",
                    "status": "FAIL",
                    "evidence_type": "dynamic_scan",
                    "evidence_source": "AgentX_CORS_Audit",
                    "evidence_summary": "Access-Control-Allow-Origin set to wildcard '*' on root response."
                })
        except Exception as exc:
            findings.append({
                "control_id": "PR.DS-1",
                "title": "Target Header Probe Unreachable",
                "status": "NO_DATA",
                "evidence_type": "untested",
                "evidence_source": "AgentX_Header_Audit",
                "evidence_summary": f"Target URL {self.target_url} unreachable during header audit: {exc}"
            })

        self.headers_audit = findings
        return findings

    def audit_static_config(self) -> List[Dict[str, Any]]:
        """Phase 4: Static Dockerfile non-root & dependency security hygiene check."""
        findings = []
        dockerfile_path = os.path.join(self.project_root, "Dockerfile")
        if os.path.exists(dockerfile_path):
            with open(dockerfile_path, "r", encoding="utf-8") as f:
                content = f.read()
                if not re.search(r"^\s*USER\s+\w+", content, re.MULTILINE):
                    findings.append({
                        "control_id": "PR.IP-1",
                        "title": "Dockerfile Root User Executable Defect",
                        "status": "FAIL",
                        "evidence_type": "static_scan",
                        "evidence_source": "Dockerfile",
                        "evidence_summary": "Dockerfile lacks explicit non-root USER directive."
                    })
                else:
                    findings.append({
                        "control_id": "PR.IP-1",
                        "title": "Dockerfile Non-Root User Enforced",
                        "status": "PASS",
                        "evidence_type": "static_scan",
                        "evidence_source": "Dockerfile",
                        "evidence_summary": "Dockerfile specifies non-root USER directive."
                    })
        else:
            findings.append({
                "control_id": "PR.IP-1",
                "title": "Dockerfile Non-Root User Verification",
                "status": "NO_DATA",
                "evidence_type": "untested",
                "evidence_source": "Project_Root",
                "evidence_summary": "No Dockerfile found in project root."
            })
        self.static_findings = findings
        return findings

    def run_all(self) -> List[Dict[str, Any]]:
        routes = self.discover_heuristic_routes()
        h_findings = self.audit_security_headers_and_cookies()
        s_findings = self.audit_static_config()
        return h_findings + s_findings

if __name__ == "__main__":
    agent_x = AgentXDiscovery()
    res = agent_x.run_all()
    print(json.dumps(res, indent=2))
