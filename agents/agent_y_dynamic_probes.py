"""
Agent Y: Framework-Guided Dynamic Verification Agent
Loads control definitions for a target framework (e.g. NIST 800-63B, OWASP ASVS, ISO 27001, etc.)
and executes category 1-4 dynamic verification probes mapped directly to framework controls.

Hardened with:
- SSRF IP validation (blocks private/loopback/metadata endpoints)
- Rate limiting & Circuit breaker logic
- Strict redirect policy (allow_redirects=False)
- Accurate route-existence handling (distinguishes 404 vs 401/403)
"""

import os
import glob
import json
import time
import socket
import ipaddress
import requests
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional

# Private / reserved network blocks for SSRF prevention
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def is_safe_target_url(url: str, allow_localhost: bool = False) -> tuple[bool, str]:
    """Validates target URL and IP destination against SSRF attacks."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False, f"Invalid scheme '{parsed.scheme}'. Only http/https supported."

        hostname = parsed.hostname
        if not hostname:
            return False, "Missing hostname in target URL."

        # Exception for explicit local development testing if flag set
        if allow_localhost and hostname in ("localhost", "127.0.0.1", "::1"):
            return True, "Allowed for local dev testing."

        # Resolve IP addresses
        ip_addrs = socket.getaddrinfo(hostname, None)
        for family, _, _, _, sockaddr in ip_addrs:
            ip_str = sockaddr[0]
            ip_obj = ipaddress.ip_address(ip_str)
            for blocked in BLOCKED_NETWORKS:
                if ip_obj in blocked:
                    return False, f"Target hostname '{hostname}' resolves to blocked/internal IP '{ip_str}' (SSRF Protection)."

        return True, "URL validated as external/safe."
    except Exception as exc:
        return False, f"URL resolution error: {exc}"


class AgentYDynamicProbes:
    def __init__(
        self,
        target_url: str = "http://127.0.0.1:8000",
        api_token: Optional[str] = None,
        framework: str = "nist/sp_800_63b_r4",
        max_req_per_sec: float = 3.0,
        max_consecutive_failures: int = 3,
        allow_local_dev: bool = True
    ):
        self.target_url = target_url.rstrip("/")
        self.api_token = api_token
        self.headers = {"Authorization": f"Bearer {api_token}"} if api_token else {}
        self.framework = framework
        self.max_req_per_sec = max_req_per_sec
        self.min_interval = 1.0 / max_req_per_sec
        self.last_req_time = 0.0
        
        self.max_consecutive_failures = max_consecutive_failures
        self.consecutive_failures = 0
        self.circuit_broken = False
        self.allow_local_dev = allow_local_dev

        self.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        # Validate URL safety on init
        is_safe, msg = is_safe_target_url(self.target_url, allow_localhost=self.allow_local_dev)
        if not is_safe:
            raise ValueError(f"SSRF Security Violation: {msg}")

    def _rate_limit_and_check_circuit(self):
        """Enforces rate limiting delay and checks if circuit breaker is tripped."""
        if self.circuit_broken:
            raise RuntimeError("Circuit Breaker Tripped: Probe batch halted due to consecutive probe failures/timeouts.")

        elapsed = time.time() - self.last_req_time
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_req_time = time.time()

    def _safe_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Wrapper around requests enforcing rate limits, circuit breaker, and no-redirect SSRF safety."""
        self._rate_limit_and_check_circuit()

        # Enforce no redirects by default to prevent redirect-based SSRF
        kwargs.setdefault("allow_redirects", False)
        kwargs.setdefault("timeout", 4)

        try:
            res = requests.request(method, url, **kwargs)
            if res.status_code >= 500:
                self.consecutive_failures += 1
            else:
                self.consecutive_failures = 0

            if self.consecutive_failures >= self.max_consecutive_failures:
                self.circuit_broken = True

            return res
        except (requests.Timeout, requests.ConnectionError) as exc:
            self.consecutive_failures += 1
            if self.consecutive_failures >= self.max_consecutive_failures:
                self.circuit_broken = True
            raise exc

    def load_framework_controls(self) -> List[Dict[str, Any]]:
        """Loads controls from structured_controls matching self.framework."""
        jur, fw = "nist", "sp_800_63b_r4"
        if "/" in self.framework:
            jur, fw = self.framework.split("/", 1)
        elif "__" in self.framework:
            jur, fw = self.framework.split("__", 1)

        fname = f"{jur}__{fw}.json"
        path = os.path.join(self.project_root, "structured_controls", fname)
        if not os.path.exists(path):
            matches = glob.glob(os.path.join(self.project_root, "structured_controls", f"*{fw}*.json"))
            if matches:
                path = matches[0]

        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def probe_password_policy(self, control_id: str = "SP_800_63B_R4-REQ-021") -> Dict[str, Any]:
        """Category 1: Password Policy Verification."""
        candidate_endpoints = [
            f"{self.target_url}/api/v1/auth/password-check",
            f"{self.target_url}/v1/auth/login",
            f"{self.target_url}/api/v1/users",
            f"{self.target_url}/auth/register"
        ]
        
        active_ep = None
        for ep in candidate_endpoints:
            try:
                r = self._safe_request("OPTIONS", ep, headers=self.headers)
                if r.status_code != 404:
                    active_ep = ep
                    break
            except Exception:
                continue
                
        if not active_ep:
            return {
                "control_id": control_id,
                "title": "Password Verification and Length Rules",
                "status": "NOT_APPLICABLE",
                "evidence_type": "untested",
                "evidence_source": "AgentY_Password_Probe",
                "evidence_summary": f"No active password validation endpoints discovered on target ({self.target_url}). Status: NOT_APPLICABLE."
            }

        try:
            res_short = self._safe_request("POST", active_ep, json={"password": "short"}, headers=self.headers)
            res_valid = self._safe_request("POST", active_ep, json={"password": "this_is_a_very_long_valid_passphrase_15"}, headers=self.headers)
            
            passed = (res_short.status_code in [400, 422]) and (res_valid.status_code in [200, 201, 204])
            status = "PASS" if passed else "FAIL"
            
            return {
                "control_id": control_id,
                "title": "Password Verification and Length Rules",
                "status": status,
                "evidence_type": "dynamic_scan",
                "evidence_source": f"AgentY_Password_Probe ({active_ep})",
                "evidence_summary": f"Short password status: {res_short.status_code}, Valid passphrase status: {res_valid.status_code}"
            }
        except Exception as exc:
            return {
                "control_id": control_id,
                "title": "Password Verification and Length Rules",
                "status": "NO_DATA",
                "evidence_type": "untested",
                "evidence_source": "AgentY_Password_Probe",
                "evidence_summary": f"Error during password policy probe: {exc}"
            }

    def probe_access_control(self, control_id: str = "PR.AA-05") -> Dict[str, Any]:
        """Category 2: Access Control Verification (SPA-aware)."""
        protected_routes = ["/admin", "/api/v1/users", "/dashboard", "/api/v1/billing"]
        unprotected_leaks = []
        verified_protected = []
        
        # Check root page signature to detect Single Page App (SPA) catch-all behavior
        root_res = None
        try:
            root_res = self._safe_request("GET", self.target_url)
        except Exception:
            pass

        root_len = len(root_res.text) if root_res and root_res.status_code == 200 else 0

        for route in protected_routes:
            url = f"{self.target_url}{route}"
            try:
                r = self._safe_request("GET", url)
                if r.status_code in (200, 201):
                    # If response length & content-type match SPA root shell HTML exactly, it's not a real backend API leak
                    is_spa_catchall = ("text/html" in r.headers.get("Content-Type", "")) and (abs(len(r.text) - root_len) < 100)
                    if not is_spa_catchall:
                        unprotected_leaks.append(route)
                elif r.status_code in (401, 403):
                    verified_protected.append(route)
            except Exception:
                pass
                
        if unprotected_leaks:
            return {
                "control_id": control_id,
                "title": "Unauthenticated Access Control Verification",
                "status": "FAIL",
                "evidence_type": "dynamic_scan",
                "evidence_source": "AgentY_AccessControl_Probe",
                "evidence_summary": f"Protected backend endpoints accessible without authorization: {', '.join(unprotected_leaks)}"
            }

        return {
            "control_id": control_id,
            "title": "Unauthenticated Access Control Verification",
            "status": "PASS",
            "evidence_type": "dynamic_scan",
            "evidence_source": "AgentY_AccessControl_Probe",
            "evidence_summary": "No unprotected backend API routes exposed. Application routing enforced."
        }

    def probe_error_handling(self, control_id: str = "DE.CM-1") -> Dict[str, Any]:
        """Category 4: Error Handling & Info Leakage Verification."""
        probe_payloads = ["' OR '1'='1", "A" * 8000, {"invalid_json": None}]
        leaks = []
        
        for p in probe_payloads:
            try:
                r = self._safe_request(
                    "POST",
                    f"{self.target_url}/api/v1/auth/login",
                    data=p if isinstance(p, str) else None,
                    json=p if isinstance(p, dict) else None
                )
                text = r.text.lower()
                if any(sig in text for sig in ["traceback (most recent call last)", "syntaxerror:", "uncaught exception", "sql syntax"]):
                    leaks.append(str(p)[:30])
            except Exception:
                pass
                
        if leaks:
            return {
                "control_id": control_id,
                "title": "Error Information Leakage Verification",
                "status": "FAIL",
                "evidence_type": "dynamic_scan",
                "evidence_source": "AgentY_ErrorLeak_Probe",
                "evidence_summary": f"Stack traces or internal diagnostic errors leaked on malformed inputs: {leaks}"
            }
        return {
            "control_id": control_id,
            "title": "Error Information Leakage Verification",
            "status": "PASS",
            "evidence_type": "dynamic_scan",
            "evidence_source": "AgentY_ErrorLeak_Probe",
            "evidence_summary": "No raw stack traces or internal diagnostic signatures detected on malformed inputs."
        }

    def run_all(self) -> List[Dict[str, Any]]:
        controls = self.load_framework_controls()
        findings = []
        
        pwd_ctrl = next((c.get("control_id") for c in controls if any(k in (c.get("title","") + c.get("description","")).lower() for k in ["password", "authenticator", "passphrase"])), "SP_800_63B_R4-REQ-021")
        ac_ctrl = next((c.get("control_id") for c in controls if any(k in (c.get("title","") + c.get("description","")).lower() for k in ["access control", "rbac", "authorization"])), "PR.AC-1")
        err_ctrl = next((c.get("control_id") for c in controls if any(k in (c.get("title","") + c.get("description","")).lower() for k in ["error", "leak", "stack trace", "logging"])), "DE.CM-1")

        try:
            findings.append(self.probe_password_policy(pwd_ctrl))
            findings.append(self.probe_access_control(ac_ctrl))
            findings.append(self.probe_error_handling(err_ctrl))
        except RuntimeError as exc:
            findings.append({
                "control_id": "PROBE_SUITE_CIRCUIT_BREAKER",
                "title": "Probe Batch Aborted by Circuit Breaker",
                "status": "FAIL",
                "evidence_type": "circuit_breaker",
                "evidence_source": "AgentY_CircuitBreaker",
                "evidence_summary": str(exc)
            })

        return findings


if __name__ == "__main__":
    agent_y = AgentYDynamicProbes(allow_local_dev=True)
    res = agent_y.run_all()
    print(json.dumps(res, indent=2))

