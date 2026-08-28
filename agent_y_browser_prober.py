"""
Agent Y Browser Prober: Headless Chromium Automation Engine
----------------------------------------------------------
Executes dynamic headless browser probing against target web applications
using a declarative framework-driven testing guide.

Supported action types:
  - navigate / navigate_path : URL navigation & redirect inspection
  - inspect_headers          : Security header presence/absence audit
  - inspect_cookies          : Cookie flag audit (Secure, HttpOnly, SameSite)
  - inspect_local_storage    : HTML5 LocalStorage sensitive data audit
  - inspect_session_storage  : HTML5 SessionStorage sensitive data audit
  - inspect_inputs           : DOM input field enumeration
  - inspect_password_fields  : Password masking & autocomplete audit
  - inspect_forms            : Form security audit (method, action, CSRF)
  - inspect_meta_tags        : HTML meta tag information leakage audit
  - inspect_cors             : CORS header permissiveness audit
  - check_console_errors     : Browser console error capture
  - check_robots_txt         : robots.txt sensitive path disclosure audit
  - check_security_txt       : RFC 9116 security.txt presence check
  - probe_error_page         : Error page stack trace leakage audit
"""

import os
import re
import json
import argparse
import asyncio
from urllib.parse import urljoin
from typing import List, Dict, Any, Optional

try:
    from playwright.async_api import async_playwright
except ImportError:
    async_playwright = None

DEFAULT_GUIDE_FILE = "framework_browser_testing_guide.json"
UNIFIED_FINDINGS_FILE = "unified_verification_findings.json"

# Sensitive patterns in robots.txt that indicate exposed admin/internal paths
ROBOTS_SENSITIVE_PATTERNS = [
    r"/admin", r"/backup", r"/api/internal", r"/debug",
    r"/phpmyadmin", r"/wp-admin", r"\.env", r"/config",
    r"/swagger", r"/graphql", r"/actuator"
]

# Stack trace / debug leakage patterns in error pages
ERROR_LEAKAGE_PATTERNS = [
    r"Traceback \(most recent call last\)",
    r"at\s+[\w\.]+\([\w\.]+:\d+\)",
    r"Exception in thread",
    r"stack trace",
    r"DEBUG\s*=\s*True",
    r"SQLSTATE\[",
    r"pg_connect\(",
    r"mysql_connect\(",
    r"ConnectionString",
    r"secret_key",
    r"\.py\", line \d+"
]


def _finding(control_id: str, status: str, summary: str, description: str, severity: str = "MEDIUM") -> Dict[str, Any]:
    """Helper to construct a normalized finding dict."""
    return {
        "control_id": control_id,
        "status": status,
        "severity": severity,
        "evidence_source": "Playwright_Headless_Browser",
        "evidence_type": "dynamic_scan",
        "evidence_summary": summary,
        "description": description
    }


def load_testing_guide(guide_path: str = DEFAULT_GUIDE_FILE) -> Dict[str, Any]:
    """Loads framework browser testing guide JSON."""
    if os.path.exists(guide_path):
        try:
            with open(guide_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            print(f"Warning: Failed to parse testing guide '{guide_path}': {exc}")
    return {}


async def _handle_navigate(page, step, target_url, findings):
    """Handle navigate / navigate_path actions."""
    path = step.get("path") or step.get("url", "/")
    full_url = urljoin(target_url, path)
    cid = step.get("control_id", "WSTG-INFO-01")
    sev = step.get("severity", "INFO")

    try:
        resp = await page.goto(full_url, wait_until="networkidle", timeout=10000)
        status = resp.status if resp else 0
        findings.append(_finding(
            cid, "PASS" if 200 <= status < 400 else "FAIL",
            f"Navigated to {full_url} -> HTTP {status}.",
            step.get("description", "Navigation probe executed."),
            sev
        ))
        return resp
    except Exception as exc:
        findings.append(_finding(cid, "SKIPPED", f"Navigation to {full_url} failed: {exc}", step.get("description", ""), sev))
        return None


async def _handle_inspect_headers(page, step, headers, target_url, findings):
    """Handle inspect_headers action: check presence/absence of security headers."""
    cid = step.get("control_id", "WSTG-CONF-07")
    sev = step.get("severity", "HIGH")
    fail_if_present = step.get("fail_if_present", False)
    headers_to_check = step.get("headers_to_check", [
        "strict-transport-security", "x-frame-options",
        "content-security-policy", "x-content-type-options",
        "referrer-policy", "permissions-policy"
    ])

    for hdr in headers_to_check:
        hdr_lower = hdr.lower()
        present = hdr_lower in headers

        if fail_if_present:
            # Technology disclosure headers (Server, X-Powered-By) — FAIL if present
            if present:
                findings.append(_finding(
                    cid, "FAIL",
                    f"Information disclosure: '{hdr}' header found with value '{headers[hdr_lower]}'.",
                    step.get("description", f"Header '{hdr}' leaks server technology information."),
                    sev
                ))
            else:
                findings.append(_finding(
                    cid, "PASS",
                    f"Header '{hdr}' not present (no technology disclosure).",
                    step.get("description", f"No information leakage via '{hdr}' header."),
                    sev
                ))
        else:
            # Security headers — FAIL if absent
            if not present:
                findings.append(_finding(
                    cid, "FAIL",
                    f"Security header '{hdr}' missing on {target_url}.",
                    step.get("description", f"Missing '{hdr}' header weakens application security posture."),
                    sev
                ))
            else:
                findings.append(_finding(
                    cid, "PASS",
                    f"Security header '{hdr}' present: {headers[hdr_lower]}",
                    step.get("description", f"Header '{hdr}' verified."),
                    sev
                ))


async def _handle_inspect_cookies(page, step, context, findings):
    """Handle inspect_cookies action: audit Secure, HttpOnly, SameSite flags."""
    cid = step.get("control_id", "ASVS-V3.4.1")
    sev = step.get("severity", "HIGH")
    cookies = await context.cookies()

    if not cookies:
        findings.append(_finding(cid, "NOT_APPLICABLE", "No cookies set by application.", step.get("description", ""), sev))
        return

    for cookie in cookies:
        name = cookie.get("name", "unknown")
        secure = cookie.get("secure", False)
        http_only = cookie.get("httpOnly", False)
        same_site = cookie.get("sameSite", "None")

        issues = []
        if not secure:
            issues.append("Missing Secure flag")
        if not http_only:
            issues.append("Missing HttpOnly flag")
        if same_site == "None":
            issues.append("SameSite=None (CSRF vulnerable)")

        if issues:
            findings.append(_finding(
                cid, "FAIL",
                f"Cookie '{name}': {', '.join(issues)}.",
                step.get("description", f"Cookie '{name}' lacks security flags."),
                sev
            ))
        else:
            findings.append(_finding(
                cid, "PASS",
                f"Cookie '{name}': Secure={secure}, HttpOnly={http_only}, SameSite={same_site}.",
                step.get("description", f"Cookie '{name}' security flags verified."),
                sev
            ))


async def _handle_inspect_storage(page, step, storage_type, findings):
    """Handle inspect_local_storage / inspect_session_storage actions."""
    cid = step.get("control_id", "WSTG-CLNT-11")
    sev = step.get("severity", "HIGH")
    api = "localStorage" if storage_type == "local" else "sessionStorage"

    sensitive_keys = await page.evaluate(f"""() => {{
        let found = [];
        try {{
            for (let i = 0; i < {api}.length; i++) {{
                let k = {api}.key(i);
                let lower = k.toLowerCase();
                if (lower.includes('token') || lower.includes('jwt') || lower.includes('auth') ||
                    lower.includes('session') || lower.includes('password') || lower.includes('secret') ||
                    lower.includes('api_key') || lower.includes('apikey') || lower.includes('credential')) {{
                    found.push(k);
                }}
            }}
        }} catch(e) {{}}
        return found;
    }}""")

    if sensitive_keys:
        findings.append(_finding(
            cid, "FAIL",
            f"Sensitive keys found in {api}: {sensitive_keys}",
            step.get("description", f"Unencrypted sensitive data detected in {api}."),
            sev
        ))
    else:
        findings.append(_finding(
            cid, "PASS",
            f"{api} clean. No sensitive keys detected.",
            step.get("description", f"Client-side {api} audited and verified."),
            sev
        ))


async def _handle_inspect_inputs(page, step, suite_control_id, findings):
    """Handle inspect_inputs action: enumerate DOM form inputs."""
    selector = step.get("selector", "input[type='text'], input:not([type]), textarea")
    cid = step.get("control_id", suite_control_id)
    sev = step.get("severity", "HIGH")

    elements = await page.query_selector_all(selector)
    findings.append(_finding(
        cid,
        "PASS" if elements else "NOT_APPLICABLE",
        f"Discovered {len(elements)} DOM input elements matching '{selector}'.",
        step.get("description", "Input field enumeration completed."),
        sev
    ))


async def _handle_inspect_password_fields(page, step, findings):
    """Handle inspect_password_fields action: check password masking & autocomplete."""
    selector = step.get("selector", "input[type='password']")
    cid = step.get("control_id", "ASVS-V2.1.1")
    sev = step.get("severity", "HIGH")

    pwd_fields = await page.query_selector_all(selector)
    if not pwd_fields:
        findings.append(_finding(cid, "NOT_APPLICABLE", "No password input fields found.", step.get("description", ""), sev))
        return

    for i, field in enumerate(pwd_fields):
        autocomplete = await field.get_attribute("autocomplete")
        if autocomplete and autocomplete.lower() not in ("off", "new-password", "current-password"):
            findings.append(_finding(
                cid, "FAIL",
                f"Password field #{i+1} has unsafe autocomplete='{autocomplete}'. Should be 'off' or 'new-password'.",
                step.get("description", "Password autocomplete attribute insecure."),
                sev
            ))
        else:
            findings.append(_finding(
                cid, "PASS",
                f"Password field #{i+1}: masking enabled, autocomplete='{autocomplete or 'default'}'.",
                step.get("description", "Password field security verified."),
                sev
            ))


async def _handle_inspect_forms(page, step, findings):
    """Handle inspect_forms action: audit form method, action URL, CSRF token presence."""
    selector = step.get("selector", "form")
    cid = step.get("control_id", "WSTG-ATHN-02")
    sev = step.get("severity", "HIGH")

    forms = await page.query_selector_all(selector)
    if not forms:
        findings.append(_finding(cid, "NOT_APPLICABLE", f"No forms matching '{selector}' found.", step.get("description", ""), sev))
        return

    for i, form in enumerate(forms):
        action = await form.get_attribute("action") or ""
        method = (await form.get_attribute("method") or "GET").upper()

        issues = []
        if method == "GET":
            issues.append("Uses GET method (credentials may appear in URL/logs)")
        if action.startswith("http://"):
            issues.append(f"Submits to insecure HTTP URL: {action}")

        # Check for CSRF token hidden input
        csrf_input = await form.query_selector("input[name*='csrf'], input[name*='token'], input[name*='_token']")
        if not csrf_input:
            issues.append("No CSRF token hidden input detected")

        if issues:
            findings.append(_finding(cid, "FAIL", f"Form #{i+1}: {'; '.join(issues)}.", step.get("description", ""), sev))
        else:
            findings.append(_finding(cid, "PASS", f"Form #{i+1}: method={method}, action='{action}', CSRF token present.", step.get("description", ""), sev))


async def _handle_inspect_meta_tags(page, step, findings):
    """Handle inspect_meta_tags action: check for framework/version disclosure."""
    cid = step.get("control_id", "WSTG-INFO-05")
    sev = step.get("severity", "LOW")

    generators = await page.evaluate("""() => {
        let results = [];
        document.querySelectorAll('meta[name="generator"], meta[name="framework"], meta[name="version"]').forEach(el => {
            results.push({name: el.getAttribute('name'), content: el.getAttribute('content')});
        });
        return results;
    }""")

    if generators:
        findings.append(_finding(
            cid, "FAIL",
            f"Framework/version disclosure via meta tags: {json.dumps(generators)}",
            step.get("description", "Meta tags expose technology stack information."),
            sev
        ))
    else:
        findings.append(_finding(cid, "PASS", "No generator/framework meta tags detected.", step.get("description", ""), sev))


async def _handle_inspect_cors(page, step, headers, findings):
    """Handle inspect_cors action: check for wildcard or overly permissive CORS."""
    cid = step.get("control_id", "WSTG-CONF-07")
    sev = step.get("severity", "HIGH")

    acao = headers.get("access-control-allow-origin", "")
    if acao == "*":
        findings.append(_finding(cid, "FAIL", "CORS wildcard (*) detected in Access-Control-Allow-Origin.", step.get("description", ""), sev))
    elif acao:
        findings.append(_finding(cid, "PASS", f"CORS origin restricted to: {acao}", step.get("description", ""), sev))
    else:
        findings.append(_finding(cid, "PASS", "No Access-Control-Allow-Origin header (CORS not enabled).", step.get("description", ""), sev))


async def _handle_check_console_errors(page, step, console_errors, findings):
    """Handle check_console_errors action."""
    cid = step.get("control_id", "WSTG-ERRH-01")
    sev = step.get("severity", "LOW")

    if console_errors:
        findings.append(_finding(
            cid, "FAIL",
            f"Captured {len(console_errors)} browser console error(s): {'; '.join(console_errors[:5])}",
            step.get("description", "Client-side JavaScript errors detected."),
            sev
        ))
    else:
        findings.append(_finding(cid, "PASS", "No browser console errors detected.", step.get("description", ""), sev))


async def _handle_check_robots_txt(page, step, target_url, findings):
    """Handle check_robots_txt action: check for sensitive path disclosure."""
    cid = step.get("control_id", "WSTG-INFO-07")
    sev = step.get("severity", "LOW")
    robots_url = urljoin(target_url, "/robots.txt")

    try:
        resp = await page.goto(robots_url, wait_until="domcontentloaded", timeout=8000)
        if resp and resp.status == 200:
            body = await page.content()
            disclosed = [p for p in ROBOTS_SENSITIVE_PATTERNS if re.search(p, body, re.IGNORECASE)]
            if disclosed:
                findings.append(_finding(cid, "FAIL", f"robots.txt discloses sensitive paths: {disclosed}", step.get("description", ""), sev))
            else:
                findings.append(_finding(cid, "PASS", "robots.txt present but no sensitive paths disclosed.", step.get("description", ""), sev))
        else:
            findings.append(_finding(cid, "PASS", f"robots.txt returned HTTP {resp.status if resp else 'N/A'} (not found/accessible).", step.get("description", ""), sev))
    except Exception:
        findings.append(_finding(cid, "PASS", "robots.txt not accessible.", step.get("description", ""), sev))


async def _handle_check_security_txt(page, step, target_url, findings):
    """Handle check_security_txt action: RFC 9116 compliance."""
    cid = step.get("control_id", "WSTG-INFO-09")
    sev = step.get("severity", "INFO")
    sec_url = urljoin(target_url, "/.well-known/security.txt")

    try:
        resp = await page.goto(sec_url, wait_until="domcontentloaded", timeout=8000)
        if resp and resp.status == 200:
            findings.append(_finding(cid, "PASS", f"security.txt found at {sec_url} (RFC 9116 compliant).", step.get("description", ""), sev))
        else:
            findings.append(_finding(cid, "FAIL", f"security.txt not found at {sec_url}. Consider adding a vulnerability disclosure policy.", step.get("description", ""), sev))
    except Exception:
        findings.append(_finding(cid, "FAIL", "security.txt not accessible.", step.get("description", ""), sev))


async def _handle_probe_error_page(page, step, target_url, findings):
    """Handle probe_error_page action: check for stack trace / debug info leakage."""
    path = step.get("path", "/nonexistent_404_probe")
    cid = step.get("control_id", "WSTG-ERRH-01")
    sev = step.get("severity", "MEDIUM")
    full_url = urljoin(target_url, path)

    try:
        resp = await page.goto(full_url, wait_until="domcontentloaded", timeout=8000)
        body = await page.content()
        leaks = [p for p in ERROR_LEAKAGE_PATTERNS if re.search(p, body, re.IGNORECASE)]

        if leaks:
            findings.append(_finding(
                cid, "FAIL",
                f"Error page at {full_url} leaks debug information. Patterns detected: {leaks[:3]}",
                step.get("description", "Error page exposes server internals."),
                sev
            ))
        else:
            status = resp.status if resp else 0
            findings.append(_finding(
                cid, "PASS",
                f"Error page at {full_url} returned HTTP {status} with no debug leakage.",
                step.get("description", "Error handling verified."),
                sev
            ))
    except Exception as exc:
        findings.append(_finding(cid, "SKIPPED", f"Error page probe at {full_url} failed: {exc}", step.get("description", ""), sev))


def probe_url_with_http_fallback(
    target_url: str,
    auth_token: Optional[str] = None,
    guide: Optional[Dict[str, Any]] = None,
    framework_filter: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Resilient HTTP dynamic fallback scanner for CI and lightweight environments without full browser binaries."""
    import urllib.request
    import urllib.error
    import ssl

    findings = []
    headers = {"User-Agent": "Mozilla/5.0 (ComplianceMesh Dynamic HTTP Fallback Prober)"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # 1. Probe Security Headers
    req = urllib.request.Request(target_url, headers=headers)
    resp_headers = {}
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            for k, v in response.headers.items():
                resp_headers[k.lower()] = v
    except urllib.error.HTTPError as exc:
        for k, v in exc.headers.items():
            resp_headers[k.lower()] = v
    except Exception as exc:
        findings.append(_finding(
            "WSTG-INFO-02", "SKIPPED",
            f"HTTP connection probe failed: {exc}",
            "Fallback scanner could not establish connection to target."
        ))
        return findings

    sec_headers = [
        ("strict-transport-security", "WSTG-CONF-07", "HIGH"),
        ("x-frame-options", "WSTG-CLNT-09", "MEDIUM"),
        ("content-security-policy", "WSTG-CONF-07", "HIGH"),
        ("x-content-type-options", "WSTG-CONF-07", "LOW"),
        ("permissions-policy", "WSTG-CONF-07", "LOW")
    ]

    for hdr, cid, sev in sec_headers:
        if hdr in resp_headers:
            findings.append(_finding(cid, "PASS", f"Security header '{hdr}' present: {resp_headers[hdr]}", f"Header '{hdr}' verified.", sev))
        else:
            findings.append(_finding(cid, "FAIL", f"Security header '{hdr}' missing on {target_url}.", f"Missing '{hdr}' header weakens security posture.", sev))

    # Technology leakage check
    for tech_hdr in ["server", "x-powered-by"]:
        if tech_hdr in resp_headers:
            findings.append(_finding("WSTG-INFO-02", "FAIL", f"Information disclosure: '{tech_hdr}' header found with value '{resp_headers[tech_hdr]}'.", "Leaking server stack.", "LOW"))
        else:
            findings.append(_finding("WSTG-INFO-02", "PASS", f"Header '{tech_hdr}' not present.", "No stack leakage.", "LOW"))

    # 2. Probe robots.txt
    robots_url = urljoin(target_url, "/robots.txt")
    try:
        r_req = urllib.request.Request(robots_url, headers=headers)
        with urllib.request.urlopen(r_req, context=ctx, timeout=5) as r_resp:
            content = r_resp.read().decode("utf-8", errors="ignore")
            exposed = []
            for line in content.splitlines():
                if any(re.search(pat, line, re.IGNORECASE) for pat in ROBOTS_SENSITIVE_PATTERNS):
                    exposed.append(line.strip())
            if exposed:
                findings.append(_finding("WSTG-INFO-03", "FAIL", f"Sensitive paths in robots.txt: {', '.join(exposed[:3])}", "Internal paths disclosed.", "MEDIUM"))
            else:
                findings.append(_finding("WSTG-INFO-03", "PASS", f"robots.txt present without sensitive disclosures.", "robots.txt verified.", "LOW"))
    except Exception:
        findings.append(_finding("WSTG-INFO-03", "PASS", "No robots.txt found or inaccessible (no sensitive path leakage).", "Robots scan complete.", "LOW"))

    print(f"\n   ✅ Fallback HTTP probe complete: {len(findings)} finding(s) generated.")
    return findings


# ── Main Orchestrator ──────────────────────────────────────────────────────────

async def probe_url_with_browser(
    target_url: str,
    auth_token: str = None,
    headless: bool = True,
    guide_path: str = DEFAULT_GUIDE_FILE,
    framework_filter: str = None,
    suite_timeout_sec: int = 60,
    force_http_fallback: bool = False
) -> List[Dict[str, Any]]:
    """Runs Playwright Chromium browser probing against target_url using framework testing guide."""
    guide = load_testing_guide(guide_path)
    findings = []

    if async_playwright is None or force_http_fallback:
        print("🌐 [Browser Prober] Playwright engine unavailable or HTTP fallback forced. Using Dynamic HTTP Prober.")
        return probe_url_with_http_fallback(target_url, auth_token, guide, framework_filter)

    print(f"🌐 [Browser Prober] Launching Chromium against target: {target_url}")
    print(f"   Guide: '{guide.get('title', 'Default Built-in')}' v{guide.get('version', '1.0')}")
    if framework_filter:
        print(f"   🎯 Framework Filter Active: Only running suites matching '{framework_filter}'")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless)

        extra_headers = {}
        if auth_token:
            extra_headers["Authorization"] = f"Bearer {auth_token}"

        context = await browser.new_context(
            extra_http_headers=extra_headers,
            user_agent="Mozilla/5.0 (ComplianceMesh Dynamic Security Prober)"
        )

        page = await context.new_page()

        console_errors = []
        page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)

        try:
            # Initial navigation to capture base response headers
            response = await page.goto(target_url, wait_until="networkidle", timeout=15000)
            base_headers = response.headers if response else {}

            # Load test suites from guide or use default
            test_suites = guide.get("test_suites", [])
            if framework_filter:
                filter_term = framework_filter.lower().replace("-", "").replace("_", "")
                test_suites = [
                    s for s in test_suites
                    if filter_term in s.get("framework", "").lower().replace("-", "").replace("_", "")
                    or filter_term in s.get("suite_id", "").lower().replace("-", "").replace("_", "")
                ]

            if not test_suites:
                test_suites = [{
                    "suite_id": "DEFAULT",
                    "steps": [
                        {"action": "inspect_headers"},
                        {"action": "inspect_cookies"},
                        {"action": "inspect_local_storage"},
                        {"action": "inspect_inputs"}
                    ]
                }]

            total_steps = sum(len(s.get("steps", [])) for s in test_suites)
            step_counter = 0

            for suite in test_suites:
                suite_id = suite.get("suite_id", "UNKNOWN")
                suite_cid = suite.get("control_id", "WSTG-GEN-01")
                category = suite.get("category", suite.get("name", ""))
                print(f"\n   ┌─ Suite: {suite_id} | {category}")

                suite_start_time = asyncio.get_event_loop().time()

                for step in suite.get("steps", []):
                    # Enforce per-suite timeout kill-switch
                    if asyncio.get_event_loop().time() - suite_start_time > suite_timeout_sec:
                        print(f"   │  ⏱️  Suite timeout ({suite_timeout_sec}s) reached — moving to next suite.")
                        findings.append(_finding(
                            suite_cid, "SKIPPED",
                            f"Suite '{suite_id}' timed out after {suite_timeout_sec}s.",
                            "Execution timeout enforced for sandbox safety."
                        ))
                        break

                    step_counter += 1
                    action = step.get("action", "")
                    step_id = step.get("step_id", f"STEP-{step_counter}")
                    print(f"   │  [{step_counter}/{total_steps}] {step_id}: {action}")

                    # Dispatch to handler
                    if action in ("navigate", "navigate_path"):
                        resp = await _handle_navigate(page, step, target_url, findings)
                        if resp:
                            base_headers = resp.headers

                    elif action == "inspect_headers":
                        await _handle_inspect_headers(page, step, base_headers, target_url, findings)

                    elif action == "inspect_cookies":
                        await _handle_inspect_cookies(page, step, context, findings)

                    elif action == "inspect_local_storage":
                        await _handle_inspect_storage(page, step, "local", findings)

                    elif action == "inspect_session_storage":
                        await _handle_inspect_storage(page, step, "session", findings)

                    elif action == "inspect_inputs":
                        await _handle_inspect_inputs(page, step, suite_cid, findings)

                    elif action == "inspect_password_fields":
                        await _handle_inspect_password_fields(page, step, findings)

                    elif action == "inspect_forms":
                        await _handle_inspect_forms(page, step, findings)

                    elif action == "inspect_meta_tags":
                        await _handle_inspect_meta_tags(page, step, findings)

                    elif action == "inspect_cors":
                        await _handle_inspect_cors(page, step, base_headers, findings)

                    elif action == "check_console_errors":
                        await _handle_check_console_errors(page, step, console_errors, findings)

                    elif action == "check_robots_txt":
                        await _handle_check_robots_txt(page, step, target_url, findings)

                    elif action == "check_security_txt":
                        await _handle_check_security_txt(page, step, target_url, findings)

                    elif action == "probe_error_page":
                        await _handle_probe_error_page(page, step, target_url, findings)

                    else:
                        print(f"   │  ⚠️  Unknown action type: '{action}' — skipped")

                print(f"   └─ Suite {suite_id} complete.")

        except Exception as exc:
            print(f"\n   ⚠️  Browser probe exception: {exc}")
            findings.append(_finding(
                "WSTG-INFO-02", "SKIPPED",
                f"Browser probe exception: {exc}",
                "Headless browser probe completed with exception."
            ))
        finally:
            await browser.close()

    print(f"\n   ✅ Probe complete: {len(findings)} finding(s) generated.")
    return findings


def update_unified_findings(new_findings: List[Dict[str, Any]], output_file: str = UNIFIED_FINDINGS_FILE):
    """Merges browser probing findings into unified_verification_findings.json."""
    existing = []
    if os.path.exists(output_file):
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            existing = []

    existing_clean = [f for f in existing if f.get("evidence_source") != "Playwright_Headless_Browser"]
    merged = existing_clean + new_findings

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2)
    print(f"Updated {output_file} with {len(new_findings)} browser probing finding(s).")


def main():
    parser = argparse.ArgumentParser(description="Agent Y: Headless Playwright Chromium Browser Prober")
    parser.add_argument("--url", required=True, help="Target URL (e.g. http://localhost:8501)")
    parser.add_argument("--token", help="Bearer API token or auth secret")
    parser.add_argument("--framework", help="Filter test suites by framework name (e.g. WSTG, ASVS, NIST)")
    parser.add_argument("--guide", default=DEFAULT_GUIDE_FILE, help="Path to declarative framework testing guide JSON")
    parser.add_argument("--headed", action="store_true", help="Run browser in headed (visible) mode instead of headless")
    args = parser.parse_args()

    findings = asyncio.run(probe_url_with_browser(
        args.url,
        args.token,
        headless=not args.headed,
        guide_path=args.guide,
        framework_filter=args.framework
    ))
    update_unified_findings(findings)


if __name__ == "__main__":
    main()
