"""
Agent 1b — Dedicated Code / Repo Ingestion Agent (Mode B)
---------------------------------------------------------
Purpose:
  Real-time, automated, and framework-agnostic source code ingestion agent.
  Reads client code repositories, performs static security/pattern extraction,
  and operates in both single-pass scan mode and real-time continuous watch mode.

Key Features:
  1. Framework-Agnostic: Works across any tech stack (Python, JS/TS, Java, Go, Rust, Docker, CI/CD)
     without requiring hardcoded compliance framework parameters.
  2. Real-Time & Automated: Includes a continuous `--watch` mode that automatically re-scans
     files on modification/creation in real time.
  3. Non-Blocking & Static: Operates 100% statically with fast local regex pattern matching
     and optional lightweight LLM interpretation (cached/graceful fallback).

CLI Usage:
  Single-Pass Automated Scan:
      python agents/agent1b_code_ingestion.py --repo-path /path/to/client/repo --engagement-id fleetbase_2026_q3

  Continuous Real-Time Watcher:
      python agents/agent1b_code_ingestion.py --repo-path /path/to/client/repo --engagement-id fleetbase_2026_q3 --watch
"""

import os
import sys
import re
import json
import glob
import time
import argparse
import subprocess
from typing import Dict, List, Any, Optional

AGENTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(AGENTS_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

LOG_DIR = os.path.join(PROJECT_ROOT, "logs")
AUDIT_LOG_FILE = os.path.join(LOG_DIR, "live_verification_audit.log")

try:
    import agents.config as config
except ImportError:
    import config

os.makedirs(LOG_DIR, exist_ok=True)


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


# ---------------------------------------------------------------------------
# 1. Repo Structure Scan (Framework Agnostic)
# ---------------------------------------------------------------------------
def scan_repo_structure(repo_path: str) -> Dict[str, Any]:
    """
    Walks repo_path and detects language stack, manifests, Dockerfile, CI files,
    .env.example, and entry points. Returns structured repo profile dictionary.
    """
    manifest_files = []
    has_dockerfile = False
    has_ci = False
    has_env_example = False
    entry_points = []
    languages = set()
    framework_guesses = set()

    for root, dirs, files in os.walk(repo_path):
        rel_root = os.path.relpath(root, repo_path)
        for f in files:
            lower_f = f.lower()
            rel_file_path = os.path.normpath(os.path.join(rel_root, f)) if rel_root != "." else f

            if lower_f in ["requirements.txt", "pyproject.toml", "setup.py"]:
                manifest_files.append(rel_file_path)
                languages.add("python")
            elif lower_f in ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"]:
                manifest_files.append(rel_file_path)
                languages.add("node/javascript")
            elif lower_f in ["pom.xml", "build.gradle", "build.gradle.kts"]:
                manifest_files.append(rel_file_path)
                languages.add("java")
            elif lower_f in ["go.mod", "go.sum"]:
                manifest_files.append(rel_file_path)
                languages.add("go")
            elif lower_f in ["cargo.toml", "cargo.lock"]:
                manifest_files.append(rel_file_path)
                languages.add("rust")

            if lower_f == "dockerfile" or lower_f.startswith("dockerfile."):
                has_dockerfile = True
            if lower_f in ["docker-compose.yml", "docker-compose.yaml"]:
                has_dockerfile = True

            if ".github" in rel_root or ".gitlab-ci.yml" in lower_f or ".circleci" in rel_root:
                has_ci = True

            if lower_f in [".env.example", ".env.sample", ".env.template"]:
                has_env_example = True

            if lower_f in ["app.py", "main.py", "server.js", "index.js", "main.go", "manage.py"]:
                entry_points.append(rel_file_path)

            if lower_f == "requirements.txt" or lower_f == "pyproject.toml":
                try:
                    with open(os.path.join(root, f), "r", encoding="utf-8", errors="ignore") as mf:
                        content = mf.read().lower()
                        for fw in ["django", "flask", "fastapi", "tornado", "pyramid"]:
                            if fw in content:
                                framework_guesses.add(fw.capitalize())
                except Exception:
                    pass
            elif lower_f == "package.json":
                try:
                    with open(os.path.join(root, f), "r", encoding="utf-8", errors="ignore") as mf:
                        content = mf.read().lower()
                        for fw in ["express", "next", "react", "vue", "angular", "nestjs"]:
                            if fw in content:
                                framework_guesses.add(fw.capitalize())
                except Exception:
                    pass

    return {
        "repo_path": repo_path,
        "languages": sorted(list(languages)),
        "framework_guess": sorted(list(framework_guesses)),
        "has_dockerfile": has_dockerfile,
        "has_ci": has_ci,
        "has_env_example": has_env_example,
        "entry_points": entry_points,
        "manifest_files": manifest_files
    }


# ---------------------------------------------------------------------------
# 2. Framework-Agnostic Static Security Scan Integration
# ---------------------------------------------------------------------------
def run_static_tool_scans(repo_path: str) -> List[Dict[str, Any]]:
    """
    Executes static analysis tools (gitleaks, trivy/audit, hadolint) if available.
    Falls back to high-speed native Python static analyzers if tools are missing.
    """
    findings = []

    # 2a. Gitleaks scan for secrets
    if subprocess.run(["which", "gitleaks"], capture_output=True).returncode == 0:
        try:
            report_file = os.path.join(PROJECT_ROOT, "gitleaks_report.json")
            cmd = ["gitleaks", "detect", "--source", repo_path, "--report-format", "json", "--report-path", report_file]
            subprocess.run(cmd, capture_output=True, text=True, check=False)
            if os.path.exists(report_file):
                with open(report_file, "r", encoding="utf-8", errors="ignore") as f:
                    gleaks_data = json.load(f)
                for idx, item in enumerate(gleaks_data):
                    findings.append({
                        "finding_id": f"gitleaks-{idx+1}",
                        "cwe_id": "CWE-798",
                        "severity": "HIGH",
                        "file_path": item.get("File", "unknown"),
                        "line": item.get("StartLine", 0),
                        "description": f"Exposed secret: {item.get('Description', 'Hardcoded secret detected')}"
                    })
        except Exception as exc:
            print(f"[gitleaks] Warning: {exc}")
    else:
        # High-speed native regex fallback for secret exposure
        secret_patterns = {
            "AWS Secret Key": r"(?i)aws_(?:secret|access)_key(?:_id)?\s*=\s*['\"][A-Za-z0-9/+=]{16,}['\"]",
            "Generic Hardcoded Token": r"(?i)(?:secret|token|password|api_key)\s*=\s*['\"][A-Za-z0-9._-]{12,}['\"]",
            "Private Key Header": r"-----BEGIN (?:RSA|OPENSSH|PRIVATE) KEY-----",
            "Database Credentials": r"(?i)postgres(?:ql)?://[^:]+:[^@]+@",
        }
        ignored_secret_dirs = {"tests", "test", "mocks", "mock", "fixtures", "node_modules", "vendor", "dist", "build", ".git"}
        for root, _, files in os.walk(repo_path):
            for fname in files:
                if fname.endswith((".py", ".js", ".ts", ".json", ".env", ".yaml", ".yml", ".sh", ".php")):
                    fpath = os.path.join(root, fname)
                    rel_path = os.path.relpath(fpath, repo_path)
                    
                    parts = set(p.lower() for p in rel_path.split(os.sep))
                    if parts.intersection(ignored_secret_dirs) or fname.lower() in (".env.example", ".env.sample", ".env.template"):
                        continue
                        
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            lines = f.readlines()
                            for l_idx, line in enumerate(lines):
                                for p_name, p_regex in secret_patterns.items():
                                    if re.search(p_regex, line) and not any(dummy in line.lower() for dummy in ["example", "changeme", "placeholder", "your_", "test_"]):
                                        findings.append({
                                            "finding_id": f"secret-regex-{len(findings)+1}",
                                            "cwe_id": "CWE-798",
                                            "severity": "HIGH",
                                            "file_path": rel_path,
                                            "line": l_idx + 1,
                                            "description": f"{p_name} detected in source code line"
                                        })
                    except Exception:
                        pass

    # 2b. Trivy or package audit for CVEs
    if subprocess.run(["which", "trivy"], capture_output=True).returncode == 0:
        try:
            trivy_out = os.path.join(PROJECT_ROOT, "trivy_report.json")
            cmd = ["trivy", "fs", "--format", "json", "-o", trivy_out, repo_path]
            subprocess.run(cmd, capture_output=True, text=True, check=False)
            if os.path.exists(trivy_out):
                with open(trivy_out, "r", encoding="utf-8", errors="ignore") as f:
                    trivy_data = json.load(f)
                results = trivy_data.get("Results", [])
                for res in results:
                    target_file = res.get("Target", "unknown")
                    vulns = res.get("Vulnerabilities", [])
                    for v in vulns:
                        cwes = v.get("CweIDs", ["CWE-1395"])
                        findings.append({
                            "finding_id": v.get("VulnerabilityID", "trivy-cve"),
                            "cwe_id": cwes[0] if cwes else "CWE-1395",
                            "severity": v.get("Severity", "MEDIUM"),
                            "file_path": target_file,
                            "line": 0,
                            "description": f"Package {v.get('PkgName')}@{v.get('InstalledVersion')}: {v.get('Title', 'Known CVE vulnerability')}"
                        })
        except Exception as exc:
            print(f"[trivy] Warning: {exc}")

    # 2c. Hadolint Dockerfile scan
    dockerfiles = glob.glob(os.path.join(repo_path, "Dockerfile*")) + glob.glob(os.path.join(repo_path, "**/Dockerfile*"), recursive=True)
    if dockerfiles and subprocess.run(["which", "hadolint"], capture_output=True).returncode == 0:
        for df in dockerfiles:
            try:
                cmd = ["hadolint", df, "-f", "json"]
                res = subprocess.run(cmd, capture_output=True, text=True, check=False)
                if res.stdout:
                    hl_data = json.loads(res.stdout)
                    rel_df = os.path.relpath(df, repo_path)
                    for item in hl_data:
                        findings.append({
                            "finding_id": f"hadolint-{item.get('code')}",
                            "cwe_id": "CWE-1188",
                            "severity": item.get("level", "style").upper(),
                            "file_path": rel_df,
                            "line": item.get("line", 1),
                            "description": f"[{item.get('code')}] {item.get('message')}"
                        })
            except Exception as exc:
                print(f"[hadolint] Warning: {exc}")

    return findings


# ---------------------------------------------------------------------------
# 3. Universal Security Pattern Extraction
# ---------------------------------------------------------------------------
def extract_config_patterns(repo_path: str) -> List[Dict[str, Any]]:
    """
    Searches source files for universal security policy patterns across any framework/language.
    """
    patterns = {
        "auth_rbac_permissions": {
            "regex": r"(?i)(hasPermission|checkPermission|is_admin|['\"]roles?['\"]\s*[:=]|['\"]permissions?['\"]\s*[:=]|->can\(|->authorize|->hasRole|\$user->role|middleware\(['\"]auth|middleware\(['\"]role|auth\(\)->user|\.hasRole\(|\.can\(|roles\s*=\s*\[|permissions\s*=\s*\[|role_required|permission_required)",
            "cwe": "CWE-285",
            "desc": "Role-based access control (RBAC) and authorization enforcement"
        },
        "token_jwt_auth": {
            "regex": r"(?i)(jwt|bearer|passport|sanctum|createToken|authenticate|bcrypt|argon2|password_hash|auth::attempt|hash::check)",
            "cwe": "CWE-287",
            "desc": "Cryptographic authentication token and credential verification"
        },
        "password_validation": {
            "regex": r"(?i)(password|passwd).*(min_length|length|regex|validate|complexity|min:\d+)",
            "cwe": "CWE-521",
            "desc": "Password validation / length verification logic"
        },
        "cors_configuration": {
            "regex": r"(?i)(cors|access-control-allow-origin)\s*[:=]\s*['\"]?(\*|true|allow)",
            "cwe": "CWE-942",
            "desc": "CORS cross-origin access configuration"
        },
        "tls_https_enforcement": {
            "regex": r"(?i)(ssl_redirect|force_ssl|https_only|secure_ssl|tls_version|strict-transport-security)",
            "cwe": "CWE-319",
            "desc": "TLS / HTTPS transport security configuration"
        },
        "session_cookie_flags": {
            "regex": r"(?i)(httponly|secure|samesite|session_cookie|cookie_flags)",
            "cwe": "CWE-614",
            "desc": "Session cookie security flags (Secure, HttpOnly, SameSite)"
        },
        "input_sanitization": {
            "regex": r"(?i)(Validator::make|validate\(|validator|sanitiz|strip_tags|htmlspecialchars|DOMPurify|escapeHtml|checkInput|sanitizeInput|cleanHtml)",
            "cwe": "CWE-79",
            "desc": "Input data validation and sanitization safeguards"
        },
        "rate_limiting": {
            "regex": r"(?i)(throttle|rateLimiter|rate_limit|maxAttempts|limiter|slowDown|tooManyAttempts)",
            "cwe": "CWE-770",
            "desc": "API rate limiting and request throttling protection"
        },
        "audit_logging": {
            "regex": r"(?i)(activity_log|Log::info|Log::warning|Log::error|logger\(|audit_trail|logAction|recordAudit)",
            "cwe": "CWE-778",
            "desc": "Security event logging and operational audit trails"
        },
        "data_encryption": {
            "regex": r"(?i)(Crypt::encrypt|Crypt::decrypt|AES-256|openssl_encrypt|crypto\.createCipher|encryptString)",
            "cwe": "CWE-311",
            "desc": "Cryptographic encryption of sensitive data"
        },
        "debug_enabled": {
            "regex": r"(?i)(DEBUG\s*=\s*True|development\s*=\s*true|env\s*=\s*['\"]dev)",
            "cwe": "CWE-215",
            "desc": "Debug mode or verbose logging enabled"
        },
        "hardcoded_ip_url": {
            "regex": r"https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?",
            "cwe": "CWE-1188",
            "desc": "Hardcoded IP address / static URL endpoint"
        }
    }

    ignored_dir_fragments = {"translations", "locales", "locale", "i18n", "lang", "node_modules", "vendor", ".git", "dist", "build", "coverage", ".next", ".nuxt", "__pycache__"}
    ignored_filenames = {"license", "license.md", "license.txt", "code_of_conduct.md", "code_of_conduct", "pull_request_template.md", "contributing.md", "release.md", "changelog.md", "pnpm-lock.yaml", "package-lock.json", "yarn.lock", "composer.lock", "cargo.lock", "poetry.lock", "gemfile.lock"}

    candidate_snippets = []
    for root, _, files in os.walk(repo_path):
        for f in files:
            f_lower = f.lower()
            if f_lower in ignored_filenames or ("template" in f_lower and f_lower.endswith(".md")):
                continue

            if f.endswith((".py", ".js", ".ts", ".php", ".java", ".go", ".json", ".yml", ".yaml", ".env", ".config")):
                fpath = os.path.join(root, f)
                rel_path = os.path.relpath(fpath, repo_path)
                
                # Exclude UI translations, third-party packages, and build artifacts
                parts = set(p.lower() for p in rel_path.split(os.sep))
                if parts.intersection(ignored_dir_fragments):
                    continue
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as file_obj:
                        lines = file_obj.readlines()
                        for line_idx, line_str in enumerate(lines):
                            for pat_key, pat_info in patterns.items():
                                if re.search(pat_info["regex"], line_str):
                                    snippet = line_str.strip()[:150]
                                    candidate_snippets.append({
                                        "pattern_type": pat_key,
                                        "cwe_id": pat_info["cwe"],
                                        "file_path": rel_path,
                                        "line": line_idx + 1,
                                        "snippet": snippet,
                                        "description": pat_info["desc"],
                                        "confidence": "candidate_evidence"
                                    })
                except Exception:
                    pass

    return candidate_snippets


# ---------------------------------------------------------------------------
# 4. Fast Review & Output Store (Unified Output)
# ---------------------------------------------------------------------------
def process_and_store_findings(engagement_id: str, tool_findings: List[Dict[str, Any]], candidate_snippets: List[Dict[str, Any]], repo_profile: Dict[str, Any]):
    """
    Stores code ingestion findings in structured stores tagged as:
      - evidence_type: 'static_code_scan' (deterministic tool/regex output)
      - evidence_type: 'static_code_review' (candidate policy snippet)
    """
    profile_out = os.path.join(PROJECT_ROOT, f"repo_profile_{engagement_id}.json")
    with open(profile_out, "w", encoding="utf-8") as f:
        json.dump(repo_profile, f, indent=2)

    # 4a. Update ChromaDB vector store
    try:
        embedder = config.get_embedder()
        import chromadb
        client = chromadb.PersistentClient(path=config.CHROMA_DB_DIR)
        collection = client.get_or_create_collection("controls")

        ids = []
        documents = []
        metadatas = []

        # Tool findings
        for idx, tf in enumerate(tool_findings):
            cid = f"code_scan_{engagement_id}_{idx+1}"
            doc_text = f"Static Tool Finding ({tf.get('finding_id')}): {tf.get('description')} in {tf.get('file_path')}:{tf.get('line')}"
            ids.append(cid)
            documents.append(doc_text)
            metadatas.append({
                "control_id": tf.get("cwe_id", "CWE-unmapped"),
                "title": f"Static Tool Finding {tf.get('finding_id')}",
                "jurisdiction": "code_analysis",
                "framework": "static_security_scan",
                "source_file": tf.get("file_path", "unknown"),
                "evidence_type": "static_code_scan",
                "verified": "false",
                "engagement_id": engagement_id
            })

        # Pattern snippets
        for idx, cs in enumerate(candidate_snippets):
            cid = f"code_pattern_{engagement_id}_{idx+1}"
            doc_text = f"Candidate Code Pattern ({cs.get('pattern_type')}): {cs.get('description')} snippet: '{cs.get('snippet')}' in {cs.get('file_path')}:{cs.get('line')}"
            ids.append(cid)
            documents.append(doc_text)
            metadatas.append({
                "control_id": cs.get("cwe_id", "CWE-unmapped"),
                "title": f"Candidate Pattern {cs.get('pattern_type')}",
                "jurisdiction": "code_analysis",
                "framework": "static_code_review",
                "source_file": cs.get("file_path", "unknown"),
                "evidence_type": "static_code_review",
                "verified": "false",
                "engagement_id": engagement_id
            })

        if documents:
            embeddings = embedder.encode(documents).tolist()
            collection.upsert(
                ids=ids,
                embeddings=embeddings,
                documents=documents,
                metadatas=metadatas
            )
            print(f"[OK] Upserted {len(ids)} findings into ChromaDB collection 'controls'.")
    except Exception as exc:
        print(f"[ChromaDB Store Note] {exc}")

    # 4b. Append to unified_verification_findings.json
    unified_file = os.path.join(PROJECT_ROOT, "unified_verification_findings.json")
    existing_findings = []
    if os.path.exists(unified_file):
        try:
            with open(unified_file, "r", encoding="utf-8") as f:
                existing_findings = json.load(f)
        except Exception:
            existing_findings = []

    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    new_findings = []

    for tf in tool_findings:
        new_findings.append({
            "control_id": tf.get("cwe_id", "CWE-unmapped"),
            "framework": "static_code_scan",
            "status": "FAIL" if tf.get("severity") in ["HIGH", "CRITICAL"] else "PARTIAL",
            "evidence_type": "static_code_scan",
            "evidence_source": f"{tf.get('file_path')}:{tf.get('line')}",
            "evidence_summary": tf.get("description"),
            "verified": False,
            "engagement_id": engagement_id,
            "timestamp": timestamp
        })

    for cs in candidate_snippets:
        new_findings.append({
            "control_id": cs.get("cwe_id", "CWE-unmapped"),
            "framework": "static_code_review",
            "status": "NO_DATA",
            "evidence_type": "static_code_review",
            "evidence_source": f"{cs.get('file_path')}:{cs.get('line')}",
            "evidence_summary": f"Candidate snippet [{cs.get('pattern_type')}]: {cs.get('snippet')}",
            "verified": False,
            "engagement_id": engagement_id,
            "timestamp": timestamp
        })

    combined = existing_findings + new_findings
    with open(unified_file, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2)

    print(f"[OK] Appended {len(new_findings)} findings to '{unified_file}'.")


# ---------------------------------------------------------------------------
# Single Scan & Continuous Watcher Automation
# ---------------------------------------------------------------------------
def run_ingestion_pass(repo_path: str, engagement_id: str, operator: str):
    """Executes a single static code ingestion pass across the target repository."""
    t0 = time.time()
    repo_profile = scan_repo_structure(repo_path)
    tool_findings = run_static_tool_scans(repo_path)
    candidate_snippets = extract_config_patterns(repo_path)
    process_and_store_findings(engagement_id, tool_findings, candidate_snippets, repo_profile)
    t_elapsed = time.time() - t0
    print(f"[{time.strftime('%H:%M:%S')}] Ingestion Pass Complete ({t_elapsed:.2f}s): {len(tool_findings)} tool findings, {len(candidate_snippets)} candidate policy snippets.")


def run_continuous_watch_mode(repo_path: str, engagement_id: str, operator: str, poll_interval: int = 3):
    """Monitors repository directory for file modifications and re-runs ingestion automatically."""
    print(f"👀 [Real-Time Watcher]: Active on '{os.path.abspath(repo_path)}'. Monitoring for file changes (interval={poll_interval}s)...")
    log_audit_event(engagement_id, repo_path, operator, "WATCHING", "Real-time filesystem watch mode activated.")

    last_mtime = 0.0

    def get_max_mtime():
        max_t = 0.0
        for root, _, files in os.walk(repo_path):
            for f in files:
                try:
                    mt = os.path.getmtime(os.path.join(root, f))
                    if mt > max_t:
                        max_t = mt
                except Exception:
                    pass
        return max_t

    # Initial pass
    run_ingestion_pass(repo_path, engagement_id, operator)
    last_mtime = get_max_mtime()

    try:
        while True:
            time.sleep(poll_interval)
            current_max = get_max_mtime()
            if current_max > last_mtime:
                print(f"\n🔄 [Real-Time Trigger]: Detected file modification in repository. Re-running ingestion pipeline...")
                last_mtime = current_max
                run_ingestion_pass(repo_path, engagement_id, operator)
    except KeyboardInterrupt:
        print("\n👋 [Real-Time Watcher]: Stopped by operator.")
        log_audit_event(engagement_id, repo_path, operator, "STOPPED", "Real-time watch mode stopped.")


def main():
    parser = argparse.ArgumentParser(description="Agent 1b: Real-Time Automated Code/Repo Ingestion Agent (Mode B)")
    parser.add_argument("--repo-path", help="Path to client repository to ingest")
    parser.add_argument("--engagement-id", default="default_engagement", help="Unique engagement identifier")
    parser.add_argument("--operator", default="automation_engine", help="Operator identity")
    parser.add_argument("--watch", action="store_true", help="Enable continuous real-time directory monitoring")
    parser.add_argument("--poll-interval", type=int, default=3, help="Watch mode polling interval in seconds")

    args = parser.parse_args()

    # Resolve repo path default if omitted
    resolved_repo_path = args.repo_path
    if not resolved_repo_path:
        resolved_repo_path = os.path.join(PROJECT_ROOT, "client_vault", args.engagement_id, "repo")

    # Path validation: fail loud if missing
    if not os.path.exists(resolved_repo_path) or not os.path.isdir(resolved_repo_path):
        log_audit_event(args.engagement_id, str(resolved_repo_path), args.operator, "REFUSED", "Resolved repo path does not exist or is not a directory.")
        print(f"\n❌ [ERROR] Provided repository path does not exist or is invalid: '{resolved_repo_path}'")
        sys.exit(1)

    print("============================================================")
    print(" Agent 1b — Real-Time Automated Code Ingestion Agent (Mode B)")
    print(f" Engagement ID : {args.engagement_id}")
    print(f" Repo Path     : {os.path.abspath(resolved_repo_path)}")
    print(f" Mode          : {'Continuous Real-Time Watcher' if args.watch else 'Automated Single Scan'}")
    print(" Strategy      : Framework-Agnostic Static Ingestion")
    print("============================================================\n")

    log_audit_event(args.engagement_id, resolved_repo_path, args.operator, "STARTED", "Real-time code ingestion started.")

    if args.watch:
        run_continuous_watch_mode(resolved_repo_path, args.engagement_id, args.operator, args.poll_interval)
    else:
        run_ingestion_pass(resolved_repo_path, args.engagement_id, args.operator)
        log_audit_event(args.engagement_id, resolved_repo_path, args.operator, "COMPLETED", "Code ingestion pass complete.")


if __name__ == "__main__":
    main()
