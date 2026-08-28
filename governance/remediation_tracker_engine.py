"""
Remediation Tracking & State Management Engine
---------------------------------------------
Manages stateful remediation items for compliance assessments:
  - Allowed States: "open", "in_progress", "resolved", "accepted_risk"
  - Stores history per client & framework in `remediation_tracker/{client_id}.json`
  - Re-run comparison: Tracks historical progress across audit cycles to show improvement over time.
"""

import os
import json
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
REMEDIATION_DIR = os.path.join(PROJECT_ROOT, "remediation_tracker")
os.makedirs(REMEDIATION_DIR, exist_ok=True)

VALID_REMEDIATION_STATES = ["open", "in_progress", "resolved", "accepted_risk"]


def _get_remediation_file(client_id: str) -> str:
    clean_id = client_id.strip().replace("..", "").replace("/", "").replace("\\", "")
    return os.path.join(REMEDIATION_DIR, f"{clean_id}_remediation.json")


def load_client_remediations(client_id: str) -> Dict[str, Any]:
    """Loads all tracked remediation items for a given client."""
    path = _get_remediation_file(client_id)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"client_id": client_id, "updated_at": datetime.now(timezone.utc).isoformat(), "items": {}}


def save_client_remediations(client_id: str, data: Dict[str, Any]):
    """Saves tracked remediation items for a client."""
    path = _get_remediation_file(client_id)
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def sync_assessment_remediations(
    client_id: str,
    framework: str,
    assessment_items: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Syncs raw assessment findings with the client's historical remediation tracking store.
    Preserves user overrides ("in_progress", "resolved", "accepted_risk") and audit logs.
    """
    tracker_data = load_client_remediations(client_id)
    items = tracker_data.get("items", {})

    synced_results = []

    for item in assessment_items:
        ctrl_id = item.get("control_id") or "UNKNOWN"
        item_key = f"{framework}__{ctrl_id}"
        status = item.get("status", "Not Compliant")
        sim_score = float(item.get("evidence_similarity", 0.0) or 0.0)

        # Compute Confidence / Evidence Strength Indicator
        if sim_score >= 0.80:
            evidence_strength = "🟢 HIGH CONFIDENCE"
        elif sim_score >= 0.60:
            evidence_strength = "🟡 MODERATE CONFIDENCE"
        elif sim_score > 0.0:
            evidence_strength = "🔴 LOW CONFIDENCE"
        else:
            evidence_strength = "⚪ NO EVIDENCE FOUND"

        existing = items.get(item_key)

        if not existing:
            initial_rem_state = "resolved" if status == "Compliant" else "open"
            rem_entry = {
                "item_key": item_key,
                "framework": framework,
                "control_id": ctrl_id,
                "title": item.get("title", ""),
                "assessment_status": status,
                "remediation_state": initial_rem_state,
                "owner": "Unassigned",
                "notes": "",
                "evidence_strength": evidence_strength,
                "evidence_similarity": sim_score,
                "history": [
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "assessment_status": status,
                        "remediation_state": initial_rem_state,
                    }
                ]
            }
            items[item_key] = rem_entry
            existing = rem_entry
        else:
            # Update historical record if assessment status changed
            existing["assessment_status"] = status
            existing["evidence_strength"] = evidence_strength
            existing["evidence_similarity"] = sim_score
            if status == "Compliant" and existing["remediation_state"] != "resolved":
                existing["remediation_state"] = "resolved"

        enriched_item = {
            **item,
            "remediation_state": existing["remediation_state"],
            "owner": existing.get("owner", "Unassigned"),
            "notes": existing.get("notes", ""),
            "evidence_strength": evidence_strength,
            "evidence_similarity": sim_score,
        }
        synced_results.append(enriched_item)

    tracker_data["items"] = items
    save_client_remediations(client_id, tracker_data)

    return synced_results


def update_remediation_status(
    client_id: str,
    item_key: str,
    new_state: str,
    owner: str = "Unassigned",
    notes: str = ""
) -> Dict[str, Any]:
    """
    Updates remediation tracking state ("open", "in_progress", "resolved", "accepted_risk") for a control gap.
    """
    if new_state not in VALID_REMEDIATION_STATES:
        raise ValueError(f"Invalid remediation state '{new_state}'. Must be one of {VALID_REMEDIATION_STATES}")

    tracker_data = load_client_remediations(client_id)
    items = tracker_data.get("items", {})

    if item_key in items:
        items[item_key]["remediation_state"] = new_state
        items[item_key]["owner"] = owner
        items[item_key]["notes"] = notes
        items[item_key]["history"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation_state": new_state,
            "owner": owner,
            "notes": notes,
        })
        save_client_remediations(client_id, tracker_data)
        
        # Log to security audit trail
        try:
            import application_security_trust as ast
            ast.log_security_event(
                tenant_id=client_id,
                action="UPDATE_REMEDIATION_STATE",
                actor=owner,
                resource=item_key,
                details={"new_state": new_state, "notes": notes}
            )
        except Exception:
            pass

        return items[item_key]

    raise KeyError(f"Item key '{item_key}' not found in client remediation tracker.")


def get_remediation_summary(client_id: str) -> Dict[str, Any]:
    """Generates remediation statistics for executive dashboards."""
    tracker_data = load_client_remediations(client_id)
    items = tracker_data.get("items", {})

    total = len(items)
    open_count = sum(1 for i in items.values() if i.get("remediation_state") == "open")
    in_prog_count = sum(1 for i in items.values() if i.get("remediation_state") == "in_progress")
    resolved_count = sum(1 for i in items.values() if i.get("remediation_state") == "resolved")
    risk_accepted_count = sum(1 for i in items.values() if i.get("remediation_state") == "accepted_risk")

    return {
        "client_id": client_id,
        "total_items": total,
        "open": open_count,
        "in_progress": in_prog_count,
        "resolved": resolved_count,
        "accepted_risk": risk_accepted_count,
        "resolution_rate": round((resolved_count / total * 100) if total > 0 else 100.0, 1),
        "last_updated": tracker_data.get("updated_at")
    }


def export_remediation_csv(client_id: str, output_path: str = None) -> str:
    """Exports client remediation state to CSV format for audit evidence."""
    import csv
    tracker_data = load_client_remediations(client_id)
    items = tracker_data.get("items", {})

    if not output_path:
        output_path = os.path.join(REMEDIATION_DIR, f"{client_id}_remediation_export.csv")

    fieldnames = [
        "item_key", "framework", "control_id", "title",
        "assessment_status", "remediation_state", "owner",
        "evidence_strength", "notes"
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in items.values():
            writer.writerow({
                "item_key": item.get("item_key", ""),
                "framework": item.get("framework", ""),
                "control_id": item.get("control_id", ""),
                "title": item.get("title", ""),
                "assessment_status": item.get("assessment_status", ""),
                "remediation_state": item.get("remediation_state", ""),
                "owner": item.get("owner", "Unassigned"),
                "evidence_strength": item.get("evidence_strength", ""),
                "notes": item.get("notes", "")
            })

    return output_path
