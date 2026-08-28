<!-- converted from test_bays_template.docx -->

# {{ report_title }}
Client: {{ client_id }} | Framework: {{ framework }} | Generated: {{ generated_at }}
## Executive Summary
{{ executive_summary }}
## Compliance Scorecard

## Control Assessment & Evidence Matrix

## Actionable Remediation Plan
{% for rec in recommendations %}
• {{ rec }}
{% endfor %}
| Status | Count | % of Assessable |
| --- | --- | --- |
| ✅ Fully Compliant | {{ fully_compliant }} | {{ pct_fully }} |
| ⚠️ Partially Compliant | {{ partially_compliant }} | {{ pct_partially }} |
| ❌ Not Compliant | {{ not_compliant }} | {{ pct_not_comp }} |
| — Not Applicable | {{ not_applicable }} | — |
| — Untested | {{ untested }} | — |
| Control ID / Requirement | Framework Mapped | Status | Auditor Rationale & Evidence |
| --- | --- | --- | --- |
| {% tr for row in findings_matrix %}{{ row.control_id }} | {{ row.framework }} | {{ row.status }} | {{ row.details }}{% tr endfor %} |