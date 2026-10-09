# ISO 27001:2022 Compliance Mapping & Evidence Matrix

## Overview
This repository provides automated, continuous compliance monitoring for **ISO 27001:2022 Annex A Technological Controls**. Raw telemetry is ingested via the GitHub REST API, normalized into JSON schemas, and evaluated against Policy-as-Code rules written in Open Policy Agent (OPA) Rego v1.

## Control Mapping Matrix

| ISO 27001 Control | Control Name | Telemetry Collector | Rego Policy File | Automated Finding Rules | Severity |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **A.5.3** | Segregation of Duties | `github_collector.py` | `policies/a8_28_secure_coding.rego` | `a8_28.review_not_required` | High |
| **A.8.9** | Configuration Management | `aws_collector.py` / Payload | `policies/a8_9_configuration_management.rego` | `a8_9.baseline_missing`<br>`a8_9.baseline_unapproved`<br>`a8_9.baseline_review_stale`<br>`a8_9.config_not_monitored`<br>`a8_9.drift_detected`<br>`a8_9.unauthorized_change` | High / Med |
| **A.8.28** | Secure Coding | `github_collector.py` | `policies/a8_28_secure_coding.rego` | `a8_28.standard_not_applied`<br>`a8_28.branch_unprotected`<br>`a8_28.sast_missing`<br>`a8_28.secret_scan_missing`<br>`a8_28.dependency_scan_missing`<br>`a8_28.secrets_in_repo`<br>`a8_28.critical_sast_open`<br>`a8_28.critical_cves_unfixed` | High / Med |

## Evidence Verification
To reproduce these findings locally and generate raw audit telemetry (`input.json` and `audit_results.json`):

```bash
# 1. Collect live API telemetry.  This creates input.json, which is used in step 2.
export GITHUB_TOKEN="INSERT_YOUR_TOKEN"
export TARGET_REPOS="informed-operator/my-grc-policy-engine,informed-operator/grc-test-target-failing"
python collectors/github_collector.py

# 2. Evaluate telemetry against OPA Rego policies
opa eval --data policies/ --input input.json "data.iso27001.a8_28.violations" --format pretty