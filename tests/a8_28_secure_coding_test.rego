package iso27001.a8_28_test

import data.iso27001.a8_28
import rego.v1

compliant_repo := {
	"id": "payments-api",
	"in_scope": true,
	"secure_coding_standard_applied": true,
	"code_review_required": true,
	"default_branch_protected": true,
	"sast_enabled": true,
	"secret_scan_enabled": true,
	"dependency_scan_enabled": true,
	"secrets_in_repo": false,
	"critical_sast_open": false,
	"critical_cves_unfixed": false,
}

out_of_scope_repo := {
	"id": "legacy-tools",
	"in_scope": false,
	"secure_coding_standard_applied": false,
	"code_review_required": false,
	"default_branch_protected": false,
	"sast_enabled": false,
	"secret_scan_enabled": false,
	"dependency_scan_enabled": false,
	"secrets_in_repo": true,
	"critical_sast_open": true,
	"critical_cves_unfixed": true,
}

test_pass_when_in_scope_repos_meet_secure_coding if {
	count(a8_28.violations) == 0 with input as {"repositories": [compliant_repo, out_of_scope_repo]}
}

test_out_of_scope_repos_are_skipped if {
	count(a8_28.violations) == 0 with input as {"repositories": [out_of_scope_repo]}
}

test_standard_not_applied if {
	repo := object.union(compliant_repo, {"id": "no-standard", "secure_coding_standard_applied": false})
	v := a8_28.violations with input as {"repositories": [repo]}
	count(v) == 1
	some finding in v
	finding.rule_id == "a8_28.standard_not_applied"
	finding.control_id == "A.8.28"
}

test_branch_unprotected if {
	repo := object.union(compliant_repo, {"id": "unprotected-branch", "default_branch_protected": false})
	v := a8_28.violations with input as {"repositories": [repo]}
	count(v) == 1
	some finding in v
	finding.rule_id == "a8_28.branch_unprotected"
}

test_review_not_required if {
	repo := object.union(compliant_repo, {"id": "no-review", "code_review_required": false})
	v := a8_28.violations with input as {"repositories": [repo]}
	count(v) == 1
	some finding in v
	finding.rule_id == "a8_28.review_not_required"
}

test_sast_missing if {
	repo := object.union(compliant_repo, {"id": "missing-sast", "sast_enabled": false})
	v := a8_28.violations with input as {"repositories": [repo]}
	count(v) == 1
	some finding in v
	finding.rule_id == "a8_28.sast_missing"
	finding.severity == "medium"
}

test_secret_scan_missing if {
	repo := object.union(compliant_repo, {"id": "missing-secret-scan", "secret_scan_enabled": false})
	v := a8_28.violations with input as {"repositories": [repo]}
	count(v) == 1
	some finding in v
	finding.rule_id == "a8_28.secret_scan_missing"
}

test_dependency_scan_missing if {
	repo := object.union(compliant_repo, {"id": "missing-dep-scan", "dependency_scan_enabled": false})
	v := a8_28.violations with input as {"repositories": [repo]}
	count(v) == 1
	some finding in v
	finding.rule_id == "a8_28.dependency_scan_missing"
}

test_secrets_in_repo if {
	repo := object.union(compliant_repo, {"id": "has-secrets", "secrets_in_repo": true})
	v := a8_28.violations with input as {"repositories": [repo]}
	count(v) == 1
	some finding in v
	finding.rule_id == "a8_28.secrets_in_repo"
	finding.severity == "high"
}

test_critical_sast_open if {
	repo := object.union(compliant_repo, {"id": "open-sast", "critical_sast_open": true})
	v := a8_28.violations with input as {"repositories": [repo]}
	count(v) == 1
	some finding in v
	finding.rule_id == "a8_28.critical_sast_open"
}

test_critical_cves_unfixed if {
	repo := object.union(compliant_repo, {"id": "unfixed-cves", "critical_cves_unfixed": true})
	v := a8_28.violations with input as {"repositories": [repo]}
	count(v) == 1
	some finding in v
	finding.rule_id == "a8_28.critical_cves_unfixed"
}

test_deny_messages_generated if {
	repo := object.union(compliant_repo, {"id": "has-secrets", "secrets_in_repo": true})
	msgs := a8_28.deny with input as {"repositories": [repo]}
	count(msgs) == 1
}

test_fail_fixture_covers_each_rule_and_skips_out_of_scope if {
	v := a8_28.violations with input as fail_fixture
	count(v) == 9
	rule_ids := {f.rule_id | some f in v}
	rule_ids == {
		"a8_28.standard_not_applied",
		"a8_28.branch_unprotected",
		"a8_28.review_not_required",
		"a8_28.sast_missing",
		"a8_28.secret_scan_missing",
		"a8_28.dependency_scan_missing",
		"a8_28.secrets_in_repo",
		"a8_28.critical_sast_open",
		"a8_28.critical_cves_unfixed",
	}
	resources := {f.resource | some f in v}
	not resources["out-of-scope"]
}

fail_fixture := {
	"repositories": [
		object.union(compliant_repo, {"id": "no-standard", "secure_coding_standard_applied": false}),
		object.union(compliant_repo, {"id": "unprotected-branch", "default_branch_protected": false}),
		object.union(compliant_repo, {"id": "no-review", "code_review_required": false}),
		object.union(compliant_repo, {"id": "missing-sast", "sast_enabled": false}),
		object.union(compliant_repo, {"id": "missing-secret-scan", "secret_scan_enabled": false}),
		object.union(compliant_repo, {"id": "missing-dep-scan", "dependency_scan_enabled": false}),
		object.union(compliant_repo, {"id": "has-secrets", "secrets_in_repo": true}),
		object.union(compliant_repo, {"id": "open-sast", "critical_sast_open": true}),
		object.union(compliant_repo, {"id": "unfixed-cves", "critical_cves_unfixed": true}),
		{
			"id": "out-of-scope",
			"in_scope": false,
			"secure_coding_standard_applied": false,
			"code_review_required": false,
			"default_branch_protected": false,
			"sast_enabled": false,
			"secret_scan_enabled": false,
			"dependency_scan_enabled": false,
			"secrets_in_repo": true,
			"critical_sast_open": true,
			"critical_cves_unfixed": true,
		},
	],
}
