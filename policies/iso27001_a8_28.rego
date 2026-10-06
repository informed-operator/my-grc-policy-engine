package iso27001.a8_28

import data.lib.findings
import rego.v1

control_id := "A.8.28"

in_scope_repos contains repo if {
	some repo in input.repositories
	repo.in_scope == true
}

# No documented/applied secure coding standard.
violations contains findings.finding(
	control_id,
	"a8_28.standard_not_applied",
	"high",
	repo.id,
	sprintf("Repository %q does not apply a documented secure coding standard.", [repo.id]),
) if {
	some repo in in_scope_repos
	repo.secure_coding_standard_applied != true
}

# Default branch is not protected.
violations contains findings.finding(
	control_id,
	"a8_28.branch_unprotected",
	"high",
	repo.id,
	sprintf("Repository %q default branch is not protected.", [repo.id]),
) if {
	some repo in in_scope_repos
	repo.default_branch_protected != true
}

# Code review is not required.
violations contains findings.finding(
	control_id,
	"a8_28.review_not_required",
	"high",
	repo.id,
	sprintf("Repository %q does not require code review before merge.", [repo.id]),
) if {
	some repo in in_scope_repos
	repo.code_review_required != true
}

# Missing SAST.
violations contains findings.finding(
	control_id,
	"a8_28.sast_missing",
	"medium",
	repo.id,
	sprintf("Repository %q does not have SAST enabled.", [repo.id]),
) if {
	some repo in in_scope_repos
	repo.sast_enabled != true
}

# Missing secret scanning.
violations contains findings.finding(
	control_id,
	"a8_28.secret_scan_missing",
	"medium",
	repo.id,
	sprintf("Repository %q does not have secret scanning enabled.", [repo.id]),
) if {
	some repo in in_scope_repos
	repo.secret_scan_enabled != true
}

# Missing dependency scanning.
violations contains findings.finding(
	control_id,
	"a8_28.dependency_scan_missing",
	"medium",
	repo.id,
	sprintf("Repository %q does not have dependency scanning enabled.", [repo.id]),
) if {
	some repo in in_scope_repos
	repo.dependency_scan_enabled != true
}

# Secrets present in the repository.
violations contains findings.finding(
	control_id,
	"a8_28.secrets_in_repo",
	"high",
	repo.id,
	sprintf("Repository %q contains known secrets.", [repo.id]),
) if {
	some repo in in_scope_repos
	repo.secrets_in_repo == true
}

# Open critical SAST findings.
violations contains findings.finding(
	control_id,
	"a8_28.critical_sast_open",
	"high",
	repo.id,
	sprintf("Repository %q has open critical SAST findings.", [repo.id]),
) if {
	some repo in in_scope_repos
	repo.critical_sast_open == true
}

# Unfixed critical dependency CVEs.
violations contains findings.finding(
	control_id,
	"a8_28.critical_cves_unfixed",
	"high",
	repo.id,
	sprintf("Repository %q has unfixed critical dependency CVEs.", [repo.id]),
) if {
	some repo in in_scope_repos
	repo.critical_cves_unfixed == true
}

deny contains msg if {
	some v in violations
	msg := sprintf("%s [%s] %s: %s", [v.control_id, v.rule_id, v.resource, v.message])
}
