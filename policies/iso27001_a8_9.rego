package iso27001.a8_9

import data.lib.findings
import rego.v1

control_id := "A.8.9"

default review_max_days := 90

review_max_days := input.policy.a8_9.review_max_days

in_scope_assets contains asset if {
	some asset in input.assets
	asset.in_scope == true
}

# Missing configuration baseline identifier.
violations contains findings.finding(
	control_id,
	"a8_9.baseline_missing",
	"high",
	asset.id,
	sprintf("Asset %q has no documented configuration baseline.", [asset.id]),
) if {
	some asset in in_scope_assets
	not _has_baseline(asset)
}

# Baseline exists but is not approved.
violations contains findings.finding(
	control_id,
	"a8_9.baseline_unapproved",
	"high",
	asset.id,
	sprintf("Asset %q baseline %q is not approved.", [asset.id, asset.baseline_id]),
) if {
	some asset in in_scope_assets
	_has_baseline(asset)
	asset.baseline_approved != true
}

# Baseline not reviewed within the allowed window.
violations contains findings.finding(
	control_id,
	"a8_9.baseline_review_stale",
	"medium",
	asset.id,
	sprintf(
		"Asset %q baseline review is %v days old; maximum allowed is %v days.",
		[asset.id, asset.baseline_reviewed_within_days, review_max_days],
	),
) if {
	some asset in in_scope_assets
	_has_baseline(asset)
	asset.baseline_approved == true
	_review_stale(asset)
}

# Configuration is not monitored.
violations contains findings.finding(
	control_id,
	"a8_9.config_not_monitored",
	"medium",
	asset.id,
	sprintf("Asset %q configuration is not monitored for drift or unauthorized change.", [asset.id]),
) if {
	some asset in in_scope_assets
	asset.config_monitored != true
}

# Configuration drift detected.
violations contains findings.finding(
	control_id,
	"a8_9.drift_detected",
	"high",
	asset.id,
	sprintf("Asset %q has configuration drift from the approved baseline.", [asset.id]),
) if {
	some asset in in_scope_assets
	asset.drift_detected == true
}

# Unauthorized configuration change.
violations contains findings.finding(
	control_id,
	"a8_9.unauthorized_change",
	"high",
	asset.id,
	sprintf("Asset %q has an unauthorized configuration change.", [asset.id]),
) if {
	some asset in in_scope_assets
	asset.unauthorized_change == true
}

deny contains msg if {
	some v in violations
	msg := sprintf("%s [%s] %s: %s", [v.control_id, v.rule_id, v.resource, v.message])
}

_has_baseline(asset) if {
	asset.baseline_id
	asset.baseline_id != ""
}

_review_stale(asset) if {
    not asset.baseline_reviewed_within_days
}

_review_stale(asset) if {
	asset.baseline_reviewed_within_days == null
}

_review_stale(asset) if {
	_is_number(asset.baseline_reviewed_within_days)
	asset.baseline_reviewed_within_days > review_max_days
}

_is_number(value) if {
	is_number(value)
}
