package iso27001.a8_9_test

import data.iso27001.a8_9
import rego.v1

compliant_asset := {
	"id": "host-web-01",
	"type": "host",
	"in_scope": true,
	"baseline_id": "cis-linux-l2",
	"baseline_approved": true,
	"baseline_reviewed_within_days": 30,
	"config_monitored": true,
	"drift_detected": false,
	"unauthorized_change": false,
}

out_of_scope_asset := {
	"id": "host-lab-01",
	"type": "host",
	"in_scope": false,
	"baseline_id": "",
	"baseline_approved": false,
	"config_monitored": false,
	"drift_detected": true,
	"unauthorized_change": true,
}

test_pass_when_in_scope_assets_meet_baseline if {
	count(a8_9.violations) == 0 with input as {"assets": [compliant_asset, out_of_scope_asset]}
}

test_out_of_scope_assets_are_skipped if {
	count(a8_9.violations) == 0 with input as {"assets": [out_of_scope_asset]}
}

test_baseline_missing if {
	asset := object.union(compliant_asset, {"id": "host-missing-baseline", "baseline_id": ""})
	v := a8_9.violations with input as {"assets": [asset]}
	count(v) == 1
	some finding in v
	finding.rule_id == "a8_9.baseline_missing"
	finding.resource == "host-missing-baseline"
	finding.control_id == "A.8.9"
}

test_baseline_unapproved if {
	asset := object.union(compliant_asset, {"id": "svc-unapproved-baseline", "baseline_id": "k8s-draft", "baseline_approved": false})
	v := a8_9.violations with input as {"assets": [asset]}
	count(v) == 1
	some finding in v
	finding.rule_id == "a8_9.baseline_unapproved"
}

test_baseline_review_stale if {
	asset := object.union(compliant_asset, {"id": "net-stale-review", "baseline_reviewed_within_days": 180})
	v := a8_9.violations with input as {"assets": [asset]}
	count(v) == 1
	some finding in v
	finding.rule_id == "a8_9.baseline_review_stale"
	finding.severity == "medium"
}

test_baseline_review_missing_days_is_stale if {
	asset := object.remove(object.union(compliant_asset, {"id": "host-no-review-date"}), {"baseline_reviewed_within_days"})
	v := a8_9.violations with input as {"assets": [asset]}
	count(v) == 1
	some finding in v
	finding.rule_id == "a8_9.baseline_review_stale"
}

test_review_max_days_override if {
	asset := object.union(compliant_asset, {"id": "host-custom-window", "baseline_reviewed_within_days": 45})
	v := a8_9.violations with input as {
		"policy": {"a8_9": {"review_max_days": 30}},
		"assets": [asset],
	}
	count(v) == 1
	some finding in v
	finding.rule_id == "a8_9.baseline_review_stale"
}

test_config_not_monitored if {
	asset := object.union(compliant_asset, {"id": "sw-unmonitored", "config_monitored": false})
	v := a8_9.violations with input as {"assets": [asset]}
	count(v) == 1
	some finding in v
	finding.rule_id == "a8_9.config_not_monitored"
}

test_drift_detected if {
	asset := object.union(compliant_asset, {"id": "host-drifted", "drift_detected": true})
	v := a8_9.violations with input as {"assets": [asset]}
	count(v) == 1
	some finding in v
	finding.rule_id == "a8_9.drift_detected"
}

test_unauthorized_change if {
	asset := object.union(compliant_asset, {"id": "host-unauthorized", "unauthorized_change": true})
	v := a8_9.violations with input as {"assets": [asset]}
	count(v) == 1
	some finding in v
	finding.rule_id == "a8_9.unauthorized_change"
}

test_deny_messages_generated if {
	asset := object.union(compliant_asset, {"id": "host-drifted", "drift_detected": true})
	msgs := a8_9.deny with input as {"assets": [asset]}
	count(msgs) == 1
}

test_fail_fixture_covers_each_rule_and_skips_out_of_scope if {
	v := a8_9.violations with input as fail_fixture
	count(v) == 6
	rule_ids := {f.rule_id | some f in v}
	rule_ids == {
		"a8_9.baseline_missing",
		"a8_9.baseline_unapproved",
		"a8_9.baseline_review_stale",
		"a8_9.config_not_monitored",
		"a8_9.drift_detected",
		"a8_9.unauthorized_change",
	}
	resources := {f.resource | some f in v}
	not resources["host-out-of-scope"]
}

fail_fixture := {
	"policy": {"a8_9": {"review_max_days": 90}},
	"assets": [
		{
			"id": "host-missing-baseline",
			"type": "host",
			"in_scope": true,
			"baseline_id": "",
			"baseline_approved": false,
			"config_monitored": true,
			"drift_detected": false,
			"unauthorized_change": false,
		},
		{
			"id": "svc-unapproved-baseline",
			"type": "service",
			"in_scope": true,
			"baseline_id": "k8s-draft",
			"baseline_approved": false,
			"baseline_reviewed_within_days": 10,
			"config_monitored": true,
			"drift_detected": false,
			"unauthorized_change": false,
		},
		{
			"id": "net-stale-review",
			"type": "network",
			"in_scope": true,
			"baseline_id": "acl-standard",
			"baseline_approved": true,
			"baseline_reviewed_within_days": 180,
			"config_monitored": true,
			"drift_detected": false,
			"unauthorized_change": false,
		},
		{
			"id": "sw-unmonitored",
			"type": "software",
			"in_scope": true,
			"baseline_id": "app-config-v3",
			"baseline_approved": true,
			"baseline_reviewed_within_days": 20,
			"config_monitored": false,
			"drift_detected": false,
			"unauthorized_change": false,
		},
		{
			"id": "host-drifted",
			"type": "host",
			"in_scope": true,
			"baseline_id": "cis-linux-l2",
			"baseline_approved": true,
			"baseline_reviewed_within_days": 5,
			"config_monitored": true,
			"drift_detected": true,
			"unauthorized_change": false,
		},
		{
			"id": "host-unauthorized",
			"type": "host",
			"in_scope": true,
			"baseline_id": "cis-linux-l2",
			"baseline_approved": true,
			"baseline_reviewed_within_days": 5,
			"config_monitored": true,
			"drift_detected": false,
			"unauthorized_change": true,
		},
		{
			"id": "host-out-of-scope",
			"type": "host",
			"in_scope": false,
			"baseline_id": "",
			"baseline_approved": false,
			"config_monitored": false,
			"drift_detected": true,
			"unauthorized_change": true,
		},
	],
}
