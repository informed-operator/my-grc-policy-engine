package lib.findings

import rego.v1

# Shared GRC finding shape used by ISO 27001 policies.
finding(control_id, rule_id, severity, resource, message) := {
	"control_id": control_id,
	"rule_id": rule_id,
	"severity": severity,
	"resource": resource,
	"message": message,
}
