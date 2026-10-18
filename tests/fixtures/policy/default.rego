package confidior.appraisal
import rego.v1

# Default appraisal policy for hardware-attested workloads.
#
# The input contract is documented in src/core/policy.py. Each rule below is a
# set of failure reasons: empty means the rule held, non-empty means it did not,
# and each element is carried into the report as the reason.
#
# Two hazards shape how these rules are written. Both are Rego semantics, not
# engine bugs, and both fail *open* if a rule is written the obvious way.
#
#   1. A set rule over an empty collection is vacuously empty, which reads as a
#      pass. `deny_missing_quote` therefore asserts that evidence is present
#      rather than iterating over whatever is there.
#
#   2. A rule body that references a missing field is undefined, so the body
#      never fires and the rule reports satisfied. `q.debug_disabled != true`
#      passes when the field is absent, which is the wrong answer for a
#      verifier: an evidence producer that drops a field would relax the policy.
#      Every field read below goes through object.get with a default that
#      fails the rule, and a missing assurance level is its own finding.

rule_meta := {
	"deny_missing_quote": {
		"severity": "high",
		"title": "Attestation evidence must be present",
	},
	"deny_low_level": {
		"severity": "high",
		"title": "Require at least hardware-attested assurance",
	},
	"deny_debug": {
		"severity": "high",
		"title": "Debug mode must be disabled",
	},
}

deny_missing_quote contains "no attestation evidence" if {
	count(object.get(object.get(input, "evidence", {}), "quote", [])) == 0
}

# An absent level is not "level 0"; it is input the engine cannot judge. Saying
# so is a distinct finding, because "below threshold" would misreport it.
deny_low_level contains "assurance level is missing from the policy input" if {
	not is_number(object.get(object.get(input, "assurance", {}), "level", null))
}

deny_low_level contains msg if {
	lvl := object.get(object.get(input, "assurance", {}), "level", null)
	is_number(lvl)
	lvl < 2
	msg := sprintf("assurance level %v is below the required 2", [lvl])
}

deny_debug contains msg if {
	some q in object.get(object.get(input, "evidence", {}), "quote", [])
	object.get(q, "debug_disabled", false) == false
	msg := sprintf("debug is enabled on %v", [object.get(q, "platform", "unknown")])
}

deny_debug contains msg if {
	some q in object.get(object.get(input, "evidence", {}), "quote", [])
	not is_boolean(object.get(q, "debug_disabled", null))
	msg := sprintf(
		"debug_disabled is missing or not a boolean on %v",
		[object.get(q, "platform", "unknown")],
	)
}
