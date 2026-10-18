package confidior.appraisal
import rego.v1

# Default appraisal policy for hardware-attested workloads.
#
# The input contract is documented in src/core/policy.py. Each rule below is a
# set of failure reasons: empty means the rule held, non-empty means it did not,
# and each element is carried into the report as the reason.
#
# The first rule exists because a set rule on an empty graph is vacuously empty,
# which would read as a pass. Absent evidence is a failure here, not silence.

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
	count(input.evidence.quote) == 0
}

deny_low_level contains msg if {
	input.assurance.level < 2
	msg := sprintf("assurance level %v is below the required 2", [input.assurance.level])
}

deny_debug contains msg if {
	some q in input.evidence.quote
	q.debug_disabled != true
	msg := sprintf("debug is enabled on %v", [q.platform])
}
