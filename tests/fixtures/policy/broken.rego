package confidior.appraisal
import rego.v1

deny_broken contains msg if {
	msg := "this module does not parse"
