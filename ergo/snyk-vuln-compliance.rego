package policy

import data.ergo

default params := {}

params := data.params

report := ergo.report(input, {"description": data.description, "subjects": data.subjects, "requirements": data.requirements}, params)

default allow := false

allow if report.compliant == true

violations contains msg if {
	some v in ergo.violations(report)
	msg := concat("", [subject_name(v), ": ", v.requirement, " ", v.check, " failed as ", v.cause, ": ", v.expression])
}

subject_name(v) := v.subject.id if is_string(v.subject.id)

subject_name(v) := "artifact" if not is_string(v.subject.id)
