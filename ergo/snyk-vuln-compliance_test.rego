package policy_test

import data.ergo
import data.policy

vulns := [{"full_id": "SNYK-ALPINE321-OPENSSL-13939001", "severity": "high", "now_ts": 1748736000, "first_seen_ts": 1748563200, "ignore_expires_exists": false, "ignore_forever": false, "ignore_expires": "", "ignore_expires_ts": 0}, {"full_id": "SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804", "severity": "medium", "now_ts": 1748736000, "first_seen_ts": 1747699200, "ignore_expires_exists": false, "ignore_forever": false, "ignore_expires": "", "ignore_expires_ts": 0}, {"full_id": "SNYK-ALPINE321-RUBY-14100871", "severity": "critical", "now_ts": 1748736000, "first_seen_ts": 1748476800, "ignore_expires_exists": true, "ignore_forever": false, "ignore_expires": "2025-06-07 00:00:00+00:00", "ignore_expires_ts": 1749254400}, {"full_id": "snyk:lic:pip:astroid:LGPL-2.1", "severity": "low", "now_ts": 1748736000, "first_seen_ts": 1748304000, "ignore_expires_exists": true, "ignore_forever": false, "ignore_expires": "2025-05-30 00:00:00+00:00", "ignore_expires_ts": 1748563200}, {"full_id": "SNYK-ALPINE321-BUSYBOX-13661163", "severity": "medium", "now_ts": 1748736000, "first_seen_ts": 1740787200, "ignore_expires_exists": true, "ignore_forever": true, "ignore_expires": "", "ignore_expires_ts": 0}, {"full_id": "SNYK-ALPINE321-ZLIB-13874461", "severity": "high", "now_ts": 1748736000, "first_seen_ts": 1748739600, "ignore_expires_exists": false, "ignore_forever": false, "ignore_expires": "", "ignore_expires_ts": 0}]

report := r if {
	r := policy.report
		with input as {"vulns": vulns}
}

violations := ergo.violations(report)

report_for(vulns) := r if {
	r := policy.report
		with input as {"vulns": vulns}
}

failed(r) := {[v.requirement, v.subject.id, v.check, v.cause] |
	some v in ergo.violations(r)
}

test_the_artifact_is_not_compliant if {
	report.compliant == false
}

test_violations_name_each_failing_vuln_and_why if {
	{[v.subject.id, v.check, v.cause] | some v in violations} == {
		["SNYK-ALPINE321-ZLIB-13874461", "seen_before_now", "value"],
		["SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804", "within_limit", "value"],
		["snyk:lic:pip:astroid:LGPL-2.1", "not_expired", "value"],
	}
}

test_vuln_past_its_limit_shows_the_numbers_read if {
	some v in violations
	v.check == "within_limit"
	v.inputs == [
		{"name": "first_seen_ts plus $params.max_seconds_by_severity.medium", "value": 1748563200},
		{"name": "first_seen_ts", "value": 1747699200},
		{"name": "$params.max_seconds_by_severity.medium", "value": 864000},
		{"name": "now_ts", "value": 1748736000},
	]
}

test_artifact_with_no_vulns_is_compliant if {
	report_for([]).compliant == true
}

test_input_without_vulns_is_not_compliant if {
	r := policy.report
		with input as {}
	r.compliant == false
}

test_run_without_params_fails_the_age_limit if {
	r := policy.report
		with input as {"vulns": vulns}
		with data.params as {}
	some row in r.results
	row.subject.id == "SNYK-ALPINE321-OPENSSL-13939001"
	row.check == "within_limit"
	row.cause == "absent"
}

vuln(fields) := object.union(
	{"full_id": "v-1", "severity": "critical", "now_ts": 1748736000, "first_seen_ts": 1748736000, "ignore_expires_exists": false, "ignore_forever": false, "ignore_expires": "", "ignore_expires_ts": 0},
	fields,
)

test_critical_vuln_on_day_zero_is_within_a_one_day_limit if {
	report_for([vuln({})]).compliant == true
}

test_critical_vuln_on_its_limit_fails if {
	r := report_for([vuln({"first_seen_ts": 1748649600})])
	failed(r) == {["critical_age", "v-1", "within_limit", "value"]}
}

test_ignore_that_expires_at_the_scan_still_holds if {
	r := report_for([vuln({"first_seen_ts": 0, "ignore_expires_exists": true, "ignore_expires_ts": 1748736000})])
	r.compliant == true
}

test_forever_ignore_passes_whatever_the_age if {
	r := report_for([vuln({"first_seen_ts": 0, "ignore_expires_exists": true, "ignore_forever": true})])
	r.compliant == true
}

test_unknown_severity_fails_instead_of_skipping_the_age_limit if {
	r := report_for([vuln({"severity": "unknown", "first_seen_ts": 0})])
	failed(r) == {["readable", "v-1", "severity", "value"]}
}

test_ignore_flag_that_is_not_a_boolean_fails_instead_of_skipping_every_case if {
	r := report_for([vuln({"ignore_expires_exists": "false", "first_seen_ts": 0})])
	failed(r) == {["readable", "v-1", "ignore_known", "value"]}
}

test_ignored_vuln_without_a_forever_flag_fails if {
	r := report_for([object.remove(vuln({"ignore_expires_exists": true}), ["ignore_forever"])])
	["ignore_readable", "v-1", "forever_known", "absent"] in failed(r)
}

test_the_artifact_is_not_allowed if {
	not policy.allow with input as {"vulns": vulns}
}

test_the_vulns_that_pass_are_allowed_on_their_own if {
	passing := {"SNYK-ALPINE321-OPENSSL-13939001", "SNYK-ALPINE321-RUBY-14100871", "SNYK-ALPINE321-BUSYBOX-13661163"}
	policy.allow with input as {"vulns": [v | some v in vulns; v.full_id in passing]}
}

test_each_message_starts_with_the_id_of_its_vuln if {
	policy.violations with input as {"vulns": vulns} == {
		"SNYK-ALPINE321-ZLIB-13874461: high_age seen_before_now failed as value: first_seen_ts is at most now_ts",
		"SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804: medium_age within_limit failed as value: first_seen_ts plus $params.max_seconds_by_severity.medium is more than now_ts",
		"snyk:lic:pip:astroid:LGPL-2.1: ignore_not_expired not_expired failed as value: ignore_expires_ts is at least now_ts",
	}
}

test_a_failure_about_no_vuln_in_particular_names_the_artifact if {
	"artifact: readable $min_subjects failed as absent: vulns can be read" in policy.violations with input as {}
}
