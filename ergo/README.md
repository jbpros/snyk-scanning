# snyk-vuln-compliance with ergo

This folder holds `../snyk-vuln-compliance.rego` written with [ergo](https://github.com/kosli-dev/ergo), a Rego library that turns a policy into a report. Each vuln gets a row for every check, with the values it read and why it failed. Nothing outside this folder uses it yet.

| file                             | what it is                                                                    |
| -------------------------------- | ----------------------------------------------------------------------------- |
| `snyk-vuln-compliance.yaml`      | the rules, one check per line                                                 |
| `snyk-vuln-compliance.rego`      | `package policy`: runs the rules and gives `allow`, `violations` and `report` |
| `ergo.rego`                      | ergo itself, copied from kosli-dev/ergo at `f94d9fd`                          |
| `rego.params.aws-*.json`         | the same limits as `../rego.params.aws-*.json`, in seconds                    |
| `snyk-vuln-compliance_test.rego` | tests, run by `run_tests.sh`                                                  |

## Running it

```sh
opa eval -d ergo/ergo.rego -d ergo/snyk-vuln-compliance.rego -d ergo/snyk-vuln-compliance.yaml \
  -d params:ergo/rego.params.aws-prod.json -i input.json -f pretty 'data.policy.violations'
```

`input.json` is the same `{"vulns": [...]}` that `kosli evaluate input` gets. With a vuln 12 days old at medium severity, a licence ignore that expired the day before the scan, and a vuln first seen an hour after the scan, this gives:

```json
[
  "SNYK-ALPINE321-ZLIB-13874461: high_age seen_before_now failed as value: first_seen_ts is at most now_ts",
  "SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804: medium_age within_limit failed as value: first_seen_ts plus $params.max_seconds_by_severity.medium is more than now_ts",
  "snyk:lic:pip:astroid:LGPL-2.1: ignore_not_expired not_expired failed as value: ignore_expires_ts is at least now_ts"
]
```

Every message still starts with the vuln's `full_id` and `: `. A failure that isn't about one vuln, like an input with no `vulns`, starts with `artifact: `. `data.policy.report` has the full report, and its `within_limit` row for the Go vuln reads:

```json
[
  {"name": "first_seen_ts plus $params.max_seconds_by_severity.medium", "value": 1748563200},
  {"name": "first_seen_ts", "value": 1747699200},
  {"name": "$params.max_seconds_by_severity.medium", "value": 864000},
  {"name": "now_ts", "value": 1748736000}
]
```

## How it differs from the original

- The original denies a vuln first seen after the scan, a severity outside the four, or an `ignore_expires_exists` that isn't a boolean, but no violation names the vuln. Here each one fails with the vuln's id.
- ergo can add but not subtract, multiply or divide, so it can't work out an age in days. It checks `first_seen_ts` plus the limit `is more than now_ts`, which is the same as `age < limit`, so the limits are in seconds.
- A check can't pick a param by a field of the vuln, like `max_days_by_severity[vuln.severity]`, so there is one requirement per severity, `critical_age` to `low_age`.
- There is no `vuln_reports`. The rows hold the numbers read, but not the days left.
- `kosli evaluate input` takes one policy file, and this needs `ergo.rego` and the YAML next to it, so the workflows can't run it as it is.

## Tests

```sh
ergo/run_tests.sh
```

It checks that both params files have a limit for each severity, then runs the tests with the prod limits. They cover the cases in `../tests/test_rego_rules.sh`: day zero for a critical vuln, an ignore that expires at the scan, a forever ignore, no vulns, no `vulns` key and no params.
