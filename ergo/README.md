# snyk-vuln-compliance with ergo

This folder holds `../snyk-vuln-compliance.rego` written with [ergo](https://github.com/kosli-dev/ergo), a Rego library that turns a policy into a report. Each vuln gets a row for every check, with the values it read and why it failed. Nothing outside this folder uses it yet.

| file                             | what it is                                                                    |
| -------------------------------- | ----------------------------------------------------------------------------- |
| `snyk-vuln-compliance.yaml`      | the rules, one check per line                                                 |
| `snyk-vuln-compliance.rego`      | `package policy`: runs the rules and gives `allow`, `violations` and `report` |
| `ergo.rego`                      | ergo itself, copied from kosli-dev/ergo at `2083c41`                          |
| `snyk-vuln-compliance_test.rego` | tests, run by `run_tests.sh`                                                  |

It reads the same params files as the original, `../rego.params.aws-*.json`.

The age rule is one line:

```yaml
within_limit: days elapsed from first_seen_ts to now_ts is less than $params.max_days_by_severity named by severity
```

## Running it

```sh
opa eval -d ergo/ergo.rego -d ergo/snyk-vuln-compliance.rego -d ergo/snyk-vuln-compliance.yaml \
  -d params:rego.params.aws-prod.json -i input.json -f pretty 'data.policy.violations'
```

`input.json` is the same `{"vulns": [...]}` that `kosli evaluate input` gets. With a vuln 12 days old at medium severity, a licence ignore that expired the day before the scan, and a vuln first seen an hour after the scan, this gives:

```json
[
  "SNYK-ALPINE321-ZLIB-13874461: age within_limit failed as value: days elapsed from first_seen_ts to now_ts is less than $params.max_days_by_severity named by severity",
  "SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804: age within_limit failed as value: days elapsed from first_seen_ts to now_ts is less than $params.max_days_by_severity named by severity",
  "snyk:lic:pip:astroid:LGPL-2.1: ignore_not_expired not_expired failed as value: ignore_expires_ts is at least now_ts"
]
```

Every message still starts with the vuln's `full_id` and `: `. A failure that isn't about one vuln, like an input with no `vulns`, starts with `artifact: `. `data.policy.report` has the full report, and its `within_limit` row for the Go vuln reads:

```json
[
  {"name": "days elapsed from first_seen_ts to now_ts", "value": 12},
  {"name": "first_seen_ts", "value": 1747699200},
  {"name": "now_ts", "value": 1748736000},
  {"name": "$params.max_days_by_severity named by severity", "value": 10},
  {"name": "severity", "value": "medium"}
]
```

The vuln first seen after the scan has no age, so its first entry is `{"name": "days elapsed from first_seen_ts to now_ts", "value": null}`.

## How it differs from the original

- It gives the same `allow` as the original on 600 generated inputs with the beta limits and 600 with the prod ones, ages at, just under and just over each limit included.
- The original denies a vuln first seen after the scan, a severity the params don't have, or an `ignore_expires_exists` that isn't a boolean, but no violation names the vuln. Here each one fails with the vuln's id.
- The age is rounded down to 6 decimal places, so a vuln one second short of a day is `0.999988` days old. The original keeps every digit. The verdict is the same, because the limits are whole days.
- An unignored vuln with no `ignore_forever` fails, where the original never reads that field on an unignored vuln. Snyk's schema requires the field.
- There is no `vuln_reports`. The rows hold the age and the limit, but not the days left.
- `kosli evaluate input` takes one policy file, and this needs `ergo.rego` and the YAML next to it, so the workflows can't run it as it is.

## Tests

```sh
ergo/run_tests.sh
```

It runs the tests with the prod limits. They cover the cases in `../tests/test_rego_rules.sh`: day zero for a critical vuln, a vuln at its limit, an ignore that expires at the scan, a forever ignore, no vulns, no `vulns` key and no params.
