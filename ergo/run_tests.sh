#!/usr/bin/env bash
set -Eeu

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"

opa check --strict "${my_dir}/ergo.rego" "${my_dir}/snyk-vuln-compliance.rego" "${my_dir}/snyk-vuln-compliance_test.rego"
for env in aws-beta aws-prod; do
  opa eval --format raw \
    -d "params:${my_dir}/rego.params.${env}.json" \
    'object.keys(data.params.max_seconds_by_severity) == {"critical", "high", "medium", "low"}' \
    | grep -qx true || { echo "rego.params.${env}.json needs a limit for each of critical, high, medium and low"; exit 1; }
done
opa test --timeout 120s \
  "${my_dir}/ergo.rego" \
  "${my_dir}/snyk-vuln-compliance.rego" \
  "${my_dir}/snyk-vuln-compliance.yaml" \
  "${my_dir}/snyk-vuln-compliance_test.rego" \
  "params:${my_dir}/rego.params.aws-prod.json"
