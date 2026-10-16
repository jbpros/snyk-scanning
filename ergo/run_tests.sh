#!/usr/bin/env bash
set -Eeu

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"

opa check --strict "${my_dir}/ergo.rego" "${my_dir}/snyk-vuln-compliance.rego" "${my_dir}/snyk-vuln-compliance_test.rego"
opa test --timeout 120s \
  "${my_dir}/ergo.rego" \
  "${my_dir}/snyk-vuln-compliance.rego" \
  "${my_dir}/snyk-vuln-compliance.yaml" \
  "${my_dir}/snyk-vuln-compliance_test.rego" \
  "params:${my_dir}/../rego.params.aws-prod.json"
