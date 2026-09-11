#!/usr/bin/env bats

setup() {
  export GATEKEEPER_NAMESPACE=${GATEKEEPER_NAMESPACE:-gatekeeper-system}
  export RUNTIME_EXPORT_NAME="runtime-export-e2e-$$"
  export RUNTIME_EXPORT_SERVICE="gatekeeper-webhook-service.${GATEKEEPER_NAMESPACE}.svc"
  export RUNTIME_EXPORT_AUTH="${BATS_TEST_TMPDIR}/curl.conf"
  export RUNTIME_EXPORT_CA="${BATS_TEST_TMPDIR}/ca.pem"
  export RUNTIME_EXPORT_RESPONSE="${BATS_TEST_TMPDIR}/response"

  kubectl get deployment gatekeeper-controller-manager -n "${GATEKEEPER_NAMESPACE}" -o json |
    jq -e '.spec.template.spec.containers[] | select(.name == "manager") | .args |
      index("--enable-runtime-violation-export=true") != null and
      index("--enable-runtime-target=false") != null'

  kubectl create -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${RUNTIME_EXPORT_NAME}
  namespace: ${GATEKEEPER_NAMESPACE}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ${RUNTIME_EXPORT_NAME}
rules:
- nonResourceURLs: ["/v1/export/runtime/${RUNTIME_EXPORT_NAME}"]
  verbs: [create]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ${RUNTIME_EXPORT_NAME}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: ${RUNTIME_EXPORT_NAME}
subjects:
- kind: ServiceAccount
  name: ${RUNTIME_EXPORT_NAME}
  namespace: ${GATEKEEPER_NAMESPACE}
---
apiVersion: connection.gatekeeper.sh/v1alpha1
kind: Connection
metadata:
  name: ${RUNTIME_EXPORT_NAME}
  namespace: ${GATEKEEPER_NAMESPACE}
spec:
  driver: disk
  sources: [runtime]
  config:
    path: /tmp/violations/topics/${RUNTIME_EXPORT_NAME}
    maxAuditResults: 3
EOF

  umask 077
  kubectl create token "${RUNTIME_EXPORT_NAME}" -n "${GATEKEEPER_NAMESPACE}" --duration=10m > "${BATS_TEST_TMPDIR}/token"
  printf 'header = "Authorization: Bearer %s"\n' "$(cat "${BATS_TEST_TMPDIR}/token")" > "${RUNTIME_EXPORT_AUTH}"
  kubectl get validatingwebhookconfiguration gatekeeper-validating-webhook-configuration -o json |
    jq -er '.webhooks[0].clientConfig.caBundle | select(length > 0) | @base64d' > "${RUNTIME_EXPORT_CA}"

  kubectl port-forward -n "${GATEKEEPER_NAMESPACE}" --address=127.0.0.1 service/gatekeeper-webhook-service :443 > "${BATS_TEST_TMPDIR}/port-forward.log" 2>&1 &
  export RUNTIME_EXPORT_FORWARD_PID=$!
  for _ in {1..30}; do
    RUNTIME_EXPORT_PORT=$(awk '/Forwarding from/ { split($3, address, ":"); print address[2]; exit }' "${BATS_TEST_TMPDIR}/port-forward.log")
    if [[ -n "${RUNTIME_EXPORT_PORT}" ]]; then
      export RUNTIME_EXPORT_PORT
      return 0
    fi
    sleep 1
  done
  cat "${BATS_TEST_TMPDIR}/port-forward.log"
  return 1
}

teardown() {
  if [[ -n "${RUNTIME_EXPORT_FORWARD_PID:-}" ]]; then
    kill "${RUNTIME_EXPORT_FORWARD_PID}" 2>/dev/null || true
    wait "${RUNTIME_EXPORT_FORWARD_PID}" 2>/dev/null || true
  fi
  if [[ -n "${RUNTIME_EXPORT_NAME:-}" ]]; then
    kubectl delete connection,serviceaccount "${RUNTIME_EXPORT_NAME}" -n "${GATEKEEPER_NAMESPACE}" --ignore-not-found
    kubectl delete clusterrole,clusterrolebinding "${RUNTIME_EXPORT_NAME}" --ignore-not-found
  fi
}

runtime_export_request() {
  local authorization=${1:-${RUNTIME_EXPORT_AUTH}}
  local connection=${2:-${RUNTIME_EXPORT_NAME}}
  curl --silent --show-error --max-time 15 --noproxy '*' \
    --cacert "${RUNTIME_EXPORT_CA}" \
    --connect-to "${RUNTIME_EXPORT_SERVICE}:443:127.0.0.1:${RUNTIME_EXPORT_PORT}" \
    --config "${authorization}" --header 'Content-Type: application/json' \
    --data-binary @test/export/runtime-finding-batch.json \
    --output "${RUNTIME_EXPORT_RESPONSE}" --write-out '%{http_code}' \
    "https://${RUNTIME_EXPORT_SERVICE}/v1/export/runtime/${connection}"
}

@test "standalone runtime export authenticates and authorizes a dedicated Connection" {
  for _ in {1..30}; do
    run runtime_export_request
    if [[ "$status" -eq 0 && "$output" == "202" ]]; then
      break
    fi
    sleep 1
  done
  if [[ "$status" -ne 0 || "$output" != "202" ]]; then
    printf 'Expected HTTP 202, received: %s\n' "$output"
    cat "${RUNTIME_EXPORT_RESPONSE}"
    return 1
  fi

  run runtime_export_request /dev/null
  [[ "$status" -eq 0 && "$output" == "401" ]]

  run runtime_export_request "${RUNTIME_EXPORT_AUTH}" "${RUNTIME_EXPORT_NAME}-forbidden"
  [[ "$status" -eq 0 && "$output" == "403" ]]

  kubectl patch connection "${RUNTIME_EXPORT_NAME}" -n "${GATEKEEPER_NAMESPACE}" \
    --type=merge --patch '{"spec":{"sources":["audit"]}}'
  run runtime_export_request
  [[ "$status" -eq 0 && "$output" == "403" ]]
}
