# Gatekeeper Runtime ConstraintTemplate target

Gatekeeper can project a bounded, declarative Constraint into the standalone
Gatekeeper Runtime API. It does not execute Rego or CEL in a kernel hook and it
does not add kernel privileges, host mounts, or BPF access to Gatekeeper pods.

## Prerequisites and enablement

Install the Gatekeeper Runtime CRDs, controller, and node agents separately.
The integration is disabled by default in Gatekeeper.

With Helm:

```sh
helm upgrade --install gatekeeper ./charts/gatekeeper \
  --namespace gatekeeper-system --create-namespace \
  --set enableRuntimeTarget=true
```

With the repository Kustomize manifests:

```sh
kubectl apply -k config/runtime-target
```

Both paths add `--enable-runtime-target=true`, RuntimePolicy projection RBAC,
and the TokenReview/SubjectAccessReview permissions used by the authenticated
runtime export endpoint. Disabling the feature leaves Gatekeeper's default
target set and mutation permissions unchanged.

An isolated Gatekeeper runtime-target deployment can use the built-in
certificate rotator without sharing the primary Gatekeeper TLS Secret. Set
`--cert-secret-name`, `--cert-service-name`, and
`--validating-webhook-configuration-name` to the isolated deployment's Secret,
Service, and `ValidatingWebhookConfiguration`, and mount that same Secret at
`--cert-dir`. Its service account must be allowed to manage that Secret and to
`get`, `patch`, and `update` only the named
`ValidatingWebhookConfiguration`; the default Gatekeeper role is intentionally
restricted to Gatekeeper's primary webhook configuration.

## Template contract

A runtime ConstraintTemplate must use only the runtime target. Frameworks
currently shares one `spec.match` across targets, so combining the normalized
runtime subject with the Kubernetes admission target could broaden admission
matching. The runtime target must use exactly this non-executable source:

```yaml
targets:
- target: runtime.gatekeeper.sh
  code:
  - engine: Runtime
    source:
      version: v1alpha1
```

Rego, CEL, libraries, admission operations, additional code blocks, unknown
source fields, and unsupported source versions are rejected. The template must
also provide an OpenAPI object schema for its parameters.

Gatekeeper projects `v1alpha1` sources to
`runtime.gatekeeper.sh/v1alpha1` `RuntimePolicy` resources. Gatekeeper never runs
runtime policy evaluation in an admission request or audit loop.

Constraint parameters use the `RuntimePolicy.spec` fields other than `mode` and
`subject`:

- `subject` comes from `Constraint.spec.match.subject`.
- `mode` comes from Gatekeeper semantics: `deny` becomes `Enforce`, and `dryrun`
  becomes `Monitor`.
- `warn` is rejected because runtime enforcement cannot return a synchronous
  admission warning. Scoped enforcement actions are not supported by this
  single-target contract.
- `failurePolicy`, `behaviors`, `monitorFilter`, `dynamicSources`,
  `staleDataPolicy`, and `resourceLimits` are passed through after structural
  and bounded semantic validation.

For source version `v1alpha1`, `Constraint.spec.match` must contain only
`subject`. Exactly one subject kind is required:

- `kubernetes` supports namespace and Pod selectors, excluded namespaces,
  RuntimeClass names, container types, and optional container names. Gatekeeper
  Config exclusions are merged only into this subject.
- `substrate` supports bounded lowercase Atespace names or trailing patterns
  such as `team-*`, ActorTemplate identity and trusted-label selectors, sandbox
  classes, and optional container names. A bare wildcard, interior wildcard,
  Unicode, uppercase, mixed subject kinds, unknown fields, and empty subjects
  are rejected.

See [the example template](../example/runtime/constrainttemplate.yaml) and
[constraint](../example/runtime/constraint.yaml). The
[Substrate template](../example/runtime/constrainttemplate-substrate.yaml) and
[constraint](../example/runtime/constraint-substrate.yaml) show the Atespace
subject contract. The
[runtime-only Connection example](../example/runtime/connection.yaml) shows the
producer-side export configuration.

## Lifecycle and status

For every accepted runtime Constraint, Gatekeeper creates one deterministic,
cluster-scoped `runtime.gatekeeper.sh/v1alpha1` `RuntimePolicy`. The policy has a
controller owner reference to the Constraint and source-identity annotations.
Gatekeeper refuses to overwrite a same-named object that it does not own.

Projection is reconciled on every Constraint reconciliation, so a temporary API
failure is retried even after the constraint framework has cached the
Constraint. RuntimePolicy status changes requeue the owning Constraint. The
Constraint pod status exposes the `runtime.gatekeeper.sh` enforcement point as
`Pending`, `Projected`, or `Error`. `Projected` means Gatekeeper wrote the
authoring handoff. It does not mean the policy compiled, reached a node, or
activated for a workload. Gatekeeper Runtime owns those states, and Pod or
Actor conditions own workload readiness.

Updating a Constraint updates its RuntimePolicy. Deleting the Constraint or its
template deletes the projected policy; the runtime controller's finalizer still
controls safe policy withdrawal from nodes.

## Gatekeeper Config exclusions

The runtime projection consumes Gatekeeper `Config.spec.match` entries whose
`processes` include `runtime` or `*`. Matching namespace exclusions are merged
with a Kubernetes subject before Gatekeeper writes the RuntimePolicy. They never
apply to Substrate Atespaces. Config
reconciliation immediately refreshes existing projections, so the standalone
runtime controller and agents do not need permission to read Gatekeeper Config
resources.

## Connection export

Enable `--enable-runtime-violation-export=true` on the controller-manager to
accept findings from Gatekeeper Runtime, including directly authored
RuntimePolicies. With Helm, set `enableRuntimeViolationExport=true`. This
option does not require the runtime ConstraintTemplate target or grant
RuntimePolicy projection permissions. Enabling `--enable-runtime-target=true`
continues to enable runtime export as well.

Gatekeeper exposes `POST /v1/export/runtime/{connection}` on its existing TLS
webhook service. The endpoint authenticates the caller with TokenReview,
authorizes `create` on the exact non-resource URL with SubjectAccessReview,
validates the bounded `RuntimeFindingBatch`, and publishes each finding
through the initialized Connection driver.

Runtime export requires a dedicated Connection with exactly `sources:
[runtime]`; sharing an audit/webhook Connection is rejected. For example:

```yaml
apiVersion: connection.gatekeeper.sh/v1alpha1
kind: Connection
metadata:
  name: runtime-connection
  namespace: gatekeeper-system
spec:
  driver: disk
  sources: [runtime]
  config:
    path: /tmp/violations/topics
    maxAuditResults: 3
```

For the disk driver, mount a writable volume at `/tmp/violations` in the
controller-manager. The [export-only Helm values](../example/runtime/export-values.yaml)
enable the endpoint and add an `emptyDir` volume for testing. Records go to the
`runtime` topic directory as JSONL. Use persistent storage or a log collector
when records must outlive the pod. For Dapr, configure its sidecar and pubsub
component on the controller-manager and use `driver: dapr` with
`config.component`; the topic is `runtime`.

The Helm chart grants the controller-manager `create` on TokenReviews and
SubjectAccessReviews whenever runtime export is enabled. Install equivalent
RBAC when configuring the flag without Helm.

On managed Kubernetes distributions that own an older Gatekeeper Connection
CRD and prune `spec.sources`, annotate the otherwise dedicated Connection with
`runtime.gatekeeper.sh/connection-source: runtime`. The annotation is a
fail-closed compatibility fallback: Gatekeeper considers it only when
`spec.sources` is absent, and any explicit source list remains authoritative.

The runtime agent reads Gatekeeper's serving CA from the configured
`ValidatingWebhookConfiguration`, uses its rotating service-account token, and
requires only `create` on `/v1/export/runtime/*`. Add the Connection name to the
existing `RuntimeConfig/cluster`:

```yaml
spec:
  exports:
    connections:
      - runtime-connection
```

Delivery uses bounded queues and retries independently of kernel enforcement.
Retries can duplicate findings after a partial backend failure, and exhausted
queues or retries can lose findings. Consumers must tolerate duplicate records.

After installing the export-only Helm values in a disposable cluster, verify
delivery and producer authorization with:

```sh
make test-e2e BATS_TESTS_FILE=test/bats/runtime-export.bats
```

## Coexistence with native RuntimePolicy

Projected policies and user-created RuntimePolicy resources are independent
inputs to the same runtime compiler and composition engine. Neither API
silently overrides the other. Their applicable rules compose using Gatekeeper
Runtime's normal specificity and deny-wins rules. Migration is explicit: create
and validate the destination object, then delete the source object after node
activation is healthy.

## Offline validation

Gator registers the same runtime target and Runtime driver. Commands that load
templates and constraints therefore perform the same source, match, parameter,
and CRD validation without a cluster. Gator does not claim to evaluate runtime
constraints against admission-review objects; kernel compilation and node
activation remain responsibilities of the separate Gatekeeper Runtime system.
