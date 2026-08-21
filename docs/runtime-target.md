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

## Template contract

A ConstraintTemplate may be runtime-only or may combine the normal admission
target with the runtime target. Each target keeps its own code block and
lifecycle. The runtime target must use exactly this non-executable source:

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

In a combined template, `admission.k8s.gatekeeper.sh` Rego/CEL is evaluated for
admission and audit, while `runtime.gatekeeper.sh` is projected to a
`RuntimePolicy`. Gatekeeper never runs runtime policy evaluation in an admission
request or audit loop, and it never treats admission Rego as kernel policy.

Constraint parameters use the `RuntimePolicy.spec` fields other than `mode` and
`match`:

- `match` comes from `Constraint.spec.match` and supports namespace selectors,
  pod selectors, and application/init/ephemeral container types.
- `mode` comes from Gatekeeper semantics: `deny` becomes `Enforce`, and `dryrun`
  becomes `Monitor`.
- `warn` is rejected because runtime enforcement cannot return a synchronous
  admission warning. Scoped enforcement actions are not supported by this
  single-target contract.
- `failurePolicy`, `behaviors`, `dynamicSources`, `staleDataPolicy`, and
  `resourceLimits` are passed through after strict structural and bounded
  semantic validation.

See [the example template](../example/runtime/constrainttemplate.yaml) and
[constraint](../example/runtime/constraint.yaml). The
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
`Pending`, `Active`, or `Error`, while the RuntimePolicy remains the detailed
source of compiler, distribution, node activation, and enforcement status.

Updating a Constraint updates its RuntimePolicy. Deleting the Constraint or its
template deletes the projected policy; the runtime controller's finalizer still
controls safe policy withdrawal from nodes.

## Gatekeeper Config exclusions

The runtime projection consumes Gatekeeper `Config.spec.match` entries whose
`processes` include `runtime` or `*`. Matching namespace exclusions are merged
with the Constraint's own `excludedNamespaces` before Gatekeeper writes the
RuntimePolicy. Config reconciliation immediately refreshes existing projections,
so the standalone runtime controller and agents do not need permission to read
Gatekeeper Config resources.

## Connection export

When the runtime target is enabled, Gatekeeper exposes
`POST /v1/export/runtime/{connection}` on its existing TLS webhook service. The
endpoint authenticates the caller with TokenReview, authorizes `create` on the
exact non-resource URL with SubjectAccessReview, validates the bounded
`RuntimeFindingBatch`, and publishes each finding through the initialized
Connection driver.

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

The runtime agent reads Gatekeeper's serving CA from the configured
`ValidatingWebhookConfiguration`, uses its rotating service-account token, and
requires only `create` on `/v1/export/runtime/*`. Add `runtime-connection` to
`RuntimeConfig/cluster.spec.exports.connections`. Delivery is bounded,
at-least-once, and independent of kernel enforcement health.

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
