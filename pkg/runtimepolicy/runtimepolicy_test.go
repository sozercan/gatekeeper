/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package runtimepolicy

import (
	"context"
	"errors"
	"strings"
	"testing"

	constraintclient "github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/rego"
	regoschema "github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/rego/schema"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/reviews"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/target"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/util"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestValidateTemplateRejectsExecutableSources(t *testing.T) {
	template := runtimeTemplate()
	if handled, err := ValidateTemplate(template); !handled || err != nil {
		t.Fatalf("ValidateTemplate(valid) = handled %v, err %v", handled, err)
	}

	tests := []struct {
		name   string
		mutate func(*templates.ConstraintTemplate)
	}{
		{name: "rego", mutate: func(template *templates.ConstraintTemplate) {
			template.Spec.Targets[0].Code = nil
			template.Spec.Targets[0].Rego = "package runtime"
		}},
		{name: "cel", mutate: func(template *templates.ConstraintTemplate) {
			template.Spec.Targets[0].Code[0].Engine = "K8sNativeValidation"
		}},
		{name: "unknown source field", mutate: func(template *templates.ConstraintTemplate) {
			template.Spec.Targets[0].Code[0].Source = &templates.Anything{Value: map[string]interface{}{"version": SourceVersion, "rego": "deny"}}
		}},
		{name: "unsupported version", mutate: func(template *templates.ConstraintTemplate) {
			template.Spec.Targets[0].Code[0].Source = &templates.Anything{Value: map[string]interface{}{"version": "v2"}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := runtimeTemplate()
			test.mutate(candidate)
			handled, err := ValidateTemplate(candidate)
			if !handled || err == nil {
				t.Fatalf("ValidateTemplate() = handled %v, err %v; want handled error", handled, err)
			}
		})
	}
}

func TestRuntimeTargetCreatesConstraintCRD(t *testing.T) {
	driver := NewOfflineDriver()
	client, err := constraintclient.NewClient(
		constraintclient.Targets(&Target{}),
		constraintclient.Driver(driver),
		constraintclient.EnforcementPoints("gator.gatekeeper.sh"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.AddTemplate(context.Background(), runtimeTemplate()); err != nil {
		t.Fatalf("AddTemplate() error = %v", err)
	}
	if _, err := client.AddConstraint(context.Background(), runtimeConstraint("deny")); err != nil {
		t.Fatalf("AddConstraint() error = %v", err)
	}
}

func TestCombinedTemplateEvaluatesAdmissionAndAuditAndProjectsRuntime(t *testing.T) {
	ctx := context.Background()
	kube := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build()
	runtimeDriver := NewDriver(kube, kube)
	regoDriver, err := rego.New()
	if err != nil {
		t.Fatal(err)
	}
	client, err := constraintclient.NewClient(
		constraintclient.Targets(&target.K8sValidationTarget{}, &Target{}),
		constraintclient.Driver(regoDriver),
		constraintclient.Driver(runtimeDriver),
		constraintclient.EnforcementPoints(util.WebhookEnforcementPoint, util.AuditEnforcementPoint),
	)
	if err != nil {
		t.Fatal(err)
	}
	template := combinedRuntimeTemplate()
	if _, err := client.AddTemplate(ctx, template); err != nil {
		t.Fatalf("AddTemplate(combined) error = %v", err)
	}

	constraint := runtimeConstraint("deny")
	if err := unstructured.SetNestedMap(constraint.Object, map[string]interface{}{
		"kinds": []interface{}{map[string]interface{}{
			"apiGroups": []interface{}{string("")},
			"kinds":     []interface{}{"Pod"},
		}},
		"labelSelector": map[string]interface{}{
			"matchLabels": map[string]interface{}{"runtime-policy": "restricted"},
		},
		"excludedNamespaces": []interface{}{"kube-*"},
		"containerTypes":     []interface{}{"Application"},
	}, "spec", "match"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AddConstraint(ctx, constraint); err != nil {
		t.Fatalf("AddConstraint(combined) error = %v", err)
	}

	pod := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      "workload",
			"namespace": "production",
			"labels":    map[string]interface{}{"runtime-policy": "restricted"},
		},
	}}
	pod.SetGroupVersionKind(schema.GroupVersionKind{Version: "v1", Kind: "Pod"})
	for _, enforcementPoint := range []string{util.WebhookEnforcementPoint, util.AuditEnforcementPoint} {
		response, err := client.Review(ctx, pod, reviews.EnforcementPoint(enforcementPoint))
		if err != nil {
			t.Fatalf("Review(%s) error = %v", enforcementPoint, err)
		}
		if results := response.Results(); len(results) != 1 || results[0].Msg != "admission denied" {
			t.Fatalf("Review(%s) results = %#v", enforcementPoint, results)
		}
	}

	projection, handled, err := runtimeDriver.ReconcileConstraint(ctx, constraint)
	if err != nil || !handled || projection.State != ProjectionPending {
		t.Fatalf("ReconcileConstraint() = %#v, handled %v, err %v", projection, handled, err)
	}
	policy := RuntimePolicyWatchObject()
	if err := kube.Get(ctx, types.NamespacedName{Name: RuntimePolicyName(constraint)}, policy); err != nil {
		t.Fatal(err)
	}
	podSelector, found, err := unstructured.NestedStringMap(policy.Object, "spec", "match", "podSelector", "matchLabels")
	if err != nil || !found || podSelector["runtime-policy"] != "restricted" {
		t.Fatalf("projected pod selector = %v, found %v, err %v", podSelector, found, err)
	}
	if _, found, err := unstructured.NestedFieldNoCopy(policy.Object, "spec", "match", "kinds"); err != nil || found {
		t.Fatalf("admission-only kinds leaked into RuntimePolicy: found %v, err %v", found, err)
	}
}

func TestParseConstraintMapsEnforcementAndRejectsUnknownPolicyFields(t *testing.T) {
	constraint := runtimeConstraint("dryrun")
	parsed, err := ParseConstraint(constraint)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Mode != "Monitor" {
		t.Fatalf("mode = %q, want Monitor", parsed.Mode)
	}

	constraint = runtimeConstraint("warn")
	if _, err := ParseConstraint(constraint); err == nil || !strings.Contains(err.Error(), "no synchronous runtime-warning semantics") {
		t.Fatalf("ParseConstraint(warn) error = %v", err)
	}

	constraint = runtimeConstraint("deny")
	parameters, _, _ := unstructured.NestedMap(constraint.Object, "spec", "parameters")
	parameters["rego"] = "package hidden"
	_ = unstructured.SetNestedMap(constraint.Object, parameters, "spec", "parameters")
	if _, err := ParseConstraint(constraint); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("ParseConstraint(unknown field) error = %v", err)
	}
}

func TestValidateParametersRejectsUnsupportedRuntimeInputs(t *testing.T) {
	tests := []struct {
		name       string
		parameters Parameters
		want       string
	}{
		{
			name: "empty network protocols",
			parameters: Parameters{Behaviors: Behaviors{Network: &NetworkBehavior{Destinations: []NetworkDestinationRule{{
				CIDR: "203.0.113.10", Action: "Deny",
			}}}}},
			want: "must contain at least one protocol",
		},
		{
			name: "unqualified UDP",
			parameters: Parameters{Behaviors: Behaviors{Network: &NetworkBehavior{Destinations: []NetworkDestinationRule{{
				CIDR: "203.0.113.10", Protocols: []string{"UDP"}, Action: "Deny",
			}}}}},
			want: "UDP, which is not qualified",
		},
		{
			name: "noncanonical IPv6 destination",
			parameters: Parameters{Behaviors: Behaviors{Network: &NetworkBehavior{Destinations: []NetworkDestinationRule{{
				CIDR: "2001:0db8::1", Protocols: []string{"TCP"}, Action: "Deny",
			}}}}},
			want: "must be canonical",
		},
		{
			name: "wildcard domain",
			parameters: Parameters{Behaviors: Behaviors{Network: &NetworkBehavior{Domains: []DomainRule{{
				Name: "*.example.com", Protocols: []string{"TCP"}, Action: "Deny",
			}}}}},
			want: "wildcard domains are unsupported",
		},
		{
			name: "incomplete ConfigMap source",
			parameters: Parameters{
				Behaviors: Behaviors{Process: &ProcessBehavior{}},
				DynamicSources: []DynamicSource{{
					Name: "tools", OutputType: "Executable", Projection: DynamicProjection{Action: "Deny"}, ConfigMapRef: &ConfigMapKeyReference{},
				}},
			},
			want: "configMapRef.namespace",
		},
		{
			name: "executable source with path projection",
			parameters: Parameters{
				Behaviors: Behaviors{Process: &ProcessBehavior{}},
				DynamicSources: []DynamicSource{{
					Name: "tools", OutputType: "Executable", Projection: DynamicProjection{Action: "Deny", MatchType: "Exact"},
					ConfigMapRef: &ConfigMapKeyReference{Namespace: "runtime", Name: "tools", Key: "values"},
				}},
			},
			want: "accepts only action",
		},
		{
			name: "unknown CEL input",
			parameters: Parameters{
				Behaviors: Behaviors{Process: &ProcessBehavior{}},
				DynamicSources: []DynamicSource{{
					Name: "tools", OutputType: "Executable", Projection: DynamicProjection{Action: "Deny"},
					CEL: &CELSource{Expression: "inputs.missing", Inputs: []string{"missing"}},
				}},
			},
			want: "references unknown source",
		},
		{
			name: "CEL dependency cycle",
			parameters: Parameters{
				Behaviors: Behaviors{Process: &ProcessBehavior{}},
				DynamicSources: []DynamicSource{
					{Name: "first", OutputType: "Executable", Projection: DynamicProjection{Action: "Deny"}, CEL: &CELSource{Expression: "inputs.second", Inputs: []string{"second"}}},
					{Name: "second", OutputType: "Executable", Projection: DynamicProjection{Action: "Deny"}, CEL: &CELSource{Expression: "inputs.first", Inputs: []string{"first"}}},
				},
			},
			want: "CEL dependency cycle",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateParameters(runtimePolicyModeEnforce, &test.parameters)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateParameters() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestValidateParametersAcceptsBoundedDynamicSource(t *testing.T) {
	parameters := Parameters{
		Behaviors: Behaviors{File: &FileBehavior{}},
		DynamicSources: []DynamicSource{{
			Name: "protected-paths", OutputType: "Path",
			Projection:   DynamicProjection{Action: "Deny", MatchType: "Prefix", Access: []string{"Read", "Write"}},
			ConfigMapRef: &ConfigMapKeyReference{Namespace: "runtime", Name: "protected-paths", Key: "paths"},
		}},
	}
	if err := validateParameters(runtimePolicyModeEnforce, &parameters); err != nil {
		t.Fatalf("validateParameters() error = %v", err)
	}
}

func TestValidateParametersAcceptsDynamicSourcePortBudget(t *testing.T) {
	ports := make([]int32, 65)
	var port int32 = 1
	for i := range ports {
		ports[i] = port
		port++
	}
	parameters := Parameters{
		Behaviors: Behaviors{Network: &NetworkBehavior{}},
		DynamicSources: []DynamicSource{{
			Name: "service-ranges", OutputType: "CIDR",
			Projection:   DynamicProjection{Action: "Deny", Ports: ports, Protocols: []string{"TCP"}},
			ConfigMapRef: &ConfigMapKeyReference{Namespace: "runtime", Name: "service-ranges", Key: "cidrs"},
		}},
	}
	if err := validateParameters(runtimePolicyModeEnforce, &parameters); err != nil {
		t.Fatalf("validateParameters() error = %v", err)
	}
}

func TestDriverProjectsUpdatesReportsAndDeletesRuntimePolicy(t *testing.T) {
	ctx := context.Background()
	kube := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build()
	driver := NewDriver(kube, kube)
	template := runtimeTemplate()
	constraint := runtimeConstraint("deny")
	if err := driver.AddTemplate(ctx, template); err != nil {
		t.Fatal(err)
	}
	if err := driver.AddConstraint(ctx, constraint); err != nil {
		t.Fatal(err)
	}

	projection, handled, err := driver.ReconcileConstraint(ctx, constraint)
	if err != nil || !handled || projection.State != ProjectionPending {
		t.Fatalf("ReconcileConstraint(create) = %#v, handled %v, err %v", projection, handled, err)
	}
	policy := RuntimePolicyWatchObject()
	if err := kube.Get(ctx, types.NamespacedName{Name: RuntimePolicyName(constraint)}, policy); err != nil {
		t.Fatalf("get projected policy: %v", err)
	}
	if got, _, _ := unstructured.NestedString(policy.Object, "spec", "mode"); got != runtimePolicyModeEnforce {
		t.Fatalf("projected mode = %q, want Enforce", got)
	}
	if got := policy.GetOwnerReferences(); len(got) != 1 || got[0].UID != constraint.GetUID() {
		t.Fatalf("owner references = %#v", got)
	}

	policy.SetGeneration(2)
	_ = unstructured.SetNestedField(policy.Object, int64(2), "status", "observedGeneration")
	_ = unstructured.SetNestedSlice(policy.Object, []interface{}{
		map[string]interface{}{"type": "Accepted", "status": "True"},
		map[string]interface{}{"type": "Compiled", "status": "True"},
		map[string]interface{}{"type": "Active", "status": "True", "message": "active on all selected nodes"},
	}, "status", "conditions")
	if err := kube.Update(ctx, policy); err != nil {
		t.Fatalf("update status fixture: %v", err)
	}
	projection, handled, err = driver.ReconcileConstraint(ctx, constraint)
	if err != nil || !handled || projection.State != ProjectionActive {
		t.Fatalf("ReconcileConstraint(active) = %#v, handled %v, err %v", projection, handled, err)
	}

	parameters, found, err := unstructured.NestedMap(constraint.Object, "spec", "parameters")
	if err != nil || !found {
		t.Fatalf("get constraint parameters: found %v, err %v", found, err)
	}
	behaviors, ok := parameters["behaviors"].(map[string]interface{})
	if !ok {
		t.Fatalf("constraint behaviors = %#v", parameters["behaviors"])
	}
	process, ok := behaviors["process"].(map[string]interface{})
	if !ok {
		t.Fatalf("constraint process behavior = %#v", behaviors["process"])
	}
	process["executables"] = []interface{}{map[string]interface{}{"path": "/usr/bin/bash", "action": "Allow"}}
	if err := unstructured.SetNestedMap(constraint.Object, parameters, "spec", "parameters"); err != nil {
		t.Fatal(err)
	}
	if err := driver.AddConstraint(ctx, constraint); err != nil {
		t.Fatal(err)
	}
	projection, _, err = driver.ReconcileConstraint(ctx, constraint)
	if err != nil || projection.State != ProjectionPending {
		t.Fatalf("ReconcileConstraint(update) = %#v, err %v", projection, err)
	}
	if err := kube.Get(ctx, types.NamespacedName{Name: RuntimePolicyName(constraint)}, policy); err != nil {
		t.Fatal(err)
	}
	path, _, _ := unstructured.NestedString(policy.Object, "spec", "behaviors", "process", "executables", "0", "path")
	if path != "" {
		t.Fatalf("unexpected string-index path lookup result %q", path)
	}
	executables, found, err := unstructured.NestedSlice(policy.Object, "spec", "behaviors", "process", "executables")
	if err != nil || !found || len(executables) != 1 {
		t.Fatalf("updated executables = %#v, found %v, err %v", executables, found, err)
	}
	executable, ok := executables[0].(map[string]interface{})
	if !ok || executable["path"] != "/usr/bin/bash" {
		t.Fatalf("updated executables = %#v", executables)
	}

	if err := driver.RemoveConstraint(ctx, constraint); err != nil {
		t.Fatal(err)
	}
	if err := kube.Get(ctx, types.NamespacedName{Name: RuntimePolicyName(constraint)}, RuntimePolicyWatchObject()); !apierrors.IsNotFound(err) {
		t.Fatalf("get deleted RuntimePolicy error = %v", err)
	}
}

func TestDriverRefreshConfigUpdatesProjectedExclusions(t *testing.T) {
	ctx := context.Background()
	kube := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build()
	exclusions := []string{"kube-*"}
	driver := NewDriver(kube, kube, func() []string { return exclusions })
	constraint := runtimeConstraint("deny")
	if err := driver.AddTemplate(ctx, runtimeTemplate()); err != nil {
		t.Fatal(err)
	}
	if err := driver.AddConstraint(ctx, constraint); err != nil {
		t.Fatal(err)
	}
	if _, _, err := driver.ReconcileConstraint(ctx, constraint); err != nil {
		t.Fatal(err)
	}

	assertExclusions := func(want ...string) {
		t.Helper()
		policy := RuntimePolicyWatchObject()
		if err := kube.Get(ctx, types.NamespacedName{Name: RuntimePolicyName(constraint)}, policy); err != nil {
			t.Fatal(err)
		}
		got, found, err := unstructured.NestedStringSlice(policy.Object, "spec", "match", "excludedNamespaces")
		if err != nil || !found {
			t.Fatalf("projected exclusions = %v, found %v, err %v", got, found, err)
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("projected exclusions = %v, want %v", got, want)
		}
	}
	assertExclusions("kube-*")

	exclusions = []string{"gatekeeper-system", "kube-*"}
	if err := driver.RefreshConfig(ctx); err != nil {
		t.Fatal(err)
	}
	assertExclusions("gatekeeper-system", "kube-*")
}

func TestDriverDeletesRuntimePolicyFromUIDLessTombstone(t *testing.T) {
	ctx := context.Background()
	kube := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build()
	driver := NewDriver(kube, kube)
	constraint := runtimeConstraint("deny")
	if err := driver.AddTemplate(ctx, runtimeTemplate()); err != nil {
		t.Fatal(err)
	}
	if err := driver.AddConstraint(ctx, constraint); err != nil {
		t.Fatal(err)
	}
	if _, _, err := driver.ReconcileConstraint(ctx, constraint); err != nil {
		t.Fatal(err)
	}

	tombstone := &unstructured.Unstructured{}
	tombstone.SetGroupVersionKind(constraint.GroupVersionKind())
	tombstone.SetName(constraint.GetName())
	if err := driver.RemoveConstraint(ctx, tombstone); err != nil {
		t.Fatalf("RemoveConstraint(tombstone) error = %v", err)
	}
	if err := kube.Get(ctx, types.NamespacedName{Name: RuntimePolicyName(constraint)}, RuntimePolicyWatchObject()); !apierrors.IsNotFound(err) {
		t.Fatalf("get deleted RuntimePolicy error = %v", err)
	}
}

func TestRuntimePolicyNameIsStableAndBounded(t *testing.T) {
	constraint := runtimeConstraint("deny")
	constraint.SetName(strings.Repeat("a", 253))
	first := RuntimePolicyName(constraint)
	second := RuntimePolicyName(constraint.DeepCopy())
	if first != second || len(first) > 253 {
		t.Fatalf("RuntimePolicyName() = %q / %q (length %d)", first, second, len(first))
	}
}

func TestRuntimePolicyStatusIgnoresStaleRejectedGeneration(t *testing.T) {
	policy := RuntimePolicyWatchObject()
	policy.SetName("runtime-process")
	policy.SetGeneration(2)
	_ = unstructured.SetNestedField(policy.Object, int64(1), "status", "observedGeneration")
	_ = unstructured.SetNestedSlice(policy.Object, []interface{}{
		map[string]interface{}{"type": "Accepted", "status": "False", "reason": "InvalidPath", "message": "old generation failed"},
	}, "status", "conditions")

	if got := runtimePolicyStatus(policy); got.State != ProjectionPending {
		t.Fatalf("runtimePolicyStatus(stale) = %#v, want Pending", got)
	}
	_ = unstructured.SetNestedField(policy.Object, int64(2), "status", "observedGeneration")
	if got := runtimePolicyStatus(policy); got.State != ProjectionError || !strings.Contains(got.Message, "old generation failed") {
		t.Fatalf("runtimePolicyStatus(current) = %#v, want current-generation Error", got)
	}
}

func TestDriverTreatsConcurrentRuntimePolicyCreateAsIdempotent(t *testing.T) {
	ctx := context.Background()
	constraint := runtimeConstraint("deny")
	desired, err := buildRuntimePolicy(constraint)
	if err != nil {
		t.Fatal(err)
	}
	kube := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).WithObjects(desired).Build()
	reader := &notFoundOnceReader{Reader: kube}
	driver := NewDriver(kube, reader)
	if err := driver.AddTemplate(ctx, runtimeTemplate()); err != nil {
		t.Fatal(err)
	}
	if err := driver.AddConstraint(ctx, constraint); err != nil {
		t.Fatal(err)
	}

	projection, handled, err := driver.ReconcileConstraint(ctx, constraint)
	if err != nil || !handled || projection.State != ProjectionPending {
		t.Fatalf("ReconcileConstraint(concurrent create) = %#v, handled %v, err %v", projection, handled, err)
	}
}

type notFoundOnceReader struct {
	client.Reader
	returnedNotFound bool
}

func (r *notFoundOnceReader) Get(ctx context.Context, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
	if !r.returnedNotFound {
		r.returnedNotFound = true
		return apierrors.NewNotFound(schema.GroupResource{Group: "runtime.gatekeeper.sh", Resource: "runtimepolicies"}, key.Name)
	}
	return r.Reader.Get(ctx, key, object, options...)
}

func runtimeTemplate() *templates.ConstraintTemplate {
	return &templates.ConstraintTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "runtimeprocess"},
		Spec: templates.ConstraintTemplateSpec{
			CRD: templates.CRD{Spec: templates.CRDSpec{
				Names: templates.Names{Kind: "RuntimeProcess"},
				Validation: &templates.Validation{OpenAPIV3Schema: &apiextensions.JSONSchemaProps{
					Type: "object",
					Properties: map[string]apiextensions.JSONSchemaProps{
						"failurePolicy": {Type: "string"},
						"behaviors":     {Type: "object", XPreserveUnknownFields: boolPtr(true)},
					},
				}},
			}},
			Targets: []templates.Target{{
				Target: TargetName,
				Code: []templates.Code{{
					Engine: EngineName,
					Source: &templates.Anything{Value: map[string]interface{}{"version": SourceVersion}},
				}},
			}},
		},
	}
}

func combinedRuntimeTemplate() *templates.ConstraintTemplate {
	template := runtimeTemplate()
	admission := templates.Target{
		Target: target.Name,
		Code: []templates.Code{{
			Engine: regoschema.Name,
			Source: &templates.Anything{Value: (&regoschema.Source{
				Version: "v1",
				Rego: `package runtimeprocess

violation contains {"msg": "admission denied"} if {
	input.review.kind.kind == "Pod"
}`,
			}).ToUnstructured()},
		}},
	}
	template.Spec.Targets = append([]templates.Target{admission}, template.Spec.Targets...)
	return template
}

func runtimeConstraint(enforcementAction string) *unstructured.Unstructured {
	constraint := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "constraints.gatekeeper.sh/v1beta1",
		"kind":       "RuntimeProcess",
		"metadata": map[string]interface{}{
			"name": "shell-policy",
		},
		"spec": map[string]interface{}{
			"enforcementAction": enforcementAction,
			"match": map[string]interface{}{
				"namespaceSelector": map[string]interface{}{"matchLabels": map[string]interface{}{"environment": "production"}},
				"containerTypes":    []interface{}{"Application"},
			},
			"parameters": map[string]interface{}{
				"failurePolicy": "FailOpen",
				"behaviors": map[string]interface{}{
					"process": map[string]interface{}{
						"defaultAction": "Deny",
						"executables": []interface{}{
							map[string]interface{}{"path": "/bin/sh", "action": "Allow"},
						},
					},
				},
			},
		},
	}}
	constraint.SetGroupVersionKind(schema.GroupVersionKind{Group: "constraints.gatekeeper.sh", Version: "v1beta1", Kind: "RuntimeProcess"})
	constraint.SetUID(types.UID("constraint-uid"))
	return constraint
}

func boolPtr(value bool) *bool { return &value }

func TestProjectionCollisionFailsClosed(t *testing.T) {
	ctx := context.Background()
	constraint := runtimeConstraint("deny")
	collision := RuntimePolicyWatchObject()
	collision.SetName(RuntimePolicyName(constraint))
	collision.Object["spec"] = map[string]interface{}{"mode": "Monitor"}
	kube := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).WithObjects(collision).Build()
	driver := NewDriver(kube, kube)
	if err := driver.AddTemplate(ctx, runtimeTemplate()); err != nil {
		t.Fatal(err)
	}
	if err := driver.AddConstraint(ctx, constraint); err != nil {
		t.Fatal(err)
	}
	_, handled, err := driver.ReconcileConstraint(ctx, constraint)
	if !handled || err == nil {
		t.Fatalf("ReconcileConstraint(collision) = handled %v, err %v", handled, err)
	}
	if !errors.Is(err, ErrInvalidRuntimeConstraint) && !strings.Contains(err.Error(), "not managed") {
		t.Fatalf("collision error = %v", err)
	}
}

func TestProjectionCollisionRejectsSpoofedSourceAnnotations(t *testing.T) {
	ctx := context.Background()
	constraint := runtimeConstraint("deny")
	collision, err := buildRuntimePolicy(constraint)
	if err != nil {
		t.Fatal(err)
	}
	collision.SetOwnerReferences(nil)
	kube := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).WithObjects(collision).Build()
	driver := NewDriver(kube, kube)
	if err := driver.AddTemplate(ctx, runtimeTemplate()); err != nil {
		t.Fatal(err)
	}
	if err := driver.AddConstraint(ctx, constraint); err != nil {
		t.Fatal(err)
	}

	_, handled, err := driver.ReconcileConstraint(ctx, constraint)
	if !handled || err == nil || !strings.Contains(err.Error(), "not managed") {
		t.Fatalf("ReconcileConstraint(spoofed ownership) = handled %v, err %v", handled, err)
	}
}
