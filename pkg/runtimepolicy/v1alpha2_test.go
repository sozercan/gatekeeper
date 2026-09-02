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
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	constraintclient "github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	actorTemplateLabelsProperty    = "actorTemplateLabels"
	actorTemplateNamespaceProperty = "namespace"
	actorTemplateProperty          = "actorTemplate"
	atespacePatternsProperty       = "atespacePatterns"
	containerNamesProperty         = "containerNames"
	generationProperty             = "generation"
	kubernetesSubjectProperty      = "kubernetes"
	matchLabelsProperty            = "matchLabels"
	runtimeClassNamesProperty      = "runtimeClassNames"
	sourceVersionProperty          = "version"
	subjectProperty                = "subject"
	substrateSubjectProperty       = "substrate"
	testActorTemplateName          = "agent"
	testActorTemplateNamespace     = "templates"
	testAtespacePattern            = "team-*"
	testApplicationContainerType   = "Application"
	testConfiguredExclusion        = "kube-*"
	testContainerName              = "main"
	testEnvironment                = "production"
	testRuntimeClassName           = "gatekeeper-runtime"
)

func TestV1Alpha2RuntimeTargetCreatesConstraintCRD(t *testing.T) {
	driver := NewOfflineDriver()
	client, err := constraintclient.NewClient(
		constraintclient.Targets(NewTarget(driver)),
		constraintclient.Driver(driver),
		constraintclient.EnforcementPoints("gator.gatekeeper.sh"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.AddTemplate(context.Background(), runtimeTemplateV1Alpha2()); err != nil {
		t.Fatalf("AddTemplate() error = %v", err)
	}
	constraint := runtimeConstraintV1Alpha2(map[string]interface{}{
		kubernetesSubjectProperty: map[string]interface{}{containerNamesProperty: []interface{}{testContainerName}},
	})
	if _, err := client.AddConstraint(context.Background(), constraint); err != nil {
		t.Fatalf("AddConstraint() error = %v", err)
	}
}

func TestV1Alpha2TemplateIsFleetGatedAndRuntimeOnly(t *testing.T) {
	template := runtimeTemplateV1Alpha2()
	if handled, err := ValidateTemplate(template); !handled || err != nil {
		t.Fatalf("ValidateTemplate(runtime-only) = handled %v, err %v", handled, err)
	}

	for _, runtimeFirst := range []bool{false, true} {
		combined := combinedRuntimeTemplate()
		combined.Spec.Targets[1].Code[0].Source = &templates.Anything{Value: map[string]interface{}{sourceVersionProperty: SubjectSourceVersion}}
		if runtimeFirst {
			combined.Spec.Targets[0], combined.Spec.Targets[1] = combined.Spec.Targets[1], combined.Spec.Targets[0]
		}
		handled, err := ValidateTemplate(combined)
		if !handled || err == nil || !strings.Contains(err.Error(), "runtime-only") {
			t.Fatalf("ValidateTemplate(combined, runtimeFirst=%v) = handled %v, err %v", runtimeFirst, handled, err)
		}
	}

	driver := NewDriver(nil, nil)
	if watches := driver.RuntimePolicyWatchObjects(); len(watches) != 1 || watches[0].GetObjectKind().GroupVersionKind().Version != "v1alpha1" {
		t.Fatalf("disabled watch objects = %#v", watches)
	}
	if err := driver.AddTemplate(context.Background(), template); err == nil || !strings.Contains(err.Error(), "fleet feature gate") {
		t.Fatalf("AddTemplate(disabled) error = %v", err)
	}
	driver.SetV1Alpha2SubjectsEnabled(true)
	if watches := driver.RuntimePolicyWatchObjects(); len(watches) != 2 || watches[1].GetObjectKind().GroupVersionKind().Version != "v1alpha2" {
		t.Fatalf("enabled watch objects = %#v", watches)
	}
	if err := driver.AddTemplate(context.Background(), template); err != nil {
		t.Fatalf("AddTemplate(enabled) error = %v", err)
	}
}

func TestV1Alpha2KubernetesProjection(t *testing.T) {
	constraint := runtimeConstraintV1Alpha2(map[string]interface{}{
		kubernetesSubjectProperty: map[string]interface{}{
			namespaceSelectorProperty: map[string]interface{}{matchLabelsProperty: map[string]interface{}{"environment": testEnvironment}},
			runtimeClassNamesProperty: []interface{}{testRuntimeClassName},
			containerTypesProperty:    []interface{}{testApplicationContainerType},
			containerNamesProperty:    []interface{}{testContainerName},
		},
	})
	parsed, err := ParseConstraintForSource(constraint, SubjectSourceVersion)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := buildRuntimePolicyFromParsed(constraint, parsed, []string{testConfiguredExclusion})
	if err != nil {
		t.Fatal(err)
	}
	if policy.GetAPIVersion() != RuntimePolicyAPIVersionV1Alpha2 {
		t.Fatalf("apiVersion = %q", policy.GetAPIVersion())
	}
	if _, found, err := unstructured.NestedFieldNoCopy(policy.Object, "spec", "match"); err != nil || found {
		t.Fatalf("legacy match projected: found %v, err %v", found, err)
	}
	classes, found, err := unstructured.NestedStringSlice(policy.Object, "spec", subjectProperty, kubernetesSubjectProperty, runtimeClassNamesProperty)
	if err != nil || !found || len(classes) != 1 || classes[0] != testRuntimeClassName {
		t.Fatalf("runtimeClassNames = %v, found %v, err %v", classes, found, err)
	}
	exclusions, found, err := unstructured.NestedStringSlice(policy.Object, "spec", subjectProperty, kubernetesSubjectProperty, excludedNamespacesProperty)
	if err != nil || !found || len(exclusions) != 1 || exclusions[0] != testConfiguredExclusion {
		t.Fatalf("excludedNamespaces = %v, found %v, err %v", exclusions, found, err)
	}
}

func TestV1Alpha2SubstrateProjectionDoesNotConsumeKubernetesExclusions(t *testing.T) {
	const generation = int64(1<<53 + 1)
	constraint := runtimeConstraintV1Alpha2(map[string]interface{}{
		substrateSubjectProperty: map[string]interface{}{
			atespacePatternsProperty: []interface{}{testAtespacePattern},
			actorTemplateProperty: map[string]interface{}{
				actorTemplateNamespaceProperty: testActorTemplateNamespace, actorTemplateNameProperty: testActorTemplateName, "uid": "template-uid", generationProperty: generation,
			},
			actorTemplateLabelsProperty: map[string]interface{}{matchLabelsProperty: map[string]interface{}{"tier": "trusted"}},
			"sandboxClasses":            []interface{}{"microvm"},
			containerNamesProperty:      []interface{}{"actor"},
		},
	})
	parsed, err := ParseConstraintForSource(constraint, SubjectSourceVersion)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := buildRuntimePolicyFromParsed(constraint, parsed, []string{testConfiguredExclusion})
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := unstructured.NestedFieldNoCopy(policy.Object, "spec", subjectProperty, substrateSubjectProperty, excludedNamespacesProperty); err != nil || found {
		t.Fatalf("Kubernetes exclusions leaked into Substrate subject: found %v, err %v", found, err)
	}
	projectedGeneration, found, err := unstructured.NestedInt64(policy.Object, "spec", subjectProperty, substrateSubjectProperty, actorTemplateProperty, generationProperty)
	if err != nil || !found || projectedGeneration != generation {
		t.Fatalf("actor template generation = %d, found %v, err %v; want %d", projectedGeneration, found, err, generation)
	}
}

func TestV1Alpha2SubjectValidation(t *testing.T) {
	tooManyAtespaces := make([]interface{}, maxAtespacePatterns+1)
	for i := range tooManyAtespaces {
		tooManyAtespaces[i] = "team-" + strconv.Itoa(i)
	}
	tests := []struct {
		name    string
		match   map[string]interface{}
		wantErr string
	}{
		{name: "missing subject", match: map[string]interface{}{}, wantErr: "requires spec.match.subject"},
		{name: "empty subject", match: map[string]interface{}{subjectProperty: map[string]interface{}{}}, wantErr: "exactly one"},
		{name: "mixed kinds", match: map[string]interface{}{subjectProperty: map[string]interface{}{
			kubernetesSubjectProperty: map[string]interface{}{containerNamesProperty: []interface{}{testContainerName}},
			substrateSubjectProperty:  map[string]interface{}{atespacePatternsProperty: []interface{}{testAtespacePattern}},
		}}, wantErr: "exactly one"},
		{name: "legacy plus subject", match: map[string]interface{}{
			namespaceSelectorProperty: map[string]interface{}{},
			subjectProperty: map[string]interface{}{
				kubernetesSubjectProperty: map[string]interface{}{containerNamesProperty: []interface{}{testContainerName}},
			},
		}, wantErr: "cannot be combined"},
		{name: "unknown subject field", match: map[string]interface{}{subjectProperty: map[string]interface{}{
			kubernetesSubjectProperty: map[string]interface{}{containerNamesProperty: []interface{}{testContainerName}, "unknown": true},
		}}, wantErr: "unknown field"},
		{name: "bare wildcard", match: map[string]interface{}{subjectProperty: map[string]interface{}{
			substrateSubjectProperty: map[string]interface{}{atespacePatternsProperty: []interface{}{"*"}},
		}}, wantErr: "wildcard prefix"},
		{name: "uppercase atespace", match: map[string]interface{}{subjectProperty: map[string]interface{}{
			substrateSubjectProperty: map[string]interface{}{atespacePatternsProperty: []interface{}{"Team"}},
		}}, wantErr: "invalid"},
		{name: "interior wildcard", match: map[string]interface{}{subjectProperty: map[string]interface{}{
			substrateSubjectProperty: map[string]interface{}{atespacePatternsProperty: []interface{}{"te*am"}},
		}}, wantErr: "once at the end"},
		{name: "unicode atespace", match: map[string]interface{}{subjectProperty: map[string]interface{}{
			substrateSubjectProperty: map[string]interface{}{atespacePatternsProperty: []interface{}{"tëam"}},
		}}, wantErr: "invalid"},
		{name: "atespace too long", match: map[string]interface{}{subjectProperty: map[string]interface{}{
			substrateSubjectProperty: map[string]interface{}{atespacePatternsProperty: []interface{}{strings.Repeat("a", maxAtespaceLength+1)}},
		}}, wantErr: "maximum is 63"},
		{name: "too many atespaces", match: map[string]interface{}{subjectProperty: map[string]interface{}{
			substrateSubjectProperty: map[string]interface{}{atespacePatternsProperty: tooManyAtespaces},
		}}, wantErr: "maximum is 32"},
		{name: "invalid actor template labels", match: map[string]interface{}{subjectProperty: map[string]interface{}{
			substrateSubjectProperty: map[string]interface{}{
				atespacePatternsProperty:    []interface{}{testAtespacePattern},
				actorTemplateLabelsProperty: map[string]interface{}{matchLabelsProperty: map[string]interface{}{"bad key": "value"}},
			},
		}}, wantErr: "actorTemplateLabels"},
		{name: "generation without uid", match: map[string]interface{}{subjectProperty: map[string]interface{}{
			substrateSubjectProperty: map[string]interface{}{
				atespacePatternsProperty: []interface{}{testAtespacePattern},
				actorTemplateProperty: map[string]interface{}{
					actorTemplateNamespaceProperty: testActorTemplateNamespace, actorTemplateNameProperty: testActorTemplateName, generationProperty: int64(1),
				},
			},
		}}, wantErr: "uid is required"},
		{name: "actor template uid too long", match: map[string]interface{}{subjectProperty: map[string]interface{}{
			substrateSubjectProperty: map[string]interface{}{
				atespacePatternsProperty: []interface{}{testAtespacePattern},
				actorTemplateProperty: map[string]interface{}{
					actorTemplateNamespaceProperty: testActorTemplateNamespace, actorTemplateNameProperty: testActorTemplateName, "uid": strings.Repeat("u", 129),
				},
			},
		}}, wantErr: "uid exceeds 128 bytes"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			constraint := runtimeConstraint("deny")
			if err := unstructured.SetNestedMap(constraint.Object, test.match, "spec", "match"); err != nil {
				t.Fatal(err)
			}
			_, err := ParseConstraintForSource(constraint, SubjectSourceVersion)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("ParseConstraintForSource() error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestNormalizeLegacyKubernetesSubjectFixtures(t *testing.T) {
	data, err := os.ReadFile("testdata/legacy-kubernetes-normalization.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Name       string        `json:"name"`
		Legacy     Match         `json:"legacy"`
		Normalized PolicySubject `json:"normalized"`
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			subject, err := NormalizeLegacyKubernetesSubject(&fixture.Legacy)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(subject, fixture.Normalized) {
				got, _ := json.Marshal(subject)
				want, _ := json.Marshal(fixture.Normalized)
				t.Fatalf("normalized subject = %s, want %s", got, want)
			}
		})
	}
}

func TestRuntimePolicySourceVersionLifecycle(t *testing.T) {
	ctx := context.Background()
	kube := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build()
	driver := NewDriver(kube, kube)
	driver.SetV1Alpha2SubjectsEnabled(true)

	legacyTemplate := runtimeTemplate()
	legacyConstraint := runtimeConstraint("deny")
	if err := driver.AddTemplate(ctx, legacyTemplate); err != nil {
		t.Fatal(err)
	}
	if err := driver.AddConstraint(ctx, legacyConstraint); err != nil {
		t.Fatal(err)
	}
	if projection, handled, err := driver.ReconcileConstraint(ctx, legacyConstraint); err != nil || !handled || projection.State != ProjectionProjected {
		t.Fatalf("ReconcileConstraint(v1alpha1) = %#v, handled %v, err %v", projection, handled, err)
	}
	assertRuntimePolicyVersion(t, ctx, kube, legacyConstraint, RuntimePolicyAPIVersion, true)

	if err := driver.AddTemplate(ctx, runtimeTemplateV1Alpha2()); err == nil || !strings.Contains(err.Error(), "cannot change") {
		t.Fatalf("AddTemplate(version switch with Constraint) error = %v", err)
	}
	if projection, handled, err := driver.ReconcileConstraint(ctx, legacyConstraint); err != nil || !handled || projection.State != ProjectionProjected {
		t.Fatalf("ReconcileConstraint(after rejected switch) = %#v, handled %v, err %v", projection, handled, err)
	}

	if err := driver.RemoveConstraint(ctx, legacyConstraint); err != nil {
		t.Fatal(err)
	}
	assertRuntimePolicyVersion(t, ctx, kube, legacyConstraint, RuntimePolicyAPIVersion, false)

	v1alpha2Template := runtimeTemplateV1Alpha2()
	if err := driver.AddTemplate(ctx, v1alpha2Template); err != nil {
		t.Fatal(err)
	}
	v1alpha2Constraint := runtimeConstraintV1Alpha2(map[string]interface{}{
		kubernetesSubjectProperty: map[string]interface{}{runtimeClassNamesProperty: []interface{}{testRuntimeClassName}},
	})
	if err := driver.AddConstraint(ctx, v1alpha2Constraint); err != nil {
		t.Fatal(err)
	}
	if projection, handled, err := driver.ReconcileConstraint(ctx, v1alpha2Constraint); err != nil || !handled || projection.State != ProjectionProjected {
		t.Fatalf("ReconcileConstraint(v1alpha2) = %#v, handled %v, err %v", projection, handled, err)
	}
	assertRuntimePolicyVersion(t, ctx, kube, v1alpha2Constraint, RuntimePolicyAPIVersionV1Alpha2, true)
	assertRuntimePolicyVersion(t, ctx, kube, v1alpha2Constraint, RuntimePolicyAPIVersion, false)

	if err := driver.RemoveTemplate(ctx, v1alpha2Template); err != nil {
		t.Fatal(err)
	}
	assertRuntimePolicyVersion(t, ctx, kube, v1alpha2Constraint, RuntimePolicyAPIVersionV1Alpha2, false)
}

func TestSourceVersionsRejectCrossVersionMatches(t *testing.T) {
	if _, err := ParseConstraintForSource(runtimeConstraintV1Alpha2(map[string]interface{}{
		kubernetesSubjectProperty: map[string]interface{}{containerNamesProperty: []interface{}{testContainerName}},
	}), SourceVersion); err == nil || !strings.Contains(err.Error(), `unknown field "`+subjectProperty+`"`) {
		t.Fatalf("v1alpha1 accepted normalized subject: %v", err)
	}
	if _, err := ParseConstraintForSource(runtimeConstraint("deny"), SubjectSourceVersion); err == nil || !strings.Contains(err.Error(), "requires spec.match.subject") {
		t.Fatalf("v1alpha2 accepted legacy match: %v", err)
	}
}

func assertRuntimePolicyVersion(t *testing.T, ctx context.Context, kube client.Reader, constraint *unstructured.Unstructured, apiVersion string, want bool) {
	t.Helper()
	policy := runtimePolicyWatchObject(apiVersion)
	err := kube.Get(ctx, types.NamespacedName{Name: RuntimePolicyName(constraint)}, policy)
	if want {
		if err != nil {
			t.Fatalf("get %s RuntimePolicy: %v", apiVersion, err)
		}
		if policy.GetAPIVersion() != apiVersion {
			t.Fatalf("RuntimePolicy apiVersion = %q, want %q", policy.GetAPIVersion(), apiVersion)
		}
		return
	}
	if !apierrors.IsNotFound(err) {
		t.Fatalf("get removed %s RuntimePolicy: %v, want not found", apiVersion, err)
	}
}

func runtimeTemplateV1Alpha2() *templates.ConstraintTemplate {
	template := runtimeTemplate()
	template.Spec.Targets[0].Code[0].Source = &templates.Anything{Value: map[string]interface{}{sourceVersionProperty: SubjectSourceVersion}}
	return template
}

func runtimeConstraintV1Alpha2(subject map[string]interface{}) *unstructured.Unstructured {
	constraint := runtimeConstraint("deny")
	if err := unstructured.SetNestedMap(constraint.Object, map[string]interface{}{subjectProperty: subject}, "spec", "match"); err != nil {
		panic(err)
	}
	return constraint
}
