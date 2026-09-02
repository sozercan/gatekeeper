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
	"strconv"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestRuntimeTemplateMustBeRuntimeOnly(t *testing.T) {
	template := runtimeTemplate()
	if handled, err := ValidateTemplate(template); !handled || err != nil {
		t.Fatalf("ValidateTemplate(runtime-only) = handled %v, err %v", handled, err)
	}

	for _, runtimeFirst := range []bool{false, true} {
		combined := combinedRuntimeTemplate()
		if runtimeFirst {
			combined.Spec.Targets[0], combined.Spec.Targets[1] = combined.Spec.Targets[1], combined.Spec.Targets[0]
		}
		handled, err := ValidateTemplate(combined)
		if !handled || err == nil || !strings.Contains(err.Error(), "runtime-only") {
			t.Fatalf("ValidateTemplate(combined, runtimeFirst=%v) = handled %v, err %v", runtimeFirst, handled, err)
		}
	}
}

func TestMatchSchemaOnlyExposesSubject(t *testing.T) {
	properties := matchSchema().Properties
	if len(properties) != 1 {
		t.Fatalf("match schema properties = %v, want only subject", properties)
	}
	if _, found := properties["subject"]; !found {
		t.Fatal("match schema does not expose subject")
	}
}

func TestKubernetesSubjectProjection(t *testing.T) {
	constraint := runtimeConstraintWithSubject(map[string]interface{}{
		"kubernetes": map[string]interface{}{
			"namespaceSelector": map[string]interface{}{"matchLabels": map[string]interface{}{"environment": "production"}},
			"runtimeClassNames": []interface{}{"gatekeeper-runtime"},
			"containerTypes":    []interface{}{"Application"},
			"containerNames":    []interface{}{"main"},
		},
	})
	parsed, err := ParseConstraint(constraint)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := buildRuntimePolicyFromParsed(constraint, parsed, []string{"kube-*"})
	if err != nil {
		t.Fatal(err)
	}
	if policy.GetAPIVersion() != RuntimePolicyAPIVersion {
		t.Fatalf("apiVersion = %q, want %q", policy.GetAPIVersion(), RuntimePolicyAPIVersion)
	}
	if _, found, err := unstructured.NestedFieldNoCopy(policy.Object, "spec", "match"); err != nil || found {
		t.Fatalf("match projected: found %v, err %v", found, err)
	}
	classes, found, err := unstructured.NestedStringSlice(policy.Object, "spec", "subject", "kubernetes", "runtimeClassNames")
	if err != nil || !found || len(classes) != 1 || classes[0] != "gatekeeper-runtime" {
		t.Fatalf("runtimeClassNames = %v, found %v, err %v", classes, found, err)
	}
	exclusions, found, err := unstructured.NestedStringSlice(policy.Object, "spec", "subject", "kubernetes", "excludedNamespaces")
	if err != nil || !found || len(exclusions) != 1 || exclusions[0] != "kube-*" {
		t.Fatalf("excludedNamespaces = %v, found %v, err %v", exclusions, found, err)
	}
}

func TestSubstrateProjectionDoesNotConsumeKubernetesExclusions(t *testing.T) {
	const generation = int64(1<<53 + 1)
	constraint := runtimeConstraintWithSubject(map[string]interface{}{
		"substrate": map[string]interface{}{
			"atespacePatterns": []interface{}{"team-*"},
			"actorTemplate": map[string]interface{}{
				"namespace": "templates", "name": "agent", "uid": "template-uid", "generation": generation,
			},
			"actorTemplateLabels": map[string]interface{}{"matchLabels": map[string]interface{}{"tier": "trusted"}},
			"sandboxClasses":      []interface{}{"microvm"},
			"containerNames":      []interface{}{"actor"},
		},
	})
	parsed, err := ParseConstraint(constraint)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := buildRuntimePolicyFromParsed(constraint, parsed, []string{"kube-*"})
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := unstructured.NestedFieldNoCopy(policy.Object, "spec", "subject", "substrate", "excludedNamespaces"); err != nil || found {
		t.Fatalf("Kubernetes exclusions leaked into Substrate subject: found %v, err %v", found, err)
	}
	projectedGeneration, found, err := unstructured.NestedInt64(policy.Object, "spec", "subject", "substrate", "actorTemplate", "generation")
	if err != nil || !found || projectedGeneration != generation {
		t.Fatalf("actor template generation = %d, found %v, err %v; want %d", projectedGeneration, found, err, generation)
	}
}

func TestSubjectValidation(t *testing.T) {
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
		{name: "empty subject", match: map[string]interface{}{"subject": map[string]interface{}{}}, wantErr: "exactly one"},
		{name: "empty Kubernetes subject", match: map[string]interface{}{"subject": map[string]interface{}{"kubernetes": map[string]interface{}{}}}, wantErr: "at least one selector"},
		{name: "mixed kinds", match: map[string]interface{}{"subject": map[string]interface{}{
			"kubernetes": map[string]interface{}{"containerNames": []interface{}{"main"}},
			"substrate":  map[string]interface{}{"atespacePatterns": []interface{}{"team-*"}},
		}}, wantErr: "exactly one"},
		{name: "other match field plus subject", match: map[string]interface{}{
			"namespaceSelector": map[string]interface{}{},
			"subject":           map[string]interface{}{"kubernetes": map[string]interface{}{"containerNames": []interface{}{"main"}}},
		}, wantErr: "cannot be combined"},
		{name: "unknown subject field", match: map[string]interface{}{"subject": map[string]interface{}{
			"kubernetes": map[string]interface{}{"containerNames": []interface{}{"main"}, "unknown": true},
		}}, wantErr: "unknown field"},
		{name: "bare wildcard", match: map[string]interface{}{"subject": map[string]interface{}{
			"substrate": map[string]interface{}{"atespacePatterns": []interface{}{"*"}},
		}}, wantErr: "wildcard prefix"},
		{name: "uppercase atespace", match: map[string]interface{}{"subject": map[string]interface{}{
			"substrate": map[string]interface{}{"atespacePatterns": []interface{}{"Team"}},
		}}, wantErr: "invalid"},
		{name: "interior wildcard", match: map[string]interface{}{"subject": map[string]interface{}{
			"substrate": map[string]interface{}{"atespacePatterns": []interface{}{"te*am"}},
		}}, wantErr: "once at the end"},
		{name: "atespace too long", match: map[string]interface{}{"subject": map[string]interface{}{
			"substrate": map[string]interface{}{"atespacePatterns": []interface{}{strings.Repeat("a", maxAtespaceLength+1)}},
		}}, wantErr: "maximum is 63"},
		{name: "too many atespaces", match: map[string]interface{}{"subject": map[string]interface{}{
			"substrate": map[string]interface{}{"atespacePatterns": tooManyAtespaces},
		}}, wantErr: "maximum is 32"},
		{name: "generation without uid", match: map[string]interface{}{"subject": map[string]interface{}{
			"substrate": map[string]interface{}{
				"atespacePatterns": []interface{}{"team-*"},
				"actorTemplate":    map[string]interface{}{"namespace": "templates", "name": "agent", "generation": int64(1)},
			},
		}}, wantErr: "uid is required"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			constraint := runtimeConstraint("deny")
			if err := unstructured.SetNestedMap(constraint.Object, test.match, "spec", "match"); err != nil {
				t.Fatal(err)
			}
			_, err := ParseConstraint(constraint)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("ParseConstraint() error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func runtimeConstraintWithSubject(subject map[string]interface{}) *unstructured.Unstructured {
	constraint := runtimeConstraint("deny")
	if err := unstructured.SetNestedMap(constraint.Object, map[string]interface{}{"subject": subject}, "spec", "match"); err != nil {
		panic(err)
	}
	return constraint
}
