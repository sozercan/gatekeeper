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

package gator

import (
	"context"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/runtimepolicy"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestNewOPAClientValidatesRuntimeTemplatesAndConstraintsOffline(t *testing.T) {
	client, err := NewOPAClient(false)
	if err != nil {
		t.Fatal(err)
	}
	template := offlineRuntimeTemplate()
	if _, err := client.AddTemplate(context.Background(), template); err != nil {
		t.Fatalf("AddTemplate(runtime) error = %v", err)
	}
	if _, err := client.AddConstraint(context.Background(), offlineRuntimeConstraint()); err != nil {
		t.Fatalf("AddConstraint(runtime) error = %v", err)
	}

	template = offlineRuntimeTemplate()
	template.Spec.Targets[0].Code = nil
	template.Spec.Targets[0].Rego = "package runtime"
	if _, err := client.AddTemplate(context.Background(), template); err == nil {
		t.Fatal("AddTemplate(runtime Rego) succeeded, want rejection")
	}
}

func offlineRuntimeTemplate() *templates.ConstraintTemplate {
	preserveUnknown := true
	return &templates.ConstraintTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "runtimeprocess"},
		Spec: templates.ConstraintTemplateSpec{
			CRD: templates.CRD{Spec: templates.CRDSpec{
				Names: templates.Names{Kind: "RuntimeProcess"},
				Validation: &templates.Validation{OpenAPIV3Schema: &apiextensions.JSONSchemaProps{
					Type: "object",
					Properties: map[string]apiextensions.JSONSchemaProps{
						"behaviors": {Type: "object", XPreserveUnknownFields: &preserveUnknown},
					},
				}},
			}},
			Targets: []templates.Target{{
				Target: runtimepolicy.TargetName,
				Code: []templates.Code{{
					Engine: runtimepolicy.EngineName,
					Source: &templates.Anything{Value: map[string]interface{}{"version": runtimepolicy.SourceVersion}},
				}},
			}},
		},
	}
}

func offlineRuntimeConstraint() *unstructured.Unstructured {
	constraint := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "constraints.gatekeeper.sh/v1beta1",
		"kind":       "RuntimeProcess",
		"metadata":   map[string]interface{}{"name": "shell-policy"},
		"spec": map[string]interface{}{
			"enforcementAction": "dryrun",
			"match": map[string]interface{}{
				"subject": map[string]interface{}{
					"kubernetes": map[string]interface{}{
						"containerNames": []interface{}{"main"},
					},
				},
			},
			"parameters": map[string]interface{}{
				"behaviors": map[string]interface{}{
					"process": map[string]interface{}{
						"executables": []interface{}{map[string]interface{}{"path": "/bin/sh", "action": "Deny"}},
					},
				},
			},
		},
	}}
	constraint.SetGroupVersionKind(schema.GroupVersionKind{Group: "constraints.gatekeeper.sh", Version: "v1beta1", Kind: "RuntimeProcess"})
	return constraint
}
