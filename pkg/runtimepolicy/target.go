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
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var _ handler.TargetHandler = &Target{}

// Target implements the non-evaluating runtime ConstraintTemplate target.
// Constraints are projected to RuntimePolicy resources instead of being run
// against admission or audit reviews inside Gatekeeper.
type Target struct{}

func (*Target) GetName() string { return TargetName }

func (*Target) ProcessData(interface{}) (bool, []string, interface{}, error) {
	return false, nil, nil, nil
}

func (*Target) HandleReview(interface{}) (bool, interface{}, error) {
	return false, nil, nil
}

func (*Target) MatchSchema() apiextensions.JSONSchemaProps { return matchSchema() }

func (*Target) ValidateConstraint(constraint *unstructured.Unstructured) error {
	_, err := ParseConstraint(constraint)
	return err
}

func (*Target) ToMatcher(*unstructured.Unstructured) (constraints.Matcher, error) {
	return noReviewMatcher{}, nil
}

type noReviewMatcher struct{}

func (noReviewMatcher) Match(interface{}) (bool, error) { return false, nil }

func matchSchema() apiextensions.JSONSchemaProps {
	maxContainerTypes := int64(3)
	maxSelectorExpressions := int64(64)
	maxSelectorValues := int64(256)
	maxExcludedNamespaces := int64(256)
	maxNamespacePatternLength := int64(253)

	stringSchema := apiextensions.JSONSchemaProps{Type: "string"}
	selectorRequirement := apiextensions.JSONSchemaProps{
		Type:     "object",
		Required: []string{"key", "operator"},
		Properties: map[string]apiextensions.JSONSchemaProps{
			"key":      {Type: "string", MinLength: int64Ptr(1), MaxLength: int64Ptr(253)},
			"operator": {Type: "string", Enum: enum("In", "NotIn", "Exists", "DoesNotExist")},
			"values": {
				Type:     "array",
				MaxItems: &maxSelectorValues,
				Items:    &apiextensions.JSONSchemaPropsOrArray{Schema: &stringSchema},
			},
		},
	}
	selector := apiextensions.JSONSchemaProps{
		Type: "object",
		Properties: map[string]apiextensions.JSONSchemaProps{
			"matchLabels": {
				Type:                 "object",
				AdditionalProperties: &apiextensions.JSONSchemaPropsOrBool{Allows: true, Schema: &stringSchema},
			},
			"matchExpressions": {
				Type:     "array",
				MaxItems: &maxSelectorExpressions,
				Items:    &apiextensions.JSONSchemaPropsOrArray{Schema: &selectorRequirement},
			},
		},
	}
	return apiextensions.JSONSchemaProps{
		Type: "object",
		Properties: map[string]apiextensions.JSONSchemaProps{
			"namespaceSelector": selector,
			"podSelector":       selector,
			"containerTypes": {
				Type:     "array",
				MaxItems: &maxContainerTypes,
				Items: &apiextensions.JSONSchemaPropsOrArray{Schema: &apiextensions.JSONSchemaProps{
					Type: "string",
					Enum: enum("Application", "Init", "Ephemeral"),
				}},
			},
			"excludedNamespaces": {
				Type:     "array",
				MaxItems: &maxExcludedNamespaces,
				Items: &apiextensions.JSONSchemaPropsOrArray{Schema: &apiextensions.JSONSchemaProps{
					Type:      "string",
					MaxLength: &maxNamespacePatternLength,
					Pattern:   `^\*?[-:a-z0-9]*\*?$`,
				}},
			},
		},
	}
}

func enum(values ...string) []apiextensions.JSON {
	out := make([]apiextensions.JSON, len(values))
	for i, value := range values {
		out[i] = value
	}
	return out
}

func int64Ptr(value int64) *int64 { return &value }
