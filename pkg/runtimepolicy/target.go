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

const (
	namespaceSelectorProperty  = "namespaceSelector"
	podSelectorProperty        = "podSelector"
	containerTypesProperty     = "containerTypes"
	excludedNamespacesProperty = "excludedNamespaces"
	actorTemplateNameProperty  = "name"
)

// NewTarget returns a runtime target whose Constraint validation follows the
// source version cached by driver for that Constraint kind.
func NewTarget(driver *Driver) *Target { return &Target{driver: driver} }

// Target implements the non-evaluating runtime ConstraintTemplate target.
// Constraints are projected to RuntimePolicy resources instead of being run
// against admission or audit reviews inside Gatekeeper.
type Target struct {
	driver *Driver
}

func (*Target) GetName() string { return TargetName }

func (*Target) ProcessData(interface{}) (bool, []string, interface{}, error) {
	return false, nil, nil, nil
}

func (*Target) HandleReview(interface{}) (bool, interface{}, error) {
	return false, nil, nil
}

func (*Target) MatchSchema() apiextensions.JSONSchemaProps { return matchSchema() }

func (t *Target) ValidateConstraint(constraint *unstructured.Unstructured) error {
	if t.driver != nil {
		_, err := t.driver.parseConstraint(constraint)
		return err
	}
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
	maxSubjectNameItems := int64(maxSubjectNames)
	maxAtespacePatternItems := int64(maxAtespacePatterns)
	maxAtespacePatternLength := int64(maxAtespaceLength)

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
	stringList := func(maxItems int64, maxLength int64) apiextensions.JSONSchemaProps {
		return apiextensions.JSONSchemaProps{
			Type: "array", MaxItems: &maxItems,
			Items: &apiextensions.JSONSchemaPropsOrArray{Schema: &apiextensions.JSONSchemaProps{Type: "string", MaxLength: &maxLength}},
		}
	}
	containerTypes := apiextensions.JSONSchemaProps{
		Type: "array", MaxItems: &maxContainerTypes,
		Items: &apiextensions.JSONSchemaPropsOrArray{Schema: &apiextensions.JSONSchemaProps{
			Type: "string", Enum: enum("Application", "Init", "Ephemeral"),
		}},
	}
	excludedNamespaces := apiextensions.JSONSchemaProps{
		Type: "array", MaxItems: &maxExcludedNamespaces,
		Items: &apiextensions.JSONSchemaPropsOrArray{Schema: &apiextensions.JSONSchemaProps{
			Type: "string", MaxLength: &maxNamespacePatternLength, Pattern: `^\*?[-:a-z0-9]*\*?$`,
		}},
	}
	kubernetesSubject := apiextensions.JSONSchemaProps{
		Type: "object",
		Properties: map[string]apiextensions.JSONSchemaProps{
			namespaceSelectorProperty:  selector,
			podSelectorProperty:        selector,
			excludedNamespacesProperty: excludedNamespaces,
			"runtimeClassNames":        stringList(maxSubjectNameItems, 253),
			containerTypesProperty:     containerTypes,
			"containerNames":           stringList(maxSubjectNameItems, 63),
		},
	}
	substrateSubject := apiextensions.JSONSchemaProps{
		Type:     "object",
		Required: []string{"atespacePatterns"},
		Properties: map[string]apiextensions.JSONSchemaProps{
			"atespacePatterns": {
				Type: "array", MinItems: int64Ptr(1), MaxItems: &maxAtespacePatternItems,
				Items: &apiextensions.JSONSchemaPropsOrArray{Schema: &apiextensions.JSONSchemaProps{Type: "string", MaxLength: &maxAtespacePatternLength}},
			},
			"actorTemplate": {
				Type: "object", Required: []string{"namespace", actorTemplateNameProperty},
				Properties: map[string]apiextensions.JSONSchemaProps{
					"namespace":               {Type: "string", MinLength: int64Ptr(1), MaxLength: int64Ptr(63)},
					actorTemplateNameProperty: {Type: "string", MinLength: int64Ptr(1), MaxLength: int64Ptr(253)},
					"uid":                     {Type: "string", MaxLength: int64Ptr(128)},
					"generation":              {Type: "integer", Format: "int64", Minimum: float64Ptr(0)},
				},
			},
			"actorTemplateLabels": selector,
			"sandboxClasses":      stringList(maxSubjectNameItems, 253),
			"containerNames":      stringList(maxSubjectNameItems, 63),
		},
	}
	return apiextensions.JSONSchemaProps{
		Type: "object",
		Properties: map[string]apiextensions.JSONSchemaProps{
			"subject": {
				Type: "object",
				Properties: map[string]apiextensions.JSONSchemaProps{
					"kubernetes": kubernetesSubject,
					"substrate":  substrateSubject,
				},
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

func float64Ptr(value float64) *float64 { return &value }
