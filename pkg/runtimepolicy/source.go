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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
)

var (
	ErrInvalidRuntimeTemplate = errors.New("invalid runtime ConstraintTemplate")
	ErrInvalidRuntimeSource   = errors.New("invalid Runtime source")
)

// Source is the bounded, non-executable source contract for a runtime target.
// Runtime policy content is supplied by Constraint parameters and projected to
// a RuntimePolicy resource; arbitrary Rego and CEL are intentionally unsupported.
type Source struct {
	Version string `json:"version"`
}

// IsRuntimeTemplate reports whether ct declares the runtime target.
func IsRuntimeTemplate(ct *templates.ConstraintTemplate) bool {
	if ct == nil {
		return false
	}
	for _, target := range ct.Spec.Targets {
		if target.Target == TargetName {
			return true
		}
	}
	return false
}

// ValidateTemplate validates the target-specific contract. The returned bool
// reports whether the template declares the runtime target.
func ValidateTemplate(ct *templates.ConstraintTemplate) (bool, error) {
	if !IsRuntimeTemplate(ct) {
		return false, nil
	}
	if ct == nil {
		return true, fmt.Errorf("%w: template is required", ErrInvalidRuntimeTemplate)
	}

	var target *templates.Target
	for i := range ct.Spec.Targets {
		if ct.Spec.Targets[i].Target != TargetName {
			continue
		}
		if target != nil {
			return true, fmt.Errorf("%w: target %q must be declared exactly once", ErrInvalidRuntimeTemplate, TargetName)
		}
		target = &ct.Spec.Targets[i]
	}
	if target == nil {
		return false, nil
	}
	if target.Rego != "" || len(target.Libs) != 0 {
		return true, fmt.Errorf("%w: Rego and library sources cannot be used with %q", ErrInvalidRuntimeTemplate, TargetName)
	}
	if len(target.Operations) != 0 {
		return true, fmt.Errorf("%w: admission operations do not apply to %q", ErrInvalidRuntimeTemplate, TargetName)
	}
	if len(target.Code) != 1 {
		return true, fmt.Errorf("%w: must declare exactly one %q code block", ErrInvalidRuntimeTemplate, EngineName)
	}
	code := target.Code[0]
	if code.Engine != EngineName {
		return true, fmt.Errorf("%w: engine must be %q, got %q", ErrInvalidRuntimeTemplate, EngineName, code.Engine)
	}
	if code.Source == nil {
		return true, fmt.Errorf("%w: source is required", ErrInvalidRuntimeSource)
	}

	var source Source
	if err := decodeStrict(code.Source.GetValue(), &source); err != nil {
		return true, fmt.Errorf("%w: %w", ErrInvalidRuntimeSource, err)
	}
	if source.Version != SourceVersion {
		return true, fmt.Errorf("%w: version must be %q, got %q", ErrInvalidRuntimeSource, SourceVersion, source.Version)
	}
	// Frameworks merges every target's match schema into one Constraint match.
	// A runtime subject would look empty to the Kubernetes target and could
	// broaden admission. Keep the normalized contract runtime-only until
	// frameworks has target-specific match sections.
	if len(ct.Spec.Targets) != 1 {
		return true, fmt.Errorf("%w: source version %q must use a runtime-only ConstraintTemplate", ErrInvalidRuntimeTemplate, SourceVersion)
	}

	validation := ct.Spec.CRD.Spec.Validation
	if validation == nil || validation.OpenAPIV3Schema == nil {
		return true, fmt.Errorf("%w: parameters must have an OpenAPI v3 schema", ErrInvalidRuntimeTemplate)
	}
	if schemaType := validation.OpenAPIV3Schema.Type; schemaType != "object" {
		return true, fmt.Errorf("%w: parameters schema type must be object, got %q", ErrInvalidRuntimeTemplate, schemaType)
	}

	return true, nil
}

func sourceVersion(ct *templates.ConstraintTemplate) (string, error) {
	if ct == nil {
		return "", fmt.Errorf("%w: template is required", ErrInvalidRuntimeTemplate)
	}
	for i := range ct.Spec.Targets {
		target := &ct.Spec.Targets[i]
		if target.Target != TargetName || len(target.Code) != 1 || target.Code[0].Source == nil {
			continue
		}
		var source Source
		if err := decodeStrict(target.Code[0].Source.GetValue(), &source); err != nil {
			return "", fmt.Errorf("%w: %w", ErrInvalidRuntimeSource, err)
		}
		return source.Version, nil
	}
	return "", fmt.Errorf("%w: target %q is required", ErrInvalidRuntimeTemplate, TargetName)
}

func decodeStrict(value interface{}, into interface{}) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode value: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}
