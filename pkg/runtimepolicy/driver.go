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
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/reviews"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/opa/v1/storage"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	_ drivers.Driver = &Driver{}
	_ Projector      = &Driver{}
)

var ErrRuntimeReviewUnsupported = errors.New("runtime constraints are projected to RuntimePolicy resources and cannot evaluate admission or audit reviews")

// Driver validates and caches declarative runtime templates and constraints.
// In Gatekeeper it also projects constraints through the Kubernetes API; Gator
// uses the same driver without a writer for offline validation parity.
type Driver struct {
	mu          sync.RWMutex
	templates   map[string]*templates.ConstraintTemplate
	constraints map[string]map[string]*unstructured.Unstructured
	writer      client.Client
	reader      client.Reader
	exclusions  func() []string
}

func NewDriver(writer client.Client, reader client.Reader, exclusionProviders ...func() []string) *Driver {
	driver := &Driver{
		templates:   make(map[string]*templates.ConstraintTemplate),
		constraints: make(map[string]map[string]*unstructured.Unstructured),
		writer:      writer,
		reader:      reader,
	}
	if len(exclusionProviders) != 0 {
		driver.exclusions = exclusionProviders[0]
	}
	return driver
}

func NewOfflineDriver() *Driver { return NewDriver(nil, nil) }

func (*Driver) Name() string { return EngineName }

func (d *Driver) AddTemplate(_ context.Context, template *templates.ConstraintTemplate) error {
	handled, err := ValidateTemplate(template)
	if err != nil {
		return err
	}
	if !handled {
		return fmt.Errorf("%w: target must be %q", ErrInvalidRuntimeTemplate, TargetName)
	}
	key := strings.ToLower(template.Spec.CRD.Spec.Names.Kind)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.templates[key] = template.DeepCopy()
	if d.constraints[key] == nil {
		d.constraints[key] = make(map[string]*unstructured.Unstructured)
	}
	return nil
}

func (d *Driver) RemoveTemplate(ctx context.Context, template *templates.ConstraintTemplate) error {
	key := strings.ToLower(template.Spec.CRD.Spec.Names.Kind)
	d.mu.RLock()
	constraints := make([]*unstructured.Unstructured, 0, len(d.constraints[key]))
	for _, constraint := range d.constraints[key] {
		constraints = append(constraints, constraint.DeepCopy())
	}
	d.mu.RUnlock()
	for _, constraint := range constraints {
		if err := deleteRuntimePolicy(ctx, d.writer, d.reader, constraint); err != nil {
			return err
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.templates, key)
	delete(d.constraints, key)
	return nil
}

func (d *Driver) AddConstraint(_ context.Context, constraint *unstructured.Unstructured) error {
	if _, err := ParseConstraint(constraint); err != nil {
		return err
	}
	key := strings.ToLower(constraint.GetKind())
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.templates[key] == nil {
		return fmt.Errorf("%w: no runtime template for kind %q", ErrInvalidRuntimeConstraint, constraint.GetKind())
	}
	if d.constraints[key] == nil {
		d.constraints[key] = make(map[string]*unstructured.Unstructured)
	}
	d.constraints[key][constraint.GetName()] = constraint.DeepCopy()
	return nil
}

func (d *Driver) RemoveConstraint(ctx context.Context, constraint *unstructured.Unstructured) error {
	key := strings.ToLower(constraint.GetKind())
	d.mu.RLock()
	handled := d.templates[key] != nil
	cached := d.constraints[key][constraint.GetName()]
	d.mu.RUnlock()
	if !handled {
		return nil
	}
	// Delete reconciles can arrive as UID-less tombstones after the source
	// object is gone. Use the identity cached when the Constraint was accepted
	// so ownership verification cannot be bypassed or made impossible by a
	// partial delete event.
	if cached == nil {
		return nil
	}
	if err := deleteRuntimePolicy(ctx, d.writer, d.reader, cached); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.constraints[key], constraint.GetName())
	return nil
}

func (*Driver) AddData(context.Context, string, storage.Path, interface{}) error { return nil }

func (*Driver) RemoveData(context.Context, string, storage.Path) error { return nil }

func (*Driver) Query(_ context.Context, target string, constraints []*unstructured.Unstructured, _ interface{}, _ ...reviews.ReviewOpt) (*drivers.QueryResponse, error) {
	if target == TargetName && len(constraints) != 0 {
		return nil, ErrRuntimeReviewUnsupported
	}
	return &drivers.QueryResponse{}, nil
}

func (d *Driver) Dump(_ context.Context) (string, error) {
	d.mu.RLock()
	constraints := make([]*unstructured.Unstructured, 0)
	for _, byName := range d.constraints {
		for _, constraint := range byName {
			constraints = append(constraints, constraint.DeepCopy())
		}
	}
	d.mu.RUnlock()
	sort.Slice(constraints, func(i, j int) bool {
		if constraints[i].GetKind() == constraints[j].GetKind() {
			return constraints[i].GetName() < constraints[j].GetName()
		}
		return constraints[i].GetKind() < constraints[j].GetKind()
	})
	policies := make([]map[string]interface{}, 0, len(constraints))
	for _, constraint := range constraints {
		policy, err := buildRuntimePolicyWithExclusions(constraint, d.configuredExclusions())
		if err != nil {
			return "", err
		}
		policies = append(policies, policy.Object)
	}
	encoded, err := json.MarshalIndent(map[string]interface{}{"runtimePolicies": policies}, "", "  ")
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func (*Driver) GetDescriptionForStat(string) (string, error) {
	return "", errors.New("runtime driver does not expose evaluation statistics")
}

func (d *Driver) ReconcileConstraint(ctx context.Context, constraint *unstructured.Unstructured) (ProjectionStatus, bool, error) {
	key := strings.ToLower(constraint.GetKind())
	d.mu.RLock()
	handled := d.templates[key] != nil
	d.mu.RUnlock()
	if !handled {
		return ProjectionStatus{}, false, nil
	}
	status, err := projectRuntimePolicy(ctx, d.writer, d.reader, constraint, d.configuredExclusions())
	return status, true, err
}

func (*Driver) RuntimePolicyWatchObject() client.Object { return RuntimePolicyWatchObject() }

// ConfigRefresher is implemented by runtime projectors that can immediately
// reconcile existing projections after Gatekeeper Config changes.
type ConfigRefresher interface {
	RefreshConfig(context.Context) error
}

func (d *Driver) configuredExclusions() []string {
	if d.exclusions == nil {
		return nil
	}
	return append([]string(nil), d.exclusions()...)
}

func (d *Driver) RefreshConfig(ctx context.Context) error {
	d.mu.RLock()
	constraints := make([]*unstructured.Unstructured, 0)
	for _, byName := range d.constraints {
		for _, constraint := range byName {
			constraints = append(constraints, constraint.DeepCopy())
		}
	}
	d.mu.RUnlock()
	sort.Slice(constraints, func(i, j int) bool {
		if constraints[i].GetKind() == constraints[j].GetKind() {
			return constraints[i].GetName() < constraints[j].GetName()
		}
		return constraints[i].GetKind() < constraints[j].GetKind()
	})
	exclusions := d.configuredExclusions()
	var errs []error
	for _, constraint := range constraints {
		if _, err := projectRuntimePolicy(ctx, d.writer, d.reader, constraint, exclusions); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
