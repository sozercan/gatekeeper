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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	ProjectionPending = "Pending"
	ProjectionActive  = "Active"
	ProjectionError   = "Error"
)

const (
	managedByLabel = "app.kubernetes.io/managed-by"
	managedByValue = "gatekeeper"

	sourceAPIVersionAnnotation = "runtime.gatekeeper.sh/source-constraint-api-version"
	sourceKindAnnotation       = "runtime.gatekeeper.sh/source-constraint-kind"
	sourceNameAnnotation       = "runtime.gatekeeper.sh/source-constraint-name"
	sourceUIDAnnotation        = "runtime.gatekeeper.sh/source-constraint-uid"
)

// ProjectionStatus is the RuntimePolicy handoff state surfaced on a
// Constraint's runtime enforcement point.
type ProjectionStatus struct {
	State   string
	Message string
}

// Projector is the lifecycle seam used by the generic Constraint controller.
type Projector interface {
	ReconcileConstraint(context.Context, *unstructured.Unstructured) (ProjectionStatus, bool, error)
	RuntimePolicyWatchObject() client.Object
}

// RuntimePolicyWatchObject returns an unstructured RuntimePolicy suitable for
// a controller-runtime watch without importing the standalone runtime API.
func RuntimePolicyWatchObject() *unstructured.Unstructured {
	object := &unstructured.Unstructured{}
	object.SetGroupVersionKind(schema.FromAPIVersionAndKind(RuntimePolicyAPIVersion, RuntimePolicyKind))
	return object
}

func buildRuntimePolicy(constraint *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	return buildRuntimePolicyWithExclusions(constraint, nil)
}

func buildRuntimePolicyWithExclusions(constraint *unstructured.Unstructured, configuredExclusions []string) (*unstructured.Unstructured, error) {
	parsed, err := ParseConstraint(constraint)
	if err != nil {
		return nil, err
	}

	spec, ok := runtime.DeepCopyJSONValue(parsed.RawParameters).(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: spec.parameters is not an object", ErrInvalidRuntimeConstraint)
	}
	spec["mode"] = parsed.Mode
	match, ok := runtime.DeepCopyJSONValue(parsed.RawMatch).(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: spec.match is not an object", ErrInvalidRuntimeConstraint)
	}
	excluded := append([]string(nil), parsed.Match.ExcludedNamespaces...)
	excluded = append(excluded, configuredExclusions...)
	sort.Strings(excluded)
	unique := excluded[:0]
	for _, namespace := range excluded {
		if len(unique) == 0 || unique[len(unique)-1] != namespace {
			unique = append(unique, namespace)
		}
	}
	if len(unique) == 0 {
		delete(match, "excludedNamespaces")
	} else {
		values := make([]interface{}, len(unique))
		for i, namespace := range unique {
			values[i] = namespace
		}
		match["excludedNamespaces"] = values
	}
	spec["match"] = match

	annotations := map[string]string{
		sourceAPIVersionAnnotation: constraint.GetAPIVersion(),
		sourceKindAnnotation:       constraint.GetKind(),
		sourceNameAnnotation:       constraint.GetName(),
		sourceUIDAnnotation:        string(constraint.GetUID()),
	}
	policy := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": RuntimePolicyAPIVersion,
		"kind":       RuntimePolicyKind,
		"metadata": map[string]interface{}{
			"name":        RuntimePolicyName(constraint),
			"labels":      map[string]interface{}{managedByLabel: managedByValue},
			"annotations": stringMapToInterfaceMap(annotations),
		},
		"spec": spec,
	}}
	policy.SetGroupVersionKind(schema.FromAPIVersionAndKind(RuntimePolicyAPIVersion, RuntimePolicyKind))
	if constraint.GetUID() != "" {
		controller := true
		blockOwnerDeletion := true
		policy.SetOwnerReferences([]metav1.OwnerReference{{
			APIVersion:         constraint.GetAPIVersion(),
			Kind:               constraint.GetKind(),
			Name:               constraint.GetName(),
			UID:                constraint.GetUID(),
			Controller:         &controller,
			BlockOwnerDeletion: &blockOwnerDeletion,
		}})
	}
	return policy, nil
}

// RuntimePolicyName returns the deterministic name of the RuntimePolicy owned
// by constraint. Kind is included so two Constraint kinds can reuse a name.
func RuntimePolicyName(constraint *unstructured.Unstructured) string {
	if constraint == nil {
		return "gatekeeper-runtime-invalid"
	}
	identity := constraint.GroupVersionKind().Group + "/" + constraint.GetKind() + "/" + constraint.GetName()
	sum := sha256.Sum256([]byte(identity))
	suffix := hex.EncodeToString(sum[:6])
	prefix := strings.ToLower("gatekeeper-" + constraint.GetKind() + "-" + constraint.GetName())
	prefix = sanitizeDNSSubdomain(prefix)
	maximumPrefix := 253 - 1 - len(suffix)
	if len(prefix) > maximumPrefix {
		prefix = strings.TrimRight(prefix[:maximumPrefix], "-.")
	}
	if prefix == "" {
		prefix = "gatekeeper-runtime"
	}
	return prefix + "-" + suffix
}

func sanitizeDNSSubdomain(value string) string {
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-.")
}

func projectRuntimePolicy(ctx context.Context, writer client.Client, reader client.Reader, constraint *unstructured.Unstructured, configuredExclusions []string) (ProjectionStatus, error) {
	desired, err := buildRuntimePolicyWithExclusions(constraint, configuredExclusions)
	if err != nil {
		return ProjectionStatus{}, err
	}
	if writer == nil {
		return ProjectionStatus{State: ProjectionPending, Message: fmt.Sprintf("validated RuntimePolicy %q (offline; not applied)", desired.GetName())}, nil
	}
	if reader == nil {
		reader = writer
	}

	current := RuntimePolicyWatchObject()
	key := types.NamespacedName{Name: desired.GetName()}
	if err := reader.Get(ctx, key, current); err != nil {
		if !apierrors.IsNotFound(err) {
			return ProjectionStatus{}, fmt.Errorf("get RuntimePolicy %q: %w", desired.GetName(), err)
		}
		if err := writer.Create(ctx, desired); err != nil {
			if !apierrors.IsAlreadyExists(err) {
				return ProjectionStatus{}, fmt.Errorf("create RuntimePolicy %q: %w", desired.GetName(), err)
			}
			// Multiple Gatekeeper processes can reconcile the same Constraint.
			// Treat a concurrent create as success, but re-read and verify
			// ownership before updating or reporting status.
			current = RuntimePolicyWatchObject()
			if err := reader.Get(ctx, key, current); err != nil {
				return ProjectionStatus{}, fmt.Errorf("get concurrently created RuntimePolicy %q: %w", desired.GetName(), err)
			}
		} else {
			return ProjectionStatus{State: ProjectionPending, Message: fmt.Sprintf("created RuntimePolicy %q; awaiting compilation and activation", desired.GetName())}, nil
		}
	}
	if err := verifyManagedPolicy(current, constraint); err != nil {
		return ProjectionStatus{}, err
	}

	updated := current.DeepCopy()
	updated.Object["spec"] = runtime.DeepCopyJSONValue(desired.Object["spec"])
	updated.SetOwnerReferences(desired.GetOwnerReferences())
	updated.SetLabels(mergeStringMaps(current.GetLabels(), desired.GetLabels()))
	updated.SetAnnotations(mergeStringMaps(current.GetAnnotations(), desired.GetAnnotations()))
	if !projectionEqual(current, updated) {
		if err := writer.Update(ctx, updated); err != nil {
			return ProjectionStatus{}, fmt.Errorf("update RuntimePolicy %q: %w", desired.GetName(), err)
		}
		return ProjectionStatus{State: ProjectionPending, Message: fmt.Sprintf("updated RuntimePolicy %q; awaiting compilation and activation", desired.GetName())}, nil
	}
	return runtimePolicyStatus(current), nil
}

func deleteRuntimePolicy(ctx context.Context, writer client.Client, reader client.Reader, constraint *unstructured.Unstructured) error {
	if writer == nil || constraint == nil {
		return nil
	}
	if reader == nil {
		reader = writer
	}
	current := RuntimePolicyWatchObject()
	key := types.NamespacedName{Name: RuntimePolicyName(constraint)}
	if err := reader.Get(ctx, key, current); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("get RuntimePolicy %q for deletion: %w", key.Name, err)
	}
	if err := verifyManagedPolicy(current, constraint); err != nil {
		return err
	}
	if err := writer.Delete(ctx, current); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete RuntimePolicy %q: %w", key.Name, err)
	}
	return nil
}

func verifyManagedPolicy(policy, constraint *unstructured.Unstructured) error {
	notManaged := func() error {
		return fmt.Errorf("RuntimePolicy %q already exists and is not managed for %s %q", policy.GetName(), constraint.GetKind(), constraint.GetName())
	}
	if policy.GetLabels()[managedByLabel] != managedByValue || constraint.GetUID() == "" {
		return notManaged()
	}
	annotations := policy.GetAnnotations()
	want := map[string]string{
		sourceAPIVersionAnnotation: constraint.GetAPIVersion(),
		sourceKindAnnotation:       constraint.GetKind(),
		sourceNameAnnotation:       constraint.GetName(),
		sourceUIDAnnotation:        string(constraint.GetUID()),
	}
	for key, value := range want {
		if annotations[key] != value {
			return notManaged()
		}
	}
	for _, owner := range policy.GetOwnerReferences() {
		if owner.Controller != nil && *owner.Controller &&
			owner.APIVersion == constraint.GetAPIVersion() &&
			owner.Kind == constraint.GetKind() &&
			owner.Name == constraint.GetName() &&
			owner.UID == constraint.GetUID() {
			return nil
		}
	}
	return notManaged()
}

func projectionEqual(left, right *unstructured.Unstructured) bool {
	return reflect.DeepEqual(left.Object["spec"], right.Object["spec"]) &&
		reflect.DeepEqual(left.GetLabels(), right.GetLabels()) &&
		reflect.DeepEqual(left.GetAnnotations(), right.GetAnnotations()) &&
		reflect.DeepEqual(left.GetOwnerReferences(), right.GetOwnerReferences())
}

func runtimePolicyStatus(policy *unstructured.Unstructured) ProjectionStatus {
	name := policy.GetName()
	observedGeneration, _, _ := unstructured.NestedInt64(policy.Object, "status", "observedGeneration")
	conditions, _, _ := unstructured.NestedSlice(policy.Object, "status", "conditions")
	condition := func(wanted string) (string, string, string, bool) {
		for _, raw := range conditions {
			entry, ok := raw.(map[string]interface{})
			if !ok || entry["type"] != wanted {
				continue
			}
			status, _ := entry["status"].(string)
			reason, _ := entry["reason"].(string)
			message, _ := entry["message"].(string)
			return status, reason, message, true
		}
		return "", "", "", false
	}
	if status, reason, message, found := condition("Accepted"); found && status == string(metav1.ConditionFalse) && observedGeneration == policy.GetGeneration() {
		return ProjectionStatus{State: ProjectionError, Message: conditionMessage(name, reason, message)}
	}
	if status, reason, message, found := condition("Compiled"); found && status == string(metav1.ConditionFalse) && observedGeneration == policy.GetGeneration() {
		return ProjectionStatus{State: ProjectionError, Message: conditionMessage(name, reason, message)}
	}
	if status, _, message, found := condition("Active"); found && status == string(metav1.ConditionTrue) && observedGeneration == policy.GetGeneration() {
		if message == "" {
			message = fmt.Sprintf("RuntimePolicy %q is active", name)
		}
		return ProjectionStatus{State: ProjectionActive, Message: message}
	}
	return ProjectionStatus{State: ProjectionPending, Message: fmt.Sprintf("RuntimePolicy %q is awaiting compilation and activation", name)}
}

func conditionMessage(name, reason, message string) string {
	if message == "" {
		message = reason
	}
	if message == "" {
		message = "runtime policy reconciliation failed"
	}
	return fmt.Sprintf("RuntimePolicy %q: %s", name, message)
}

func mergeStringMaps(current, desired map[string]string) map[string]string {
	merged := make(map[string]string, len(current)+len(desired))
	for key, value := range current {
		merged[key] = value
	}
	for key, value := range desired {
		merged[key] = value
	}
	return merged
}

func stringMapToInterfaceMap(values map[string]string) map[string]interface{} {
	out := make(map[string]interface{}, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}
