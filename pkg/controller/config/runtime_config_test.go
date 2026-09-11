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

package config

import (
	"context"
	"errors"
	"testing"

	configv1alpha1 "github.com/open-policy-agent/gatekeeper/v3/apis/config/v1alpha1"
	statusv1beta1 "github.com/open-policy-agent/gatekeeper/v3/apis/status/v1beta1"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/cachemanager"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/controller/config/process"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/fakes"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/keys"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/readiness"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/runtimepolicy"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/wildcard"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type configRuntimeProjector struct {
	validateErr  error
	refreshErr   error
	refreshCalls int
}

func (*configRuntimeProjector) ReconcileConstraint(context.Context, *unstructured.Unstructured) (runtimepolicy.ProjectionStatus, bool, error) {
	return runtimepolicy.ProjectionStatus{}, false, nil
}

func (*configRuntimeProjector) RuntimePolicyWatchObject() client.Object {
	return runtimepolicy.RuntimePolicyWatchObject()
}

func (p *configRuntimeProjector) ValidateConfig([]string) error {
	return p.validateErr
}

func (p *configRuntimeProjector) RefreshConfig(context.Context) error {
	p.refreshCalls++
	return p.refreshErr
}

func setupRuntimeConfigReconciler(t *testing.T, projector *configRuntimeProjector) (*ReconcileConfig, *process.Excluder, client.Client) {
	t.Helper()
	mgr, wm := setupManager(t)
	tracker := readiness.NewTracker(nil, false, false, false)
	config := &configv1alpha1.Config{
		ObjectMeta: metav1.ObjectMeta{Name: keys.Config.Name, Namespace: keys.Config.Namespace, UID: types.UID("config-uid"), Generation: 2},
		Spec: configv1alpha1.ConfigSpec{Match: []configv1alpha1.MatchEntry{{
			Processes: []string{"runtime"}, ExcludedNamespaces: []wildcard.Wildcard{"new-namespace"},
		}}},
	}
	pod := fakes.Pod(fakes.WithNamespace(keys.Config.Namespace), fakes.WithName("runtime-config-test"))
	kube := fake.NewClientBuilder().WithScheme(mgr.GetScheme()).WithObjects(config, pod).Build()
	excluder := process.New()
	excluder.Add([]configv1alpha1.MatchEntry{{Processes: []string{"runtime"}, ExcludedNamespaces: []wildcard.Wildcard{"old-namespace"}}})
	reg, err := wm.NewRegistrar("runtime-config-test", make(chan event.GenericEvent, 1))
	require.NoError(t, err)
	cacheManager, err := cachemanager.NewCacheManager(&cachemanager.Config{
		Tracker: tracker, ProcessExcluder: excluder, Registrar: reg, Reader: kube,
	})
	require.NoError(t, err)
	r, err := newReconciler(mgr, cacheManager, tracker, func(context.Context) (*corev1.Pod, error) { return pod, nil }, nil)
	require.NoError(t, err)
	r.reader, r.writer, r.statusClient, r.runtimeProjector = kube, kube, kube, projector
	return r, excluder, kube
}

func TestRuntimeConfigRefreshRetriesAfterExcluderChanged(t *testing.T) {
	ctx := context.Background()
	projector := &configRuntimeProjector{refreshErr: errors.New("runtime API unavailable")}
	r, excluder, kube := setupRuntimeConfigReconciler(t, projector)
	request := reconcile.Request{NamespacedName: keys.Config}
	_, err := r.Reconcile(ctx, request)
	require.ErrorContains(t, err, "runtime API unavailable")
	require.Equal(t, []string{"new-namespace"}, excluder.GetExcludedNamespaces(process.Runtime))
	require.Equal(t, 1, projector.refreshCalls)

	projector.refreshErr = nil
	_, err = r.Reconcile(ctx, request)
	require.NoError(t, err)
	require.Equal(t, 2, projector.refreshCalls, "the failed projection refresh must retry even though Config and the excluder are unchanged")
	_, err = r.Reconcile(ctx, request)
	require.NoError(t, err)
	require.Equal(t, 2, projector.refreshCalls, "a completed Config refresh should not repeat")
	statuses := &statusv1beta1.ConfigPodStatusList{}
	require.NoError(t, kube.List(ctx, statuses))
	require.Len(t, statuses.Items, 1)
	require.Empty(t, statuses.Items[0].Status.Errors)
}

func TestInvalidRuntimeConfigKeepsActiveExclusionsAndReportsStatus(t *testing.T) {
	ctx := context.Background()
	projector := &configRuntimeProjector{validateErr: errors.New("combined exclusions exceed maximum 256")}
	r, excluder, kube := setupRuntimeConfigReconciler(t, projector)
	request := reconcile.Request{NamespacedName: keys.Config}
	_, err := r.Reconcile(ctx, request)
	require.ErrorContains(t, err, "combined exclusions exceed maximum 256")
	require.Equal(t, []string{"old-namespace"}, excluder.GetExcludedNamespaces(process.Runtime))
	require.Zero(t, projector.refreshCalls)
	statuses := &statusv1beta1.ConfigPodStatusList{}
	require.NoError(t, kube.List(ctx, statuses))
	require.Len(t, statuses.Items, 1)
	require.Equal(t, int64(2), statuses.Items[0].Status.ObservedGeneration)
	require.Len(t, statuses.Items[0].Status.Errors, 1)
	require.Contains(t, statuses.Items[0].Status.Errors[0].Message, "combined exclusions exceed maximum 256")

	projector.validateErr = nil
	_, err = r.Reconcile(ctx, request)
	require.NoError(t, err)
	require.Equal(t, []string{"new-namespace"}, excluder.GetExcludedNamespaces(process.Runtime))
	require.Equal(t, 1, projector.refreshCalls)
	require.NoError(t, kube.List(ctx, statuses))
	require.Empty(t, statuses.Items[0].Status.Errors)
}
