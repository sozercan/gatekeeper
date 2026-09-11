package webhook

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	connectionv1alpha1 "github.com/open-policy-agent/gatekeeper/v3/apis/connection/v1alpha1"
	statusv1alpha1 "github.com/open-policy-agent/gatekeeper/v3/apis/status/v1alpha1"
	exportcontroller "github.com/open-policy-agent/gatekeeper/v3/pkg/controller/export"
	gatekeeperexport "github.com/open-policy-agent/gatekeeper/v3/pkg/export"
	exportutil "github.com/open-policy-agent/gatekeeper/v3/pkg/export/util"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/fakes"
	anythingtypes "github.com/open-policy-agent/gatekeeper/v3/pkg/mutation/types"
	"github.com/open-policy-agent/gatekeeper/v3/test/testutils"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	runtimeStatusNamespace      = "gatekeeper-system"
	runtimeStatusConnectionName = "runtime-connection"
)

type runtimeExportStatusReport struct {
	connection *connectionv1alpha1.Connection
	status     statusv1alpha1.ConnectionPublishStatus
}

type fakeRuntimeExportStatusReporter struct {
	reports []runtimeExportStatusReport
	report  func(context.Context, *connectionv1alpha1.Connection, statusv1alpha1.ConnectionPublishStatus) error
}

func (reporter *fakeRuntimeExportStatusReporter) ReportForConnection(ctx context.Context, connection *connectionv1alpha1.Connection, status statusv1alpha1.ConnectionPublishStatus) error {
	if reporter.report != nil {
		return reporter.report(ctx, connection, status)
	}
	reporter.reports = append(reporter.reports, runtimeExportStatusReport{connection: connection.DeepCopy(), status: status})
	return nil
}

func runtimeStatusTestConnection() *connectionv1alpha1.Connection {
	return &connectionv1alpha1.Connection{
		ObjectMeta: metav1.ObjectMeta{Name: runtimeStatusConnectionName, Namespace: runtimeStatusNamespace, UID: "connection-uid", Generation: 1},
		Spec:       connectionv1alpha1.ConnectionSpec{Sources: []connectionv1alpha1.ConnectionSource{connectionv1alpha1.RuntimeSource}},
	}
}

func serveRuntimeStatusTestRequest(handler *runtimeExportHandler) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, runtimeExportPathPrefix+runtimeStatusConnectionName, strings.NewReader(validRuntimeExportBody))
	request.Header.Set("Authorization", "Bearer test-token")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestRuntimeExportStatusReportsFailureAndRecoveryForOwningPod(t *testing.T) {
	testutils.Setenv(t, "POD_NAMESPACE", runtimeStatusNamespace)
	exporter := &recordingRuntimeExporter{publishErr: errors.New("backend unavailable: request details")}
	handler := newRuntimeExportTestHandler(t, exporter, []connectionv1alpha1.ConnectionSource{connectionv1alpha1.RuntimeSource}, nil, true, true, nil)
	k8sClient, ok := handler.reader.(client.Client)
	require.True(t, ok)
	require.NoError(t, statusv1alpha1.AddToScheme(k8sClient.Scheme()))
	require.NoError(t, corev1.AddToScheme(k8sClient.Scheme()))
	pod := fakes.Pod(fakes.WithNamespace(runtimeStatusNamespace), fakes.WithName("runtime-pod"))
	handler.statuses = newRuntimeExportStatus(&connectionStatusReporter{
		reader: k8sClient,
		writer: k8sClient,
		scheme: k8sClient.Scheme(),
		getPod: func(context.Context) (*corev1.Pod, error) { return pod, nil },
	})
	now := time.Unix(100, 0)
	handler.statuses.now = func() time.Time { return now }

	response := serveRuntimeStatusTestRequest(handler)
	require.Equal(t, http.StatusServiceUnavailable, response.Code)
	statuses := &statusv1alpha1.ConnectionPodStatusList{}
	require.NoError(t, k8sClient.List(t.Context(), statuses))
	require.Empty(t, statuses.Items, "HTTP handlers must not write publishing status")
	handler.statuses.reportPending(t.Context(), false)
	require.NoError(t, k8sClient.List(t.Context(), statuses))
	require.Len(t, statuses.Items, 1)
	podStatus := &statuses.Items[0]
	require.Equal(t, pod.Name, podStatus.Status.ID)
	require.Len(t, podStatus.Status.PublishStatuses, 1)
	publish := podStatus.Status.PublishStatuses[0]
	require.Equal(t, statusv1alpha1.RuntimePublishSource, publish.Source)
	require.False(t, publish.Active)
	require.Equal(t, now.UTC(), publish.LastAttemptTime.UTC())
	require.Nil(t, publish.LastSuccessTime)
	require.Equal(t, []*statusv1alpha1.ConnectionError{{Type: statusv1alpha1.PublishError, Message: "backend unavailable"}}, publish.Errors)

	now = now.Add(time.Second)
	exporter.publishErr = nil
	require.Equal(t, http.StatusAccepted, serveRuntimeStatusTestRequest(handler).Code)
	handler.statuses.reportPending(t.Context(), false)
	require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKeyFromObject(podStatus), podStatus))
	publish = podStatus.Status.PublishStatuses[0]
	require.True(t, publish.Active)
	require.Empty(t, publish.Errors)
	require.Equal(t, now.UTC(), publish.LastAttemptTime.UTC())
	require.Equal(t, now.UTC(), publish.LastSuccessTime.UTC())

	lastSuccess := now
	now = now.Add(time.Second)
	exporter.publishErr = errors.New("backend unavailable: later request")
	require.Equal(t, http.StatusServiceUnavailable, serveRuntimeStatusTestRequest(handler).Code)
	handler.statuses.reportPending(t.Context(), false)
	require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKeyFromObject(podStatus), podStatus))
	publish = podStatus.Status.PublishStatuses[0]
	require.False(t, publish.Active)
	require.Equal(t, lastSuccess.UTC(), publish.LastSuccessTime.UTC(), "failure must preserve the previous success time")
}

func TestRuntimeExportStatusDoesNotBlockHTTP(t *testing.T) {
	statusStarted := make(chan struct{})
	releaseStatus := make(chan struct{})
	var once sync.Once
	reporter := &fakeRuntimeExportStatusReporter{report: func(context.Context, *connectionv1alpha1.Connection, statusv1alpha1.ConnectionPublishStatus) error {
		once.Do(func() {
			close(statusStarted)
			<-releaseStatus
		})
		return nil
	}}
	handler := newRuntimeExportTestHandler(t, &recordingRuntimeExporter{}, []connectionv1alpha1.ConnectionSource{connectionv1alpha1.RuntimeSource}, nil, true, true, nil)
	handler.statuses = newRuntimeExportStatus(reporter)
	handler.statuses.statusInterval = time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- handler.statuses.Start(ctx) }()
	t.Cleanup(func() {
		close(releaseStatus)
		cancel()
		require.NoError(t, <-done)
	})
	require.False(t, handler.statuses.NeedLeaderElection())
	require.Equal(t, http.StatusAccepted, serveRuntimeStatusTestRequest(handler).Code)
	select {
	case <-statusStarted:
	case <-time.After(time.Second):
		t.Fatal("publishing status worker did not start")
	}
	response := make(chan int, 1)
	go func() { response <- serveRuntimeStatusTestRequest(handler).Code }()
	select {
	case code := <-response:
		require.Equal(t, http.StatusAccepted, code)
	case <-time.After(time.Second):
		t.Fatal("status API write blocked an HTTP request")
	}
}

func TestRuntimeExportStatusBoundsErrorsThrottlesHealthyWritesAndExpiresIdleConnections(t *testing.T) {
	reporter := &fakeRuntimeExportStatusReporter{}
	status := newRuntimeExportStatus(reporter)
	now := time.Unix(100, 0)
	status.now = func() time.Time { return now }
	connection := runtimeStatusTestConnection()
	results := make([]error, exportutil.MaxConnectionStatusErrors+5)
	for i := range results {
		results[i] = fmt.Errorf("failure-%d: details", i)
	}
	status.record(status.begin(connection), results)
	require.Len(t, status.connections, 1)
	status.reportPending(t.Context(), false)
	require.Len(t, reporter.reports, 1)
	require.Len(t, reporter.reports[0].status.Errors, exportutil.MaxConnectionStatusErrors)

	status.record(status.begin(connection), []error{nil})
	status.reportPending(t.Context(), false)
	require.Len(t, reporter.reports, 2, "recovery must bypass healthy throttling")
	require.Empty(t, reporter.reports[1].status.Errors)
	for range 100 {
		status.record(status.begin(connection), []error{nil})
		status.reportPending(t.Context(), false)
	}
	require.Len(t, reporter.reports, 2)
	now = now.Add(status.healthyInterval)
	status.reportPending(t.Context(), false)
	require.Len(t, reporter.reports, 3)
	now = now.Add(status.healthyInterval)
	status.reportPending(t.Context(), false)
	require.Empty(t, status.connections)

	attempt := status.begin(connection)
	now = now.Add(2 * status.healthyInterval)
	status.reportPending(t.Context(), false)
	require.Len(t, status.connections, 1, "an in-flight publish must survive idle cleanup")
	status.record(attempt, []error{nil})
	status.reportPending(t.Context(), false)
	require.Len(t, reporter.reports, 4)
}

func TestRuntimeExportStatusMergesFailedSnapshotsWithConcurrentResults(t *testing.T) {
	reporter := &fakeRuntimeExportStatusReporter{}
	status := newRuntimeExportStatus(reporter)
	connection := runtimeStatusTestConnection()
	now := time.Unix(100, 0)
	status.now = func() time.Time { return now }
	status.record(status.begin(connection), []error{errors.New("backend failed: initial")})
	reporter.report = func(context.Context, *connectionv1alpha1.Connection, statusv1alpha1.ConnectionPublishStatus) error {
		now = now.Add(time.Second)
		status.record(status.begin(connection), []error{nil})
		return errors.New("API unavailable")
	}
	status.reportPending(t.Context(), false)
	reporter.report = nil
	status.reportPending(t.Context(), false)
	require.Len(t, reporter.reports, 1)
	report := reporter.reports[0].status
	require.True(t, report.Active)
	require.Equal(t, now.UTC(), report.LastSuccessTime.UTC())
	require.Equal(t, now.UTC(), report.LastAttemptTime.UTC())
	require.Equal(t, []*statusv1alpha1.ConnectionError{{Type: statusv1alpha1.PublishError, Message: "backend failed"}}, report.Errors)
}

func TestRuntimeExportStatusDiscardsSupersededAndDeletedConnections(t *testing.T) {
	const generationChange = "generation"
	for _, change := range []string{generationChange, "uid"} {
		t.Run(change, func(t *testing.T) {
			reporter := &fakeRuntimeExportStatusReporter{}
			status := newRuntimeExportStatus(reporter)
			connection := runtimeStatusTestConnection()
			oldAttempt := status.begin(connection)
			current := connection.DeepCopy()
			if change == generationChange {
				current.Generation++
			} else {
				current.UID = types.UID("replacement-uid")
			}
			reporter.report = func(_ context.Context, connection *connectionv1alpha1.Connection, publish statusv1alpha1.ConnectionPublishStatus) error {
				if connection.UID != current.UID || connection.Generation != current.Generation {
					return exportcontroller.ErrStaleConnectionPublishStatus
				}
				reporter.reports = append(reporter.reports, runtimeExportStatusReport{connection: connection.DeepCopy(), status: publish})
				return nil
			}
			status.record(status.begin(current), []error{nil})
			status.record(oldAttempt, []error{errors.New("obsolete failure")})
			if change == generationChange {
				require.Nil(t, status.begin(connection))
			}
			status.reportPending(t.Context(), false)
			require.Len(t, reporter.reports, 1)
			require.Equal(t, current.UID, reporter.reports[0].connection.UID)
			require.Equal(t, current.Generation, reporter.reports[0].connection.Generation)
			require.Empty(t, reporter.reports[0].status.Errors)
		})
	}
	for _, reportErr := range []error{
		apierrors.NewNotFound(schema.GroupResource{Group: "connection.gatekeeper.sh", Resource: "connections"}, runtimeStatusConnectionName),
		exportcontroller.ErrStaleConnectionPublishStatus,
	} {
		reporter := &fakeRuntimeExportStatusReporter{report: func(context.Context, *connectionv1alpha1.Connection, statusv1alpha1.ConnectionPublishStatus) error {
			return reportErr
		}}
		status := newRuntimeExportStatus(reporter)
		status.record(status.begin(runtimeStatusTestConnection()), []error{nil})
		status.reportPending(t.Context(), false)
		require.Empty(t, status.connections)
	}
}

func newRuntimeDiskStatusTestHandler(t *testing.T, path string) (*runtimeExportHandler, *gatekeeperexport.System, client.Client, *connectionv1alpha1.Connection) {
	t.Helper()
	testutils.Setenv(t, "POD_NAMESPACE", runtimeStatusNamespace)
	exporter := gatekeeperexport.NewSystem()
	t.Cleanup(func() { require.NoError(t, exporter.CloseConnection(runtimeStatusConnectionName)) })
	handler := newRuntimeExportTestHandler(t, exporter, []connectionv1alpha1.ConnectionSource{connectionv1alpha1.RuntimeSource}, nil, true, true, nil)
	k8sClient, ok := handler.reader.(client.Client)
	if !ok {
		t.Fatal("runtime handler reader does not implement client.Client")
	}
	require.NoError(t, statusv1alpha1.AddToScheme(k8sClient.Scheme()))
	require.NoError(t, corev1.AddToScheme(k8sClient.Scheme()))
	connection := &connectionv1alpha1.Connection{}
	require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKey{Namespace: runtimeStatusNamespace, Name: runtimeStatusConnectionName}, connection))
	connection.UID, connection.Generation = "original-uid", 1
	connection.Spec.Driver = "disk"
	connection.Spec.Config = &anythingtypes.Anything{Value: map[string]any{"path": path, "maxAuditResults": float64(3)}}
	require.NoError(t, k8sClient.Update(t.Context(), connection))
	require.NoError(t, exporter.UpsertConnection(t.Context(), connection))
	pod := fakes.Pod(fakes.WithNamespace(runtimeStatusNamespace), fakes.WithName("runtime-version-pod"))
	handler.statuses = newRuntimeExportStatus(&connectionStatusReporter{
		reader: k8sClient, writer: k8sClient, scheme: k8sClient.Scheme(),
		getPod: func(context.Context) (*corev1.Pod, error) { return pod, nil },
	})
	return handler, exporter, k8sClient, connection
}

func TestRuntimeExportStatusWaitsForInitializedGeneration(t *testing.T) {
	oldPath, newPath := t.TempDir(), t.TempDir()
	handler, exporter, k8sClient, connection := newRuntimeDiskStatusTestHandler(t, oldPath)
	now := time.Unix(100, 0)
	handler.statuses.now = func() time.Time { return now }
	require.Equal(t, http.StatusAccepted, serveRuntimeStatusTestRequest(handler).Code)
	handler.statuses.reportPending(t.Context(), false)

	// The direct API read can see the new generation before the local
	// Connection reconciler has applied it to the initialized backend.
	connection.Generation++
	connection.Spec.Config = &anythingtypes.Anything{Value: map[string]any{"path": newPath, "maxAuditResults": float64(3)}}
	require.NoError(t, k8sClient.Update(t.Context(), connection))
	now = now.Add(2 * time.Minute)
	require.Equal(t, http.StatusServiceUnavailable, serveRuntimeStatusTestRequest(handler).Code)
	handler.statuses.reportPending(t.Context(), false)
	statuses := &statusv1alpha1.ConnectionPodStatusList{}
	require.NoError(t, k8sClient.List(t.Context(), statuses))
	require.Len(t, statuses.Items, 1)
	status := statuses.Items[0].Status
	require.Equal(t, connection.Generation, status.ObservedGeneration)
	require.Len(t, status.PublishStatuses, 1)
	require.False(t, status.PublishStatuses[0].Active)
	require.Nil(t, status.PublishStatuses[0].LastSuccessTime, "the old backend's success must not be carried into the new generation")
	require.Equal(t, []*statusv1alpha1.ConnectionError{{Type: statusv1alpha1.PublishError, Message: "connection configuration is not initialized"}}, status.PublishStatuses[0].Errors)
	files, err := filepath.Glob(filepath.Join(oldPath, "runtime", "*.open"))
	require.NoError(t, err)
	require.Len(t, files, 1)
	stored, err := os.ReadFile(files[0])
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(stored), "\n"), "the request for the new version must not write to the old backend")
	files, err = filepath.Glob(filepath.Join(newPath, "runtime", "*"))
	require.NoError(t, err)
	require.Empty(t, files)

	require.NoError(t, exporter.UpsertConnection(t.Context(), connection))
	now = now.Add(time.Second)
	require.Equal(t, http.StatusAccepted, serveRuntimeStatusTestRequest(handler).Code)
	handler.statuses.reportPending(t.Context(), false)
	require.NoError(t, k8sClient.List(t.Context(), statuses))
	status = statuses.Items[0].Status
	require.Equal(t, connection.Generation, status.ObservedGeneration)
	require.True(t, status.PublishStatuses[0].Active)
	require.Empty(t, status.PublishStatuses[0].Errors)
	require.Equal(t, now.UTC(), status.PublishStatuses[0].LastSuccessTime.UTC())
	files, err = filepath.Glob(filepath.Join(newPath, "runtime", "*.open"))
	require.NoError(t, err)
	require.Len(t, files, 1)
	stored, err = os.ReadFile(files[0])
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(stored), "\n"))
}

type delayedRuntimeConnectionReader struct {
	client.Reader
	afterRead func(*connectionv1alpha1.Connection)
}

func (reader *delayedRuntimeConnectionReader) Get(ctx context.Context, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
	if err := reader.Reader.Get(ctx, key, object, options...); err != nil {
		return err
	}
	if connection, ok := object.(*connectionv1alpha1.Connection); ok {
		reader.afterRead(connection)
	}
	return nil
}

type delayedRuntimeConnectionExporter struct {
	gatekeeperexport.ConnectionBatchExporter
	afterPublish func(*connectionv1alpha1.Connection)
}

func (exporter *delayedRuntimeConnectionExporter) PublishBatchForConnection(ctx context.Context, source connectionv1alpha1.ConnectionSource, connection *connectionv1alpha1.Connection, subject string, messages []any) []error {
	results := exporter.ConnectionBatchExporter.PublishBatchForConnection(ctx, source, connection, subject, messages)
	exporter.afterPublish(connection)
	return results
}

func TestRuntimeExportStatusPreservesReplacementDuringOlderRequests(t *testing.T) {
	for _, phase := range []string{"connection read", "publish completion"} {
		t.Run(phase, func(t *testing.T) {
			path := t.TempDir()
			handler, exporter, k8sClient, original := newRuntimeDiskStatusTestHandler(t, path)
			started, release := make(chan struct{}), make(chan struct{})
			var once, releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			delay := func(connection *connectionv1alpha1.Connection) {
				if connection.UID == original.UID {
					once.Do(func() { close(started); <-release })
				}
			}
			if phase == "connection read" {
				handler.reader = &delayedRuntimeConnectionReader{Reader: handler.reader, afterRead: delay}
			} else {
				handler.exporter = &delayedRuntimeConnectionExporter{ConnectionBatchExporter: exporter, afterPublish: delay}
			}
			response, finished := make(chan int, 1), make(chan struct{})
			go func() {
				defer close(finished)
				response <- serveRuntimeStatusTestRequest(handler).Code
			}()
			t.Cleanup(func() {
				unblock()
				select {
				case <-finished:
				case <-time.After(time.Second):
					t.Error("older runtime request did not finish")
				}
			})
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("older runtime request did not reach the delayed phase")
			}
			current := original.DeepCopy()
			current.UID = "replacement-uid"
			require.NoError(t, k8sClient.Update(t.Context(), current))
			require.NoError(t, exporter.UpsertConnection(t.Context(), current))
			require.Equal(t, http.StatusAccepted, serveRuntimeStatusTestRequest(handler).Code)
			unblock()
			expectedCode, expectedRecords := http.StatusAccepted, 2
			if phase == "connection read" {
				expectedCode, expectedRecords = http.StatusServiceUnavailable, 1
			}
			require.Equal(t, expectedCode, <-response)
			handler.statuses.reportPending(t.Context(), false)
			statuses := &statusv1alpha1.ConnectionPodStatusList{}
			require.NoError(t, k8sClient.List(t.Context(), statuses))
			require.Len(t, statuses.Items, 1)
			status := statuses.Items[0].Status
			require.Equal(t, current.UID, status.ConnectionUID)
			require.Len(t, status.PublishStatuses, 1)
			require.True(t, status.PublishStatuses[0].Active)
			require.Empty(t, status.PublishStatuses[0].Errors)
			require.Len(t, handler.statuses.connections, 1, "the obsolete UID must be discarded without erasing the replacement")
			files, err := filepath.Glob(filepath.Join(path, "runtime", "*.open"))
			require.NoError(t, err)
			require.Len(t, files, 1)
			stored, err := os.ReadFile(files[0])
			require.NoError(t, err)
			require.Equal(t, expectedRecords, strings.Count(string(stored), "\n"))
		})
	}
}
