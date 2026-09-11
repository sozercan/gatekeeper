package webhook

import (
	"context"
	"errors"
	"sync"
	"time"

	connectionv1alpha1 "github.com/open-policy-agent/gatekeeper/v3/apis/connection/v1alpha1"
	statusv1alpha1 "github.com/open-policy-agent/gatekeeper/v3/apis/status/v1alpha1"
	exportcontroller "github.com/open-policy-agent/gatekeeper/v3/pkg/controller/export"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type runtimeExportStatusReporter interface {
	ReportForConnection(context.Context, *connectionv1alpha1.Connection, statusv1alpha1.ConnectionPublishStatus) error
}

// runtimeExportStatus retains one bounded error set per Connection UID.
// The worker performs API writes separately from HTTP requests and expires idle
// entries after the healthy reporting interval.
type runtimeExportStatus struct {
	mu              sync.Mutex
	connections     map[runtimeConnectionKey]*runtimeConnectionPublishState
	reporter        runtimeExportStatusReporter
	statusInterval  time.Duration
	healthyInterval time.Duration
	now             func() time.Time
}

type runtimeConnectionKey struct {
	namespace string
	name      string
	uid       types.UID
}

func runtimeConnectionKeyFor(connection *connectionv1alpha1.Connection) runtimeConnectionKey {
	return runtimeConnectionKey{namespace: connection.Namespace, name: connection.Name, uid: connection.UID}
}

type runtimeConnectionPublishState struct {
	connection       *connectionv1alpha1.Connection
	state            exportPublishState
	inFlight         int
	lastActivity     time.Time
	reported         bool
	lastReport       time.Time
	lastReportActive bool
	lastReportErrors bool
}

func newRuntimeExportStatus(reporter runtimeExportStatusReporter) *runtimeExportStatus {
	return &runtimeExportStatus{
		connections:     make(map[runtimeConnectionKey]*runtimeConnectionPublishState),
		reporter:        reporter,
		statusInterval:  defaultExportStatusInterval,
		healthyInterval: defaultExportHealthyInterval,
		now:             time.Now,
	}
}

// begin binds an attempt to the Connection version read by the HTTP handler.
// Completion of an older in-flight request cannot overwrite a newer version.
func (status *runtimeExportStatus) begin(connection *connectionv1alpha1.Connection) *runtimeConnectionPublishState {
	if status == nil {
		return nil
	}
	status.mu.Lock()
	defer status.mu.Unlock()
	key := runtimeConnectionKeyFor(connection)
	entry := status.connections[key]
	if entry != nil && entry.connection.Generation > connection.Generation {
		return nil
	}
	if entry == nil || entry.connection.Generation != connection.Generation {
		entry = &runtimeConnectionPublishState{
			connection: &connectionv1alpha1.Connection{ObjectMeta: metav1.ObjectMeta{
				Name:       connection.Name,
				Namespace:  connection.Namespace,
				UID:        connection.UID,
				Generation: connection.Generation,
			}},
			state: newExportPublishState(),
		}
		status.connections[key] = entry
	}
	entry.inFlight++
	entry.lastActivity = status.now()
	return entry
}

func (status *runtimeExportStatus) record(entry *runtimeConnectionPublishState, results []error) {
	if status == nil || entry == nil {
		return
	}
	status.mu.Lock()
	defer status.mu.Unlock()
	if status.connections[runtimeConnectionKeyFor(entry.connection)] != entry {
		return
	}
	entry.inFlight--
	now := status.now().UTC()
	entry.lastActivity = now
	for _, err := range results {
		entry.state.record(now, err)
	}
}

// Every replica reports the publishes it handled, independently of leadership.
func (*runtimeExportStatus) NeedLeaderElection() bool { return false }

func (status *runtimeExportStatus) Start(ctx context.Context) error {
	ticker := time.NewTicker(status.statusInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			flushCtx, cancel := context.WithTimeout(context.Background(), exportStatusTimeout)
			status.reportPending(flushCtx, true)
			cancel()
			return nil
		case <-ticker.C:
			status.reportPending(ctx, false)
		}
	}
}

func (status *runtimeExportStatus) reportPending(ctx context.Context, force bool) {
	type snapshot struct {
		entry *runtimeConnectionPublishState
		state exportPublishState
	}
	status.mu.Lock()
	now := status.now()
	pending := make([]snapshot, 0, len(status.connections))
	for name, entry := range status.connections {
		if !entry.state.attempted {
			if entry.inFlight == 0 && now.Sub(entry.lastActivity) >= status.healthyInterval {
				delete(status.connections, name)
			}
			continue
		}
		if !force && entry.reported && !entry.lastReportErrors && len(entry.state.errors) == 0 && entry.state.active == entry.lastReportActive && now.Sub(entry.lastReport) < status.healthyInterval {
			continue
		}
		pending = append(pending, snapshot{entry: entry, state: entry.state})
		entry.state = newExportPublishState()
	}
	status.mu.Unlock()

	for _, snapshot := range pending {
		reportCtx, cancel := context.WithTimeout(ctx, exportStatusTimeout)
		err := status.reporter.ReportForConnection(reportCtx, snapshot.entry.connection, snapshot.state.status(statusv1alpha1.RuntimePublishSource))
		cancel()
		status.mu.Lock()
		key := runtimeConnectionKeyFor(snapshot.entry.connection)
		entry := status.connections[key]
		if entry != snapshot.entry {
			status.mu.Unlock()
			continue
		}
		switch {
		case apierrors.IsNotFound(err), errors.Is(err, exportcontroller.ErrStaleConnectionPublishStatus):
			delete(status.connections, key)
		case err != nil:
			entry.state.merge(snapshot.state)
		case err == nil:
			entry.reported = true
			entry.lastReport = status.now()
			entry.lastReportActive = snapshot.state.active
			entry.lastReportErrors = len(snapshot.state.errors) > 0
		}
		status.mu.Unlock()
		if err != nil && !apierrors.IsNotFound(err) && !errors.Is(err, exportcontroller.ErrStaleConnectionPublishStatus) {
			log.Error(err, "reporting runtime export connection status", "connection", snapshot.entry.connection.Name)
		}
	}
}
