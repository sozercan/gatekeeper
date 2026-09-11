package export

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	connectionv1alpha1 "github.com/open-policy-agent/gatekeeper/v3/apis/connection/v1alpha1"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/export/dapr"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/export/disk"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/export/driver"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/export/testdriver"
	exportutil "github.com/open-policy-agent/gatekeeper/v3/pkg/export/util"
	anythingtypes "github.com/open-policy-agent/gatekeeper/v3/pkg/mutation/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	recordingDriverName                                     = "recording"
	unsupportedSource   connectionv1alpha1.ConnectionSource = "unknown-source"
)

var testSystem *System

func systemTestConnection(name, driver string, config interface{}, sources ...connectionv1alpha1.ConnectionSource) *connectionv1alpha1.Connection {
	return &connectionv1alpha1.Connection{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: connectionv1alpha1.ConnectionSpec{
			Driver: driver, Config: &anythingtypes.Anything{Value: config}, Sources: sources,
		},
	}
}

type recordingDriver struct {
	published []any
	updateErr error
}

func (driver *recordingDriver) Publish(_ context.Context, _ string, data interface{}, _ string) error {
	driver.published = append(driver.published, data)
	return nil
}

func (*recordingDriver) CloseConnection(string) error { return nil }

func (driver *recordingDriver) UpdateConnection(context.Context, string, interface{}) error {
	return driver.updateErr
}

func (*recordingDriver) CreateConnection(context.Context, string, interface{}) error { return nil }

func TestMain(m *testing.M) {
	ctx := context.Background()
	supportedDrivers = map[string]driver.Driver{
		dapr.Name: dapr.FakeConn,
	}
	testSystem = NewSystem()
	cfg := map[string]interface{}{
		dapr.Name: map[string]interface{}{
			"component": "pubsub",
		},
	}
	for name, fakeConn := range supportedDrivers {
		testSystem.connectionToDriver[name] = name
		testSystem.connectionSources[name] = []connectionv1alpha1.ConnectionSource{connectionv1alpha1.AuditSource, connectionv1alpha1.WebhookSource}
		_ = fakeConn.CreateConnection(ctx, name, cfg[name])
	}
	r := m.Run()
	for name, fakeConn := range testSystem.connectionToDriver {
		_ = supportedDrivers[fakeConn].CloseConnection(name)
	}

	if r != 0 {
		os.Exit(r)
	}
}

func TestNewSystem(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  *System
	}{
		{
			name: "requesting system",
			want: &System{
				connectionToDriver: map[string]string{},
				connectionSources:  map[string][]connectionv1alpha1.ConnectionSource{},
				connectionIdentity: map[string]connectionIdentity{},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ret := NewSystem()
			assert.Equal(t, ret, tc.want)
		})
	}
}

func TestSystem_UpsertConnection(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		config         interface{}
		connectionName string
		newDriver      string
		setup          func(*System) error
		wantErr        bool
	}{
		{
			name:           "new connection with supported driver",
			config:         map[string]interface{}{"component": "pubsub"},
			connectionName: "conn1",
			newDriver:      dapr.Name,
			setup: func(s *System) error {
				s.connectionToDriver = map[string]string{}
				supportedDrivers[dapr.Name] = dapr.FakeConn
				return nil
			},
			wantErr: false,
		},
		{
			name:           "update existing connection with same driver",
			config:         map[string]interface{}{"component": "pubsub1"},
			connectionName: "conn1",
			newDriver:      dapr.Name,
			setup: func(s *System) error {
				s.connectionToDriver["conn1"] = dapr.Name
				supportedDrivers[dapr.Name] = dapr.FakeConn
				return supportedDrivers[dapr.Name].CreateConnection(ctx, "conn1", map[string]interface{}{"component": "pubsub"})
			},
			wantErr: false,
		},
		{
			name:           "new connection with unsupported driver",
			config:         map[string]interface{}{"component": "pubsub"},
			connectionName: "conn3",
			newDriver:      "unsupportedDriver",
			setup:          func(_ *System) error { return nil },
			wantErr:        true,
		},
		{
			name:           "update existing connection with different driver",
			config:         map[string]interface{}{"component": "pubsub"},
			connectionName: "conn4",
			newDriver:      dapr.Name,
			setup: func(s *System) error {
				s.connectionToDriver["conn4"] = testdriver.Name
				supportedDrivers[dapr.Name] = dapr.FakeConn
				supportedDrivers[testdriver.Name] = testdriver.FakeConn
				return supportedDrivers[testdriver.Name].CreateConnection(ctx, "conn4", "config4")
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			system := NewSystem()
			if err := tt.setup(system); err != nil {
				t.Fatalf("failed to setup test: %v", err)
			}

			err := system.UpsertConnection(ctx, systemTestConnection(tt.connectionName, tt.newDriver, tt.config))
			if (err != nil) != tt.wantErr {
				t.Errorf("UpsertConnection() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				if driver, ok := system.connectionToDriver[tt.connectionName]; !ok || driver != tt.newDriver {
					t.Errorf("connection %s not found or driver mismatch: got %v, want %v", tt.connectionName, driver, tt.newDriver)
				}
			}
		})
	}
}

func TestSystem_CloseConnection(t *testing.T) {
	tests := []struct {
		name           string
		setup          func(*System)
		connectionName string
		wantErr        bool
	}{
		{
			name: "close existing connection",
			setup: func(s *System) {
				s.connectionToDriver["test-connection"] = dapr.Name
				supportedDrivers[dapr.Name] = dapr.FakeConn
				_ = dapr.FakeConn.CreateConnection(context.TODO(), "test-connection", map[string]interface{}{"component": "pubsub"})
			},
			connectionName: "test-connection",
			wantErr:        false,
		},
		{
			name: "close non-existing connection",
			setup: func(s *System) {
				// No setup needed for non-existing connection
				s.connectionToDriver = map[string]string{}
			},
			connectionName: "non-existing-connection",
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSystem()
			if tt.setup != nil {
				tt.setup(s)
			}

			err := s.CloseConnection(tt.connectionName)
			if (err != nil) != tt.wantErr {
				t.Errorf("CloseConnection() error = %v, wantErr %v", err, tt.wantErr)
			}

			if _, exists := s.connectionToDriver[tt.connectionName]; exists && !tt.wantErr {
				t.Errorf("connection %s still exists after CloseConnection", tt.connectionName)
			}
		})
	}
}

func TestSystem_Publish(t *testing.T) {
	type fields struct {
		connections map[string]string
	}
	type args struct {
		ctx        context.Context
		connection string
		topic      string
		msg        interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "There are no connections established",
			fields: fields{
				connections: nil,
			},
			args:    args{ctx: context.Background(), connection: "audit", topic: "test", msg: nil},
			wantErr: true,
		},
		{
			name: "Exporting to a connection that does not exist",
			fields: fields{
				connections: map[string]string{"audit": dapr.Name},
			},
			args:    args{ctx: context.Background(), connection: "test", topic: "test", msg: nil},
			wantErr: true,
		},
		{
			name: "Exporting to a connection that does exist",
			fields: fields{
				connections: testSystem.connectionToDriver,
			},
			args:    args{ctx: context.Background(), connection: "dapr", topic: "test", msg: nil},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &System{
				mux:                sync.RWMutex{},
				connectionToDriver: tt.fields.connections,
				connectionSources:  map[string][]connectionv1alpha1.ConnectionSource{"dapr": {connectionv1alpha1.AuditSource}},
			}
			if err := s.Publish(tt.args.ctx, connectionv1alpha1.AuditSource, tt.args.connection, tt.args.topic, tt.args.msg); (err != nil) != tt.wantErr {
				t.Errorf("System.Publish() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSystemPublishBatchFallbackPreservesMessageTypes(t *testing.T) {
	recorder := &recordingDriver{}
	oldDrivers := supportedDrivers
	supportedDrivers = map[string]driver.Driver{recordingDriverName: recorder}
	t.Cleanup(func() { supportedDrivers = oldDrivers })
	system := &System{
		connectionToDriver: map[string]string{"connection": recordingDriverName},
		connectionSources:  map[string][]connectionv1alpha1.ConnectionSource{"connection": {connectionv1alpha1.WebhookSource}},
	}
	raw := json.RawMessage(`{"eventType":"violation_admission"}`)
	typed := exportutil.ExportMsg{ID: "audit-1", Message: exportutil.AuditStartedMsg}

	errorsByMessage := system.PublishBatch(context.Background(), connectionv1alpha1.WebhookSource, "connection", "topic", []any{raw, typed})

	assert.Len(t, errorsByMessage, 2)
	assert.NoError(t, errorsByMessage[0])
	assert.NoError(t, errorsByMessage[1])
	assert.Equal(t, []any{raw, typed}, recorder.published)
}

func TestSystemSupportsAuditAndAdmissionOnSharedDiskConnection(t *testing.T) {
	oldDrivers := supportedDrivers
	supportedDrivers = map[string]driver.Driver{disk.Name: disk.Connections}
	t.Cleanup(func() { supportedDrivers = oldDrivers })

	ctx := context.Background()
	system := NewSystem()
	connectionName := "shared-disk-sources"
	path := t.TempDir()
	config := map[string]interface{}{
		"path":            path,
		"maxAuditResults": float64(1),
	}
	if err := system.UpsertConnection(ctx, systemTestConnection(connectionName, disk.Name, config)); err != nil {
		t.Fatalf("UpsertConnection() error = %v", err)
	}
	t.Cleanup(func() { _ = system.CloseConnection(connectionName) })

	if err := system.Publish(ctx, connectionv1alpha1.AuditSource, connectionName, "audit", exportutil.ExportMsg{ID: "audit-1", Message: exportutil.AuditStartedMsg}); err != nil {
		t.Fatalf("Publish(audit start) error = %v", err)
	}
	admission, err := json.Marshal(exportutil.ExportMsg{EventType: exportutil.AdmissionViolationEventType, ResourceName: "denied-pod"})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	batchResults := system.PublishBatch(ctx, connectionv1alpha1.WebhookSource, connectionName, "audit", []any{
		json.RawMessage(admission),
		exportutil.ExportMsg{EventType: exportutil.AdmissionViolationEventType, ResourceName: "second-denied-pod"},
	})
	for i, result := range batchResults {
		if result != nil {
			t.Fatalf("PublishBatch(admission) result %d error = %v", i, result)
		}
	}
	if err := system.Publish(ctx, connectionv1alpha1.AuditSource, connectionName, "audit", exportutil.ExportMsg{ID: "audit-1", Message: exportutil.AuditCompletedMsg}); err != nil {
		t.Fatalf("Publish(audit end) error = %v", err)
	}

	if _, err := os.Stat(filepath.Join(path, "audit", "audit-1.log")); err != nil {
		t.Fatalf("expected audit file: %v", err)
	}
	files, err := os.ReadDir(filepath.Join(path, "audit"))
	if err != nil || len(files) != 2 {
		t.Fatalf("expected audit and admission files in one channel, files=%v err=%v", files, err)
	}
	var foundAdmission bool
	for _, file := range files {
		foundAdmission = foundAdmission || strings.HasPrefix(file.Name(), "admission-")
	}
	if !foundAdmission {
		t.Fatalf("expected admission-prefixed file, got %v", files)
	}
}

func TestSystemAllowsRuntimeChannelForAuditAndAdmission(t *testing.T) {
	oldDrivers := supportedDrivers
	supportedDrivers = map[string]driver.Driver{disk.Name: disk.Connections}
	t.Cleanup(func() { supportedDrivers = oldDrivers })

	system := NewSystem()
	const connectionName = "audit-runtime-channel"
	const subject = "runtime"
	path := t.TempDir()
	require.NoError(t, system.UpsertConnection(t.Context(), systemTestConnection(connectionName, disk.Name, map[string]interface{}{
		"path":            path,
		"maxAuditResults": float64(1),
	}, connectionv1alpha1.AuditSource, connectionv1alpha1.WebhookSource)))
	t.Cleanup(func() { require.NoError(t, system.CloseConnection(connectionName)) })

	admission := exportutil.ExportMsg{EventType: exportutil.AdmissionViolationEventType, ResourceName: "denied-pod"}
	rawAdmission, err := json.Marshal(admission)
	require.NoError(t, err)
	for _, auditID := range []string{"audit-1", "audit-2"} {
		auditRecords := []exportutil.ExportMsg{
			{ID: auditID, Message: exportutil.AuditStartedMsg},
			{ID: auditID, Message: "missing required label", ResourceName: "existing-pod"},
			{ID: auditID, Message: exportutil.AuditCompletedMsg},
		}
		require.NoError(t, system.Publish(t.Context(), connectionv1alpha1.AuditSource, connectionName, subject, auditRecords[0]))
		require.NoError(t, system.Publish(t.Context(), connectionv1alpha1.WebhookSource, connectionName, subject, admission))
		for _, result := range system.PublishBatch(t.Context(), connectionv1alpha1.WebhookSource, connectionName, subject, []any{json.RawMessage(rawAdmission), admission}) {
			require.NoError(t, result)
		}
		for _, record := range auditRecords[1:] {
			require.NoError(t, system.Publish(t.Context(), connectionv1alpha1.AuditSource, connectionName, subject, record))
		}
		data, err := os.ReadFile(filepath.Join(path, subject, auditID+".log"))
		require.NoError(t, err, "the channel name must not change audit file handling")
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		require.Len(t, lines, len(auditRecords))
		for index, line := range lines {
			var record exportutil.ExportMsg
			require.NoError(t, json.Unmarshal([]byte(line), &record))
			require.Equal(t, auditRecords[index], record)
		}
	}

	require.NoFileExists(t, filepath.Join(path, subject, "audit-1.log"), "audit retention must still apply")
	require.FileExists(t, filepath.Join(path, subject, "audit-2.log"))
	files, err := filepath.Glob(filepath.Join(path, subject, "admission-*"))
	require.NoError(t, err)
	require.Len(t, files, 1, "admission must keep its separate spool")
	data, err := os.ReadFile(files[0])
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 6)
	for _, line := range lines {
		var record exportutil.ExportMsg
		require.NoError(t, json.Unmarshal([]byte(line), &record))
		require.Equal(t, admission, record, "audit records must not enter the admission spool")
	}
}

func TestSystem_closeConnection(t *testing.T) {
	ctx := context.Background()

	type args struct {
		connectionName string
	}
	tests := []struct {
		name                string
		setup               func(*System)
		args                args
		wantErr             bool
		expectConnectionDel bool
	}{
		{
			name: "close existing connection with supported driver",
			setup: func(s *System) {
				s.connectionToDriver["conn1"] = dapr.Name
				supportedDrivers[dapr.Name] = dapr.FakeConn
				_ = dapr.FakeConn.CreateConnection(ctx, "conn1", map[string]interface{}{"component": "pubsub"})
			},
			args:                args{connectionName: "conn1"},
			wantErr:             false,
			expectConnectionDel: true,
		},
		{
			name: "close connection with unsupported driver",
			setup: func(s *System) {
				s.connectionToDriver["conn2"] = "unsupported"
				// Do not add to supportedDrivers
			},
			args:                args{connectionName: "conn2"},
			wantErr:             false,
			expectConnectionDel: true,
		},
		{
			name: "close connection returns error from driver",
			setup: func(s *System) {
				s.connectionToDriver["conn3"] = testdriver.ErrName
				supportedDrivers[testdriver.ErrName] = testdriver.FakeErrConn
				_ = supportedDrivers[testdriver.ErrName].CreateConnection(ctx, "conn3", "config3")
			},
			args:                args{connectionName: "conn3"},
			wantErr:             true,
			expectConnectionDel: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSystem()
			if tt.setup != nil {
				tt.setup(s)
			}
			err := s.closeConnection(tt.args.connectionName)
			if (err != nil) != tt.wantErr {
				t.Errorf("closeConnection() error = %v, wantErr %v", err, tt.wantErr)
			}
			_, exists := s.connectionToDriver[tt.args.connectionName]
			if tt.expectConnectionDel && exists {
				t.Errorf("connection %s should have been deleted from map", tt.args.connectionName)
			}
		})
	}
}

type recordingBatchDriver struct{ recordingDriver }

func (driver *recordingBatchDriver) PublishBatch(_ context.Context, _ string, messages []any, _ string) []error {
	driver.published = append(driver.published, messages...)
	return make([]error, len(messages))
}

func TestSystemEnforcesProducerSourcesIndependentlyOfSubject(t *testing.T) {
	oldDrivers := supportedDrivers
	t.Cleanup(func() { supportedDrivers = oldDrivers })
	tests := []struct {
		name    string
		sources []connectionv1alpha1.ConnectionSource
		allowed []connectionv1alpha1.ConnectionSource
	}{
		{name: "omitted", allowed: []connectionv1alpha1.ConnectionSource{connectionv1alpha1.AuditSource, connectionv1alpha1.WebhookSource}},
		{name: "audit", sources: []connectionv1alpha1.ConnectionSource{connectionv1alpha1.AuditSource}, allowed: []connectionv1alpha1.ConnectionSource{connectionv1alpha1.AuditSource}},
		{name: "webhook", sources: []connectionv1alpha1.ConnectionSource{connectionv1alpha1.WebhookSource}, allowed: []connectionv1alpha1.ConnectionSource{connectionv1alpha1.WebhookSource}},
		{name: "audit and webhook", sources: []connectionv1alpha1.ConnectionSource{connectionv1alpha1.AuditSource, connectionv1alpha1.WebhookSource}, allowed: []connectionv1alpha1.ConnectionSource{connectionv1alpha1.AuditSource, connectionv1alpha1.WebhookSource}},
		{name: "runtime", sources: []connectionv1alpha1.ConnectionSource{connectionv1alpha1.RuntimeSource}, allowed: []connectionv1alpha1.ConnectionSource{connectionv1alpha1.RuntimeSource}},
	}
	for _, batched := range []bool{false, true} {
		for _, test := range tests {
			t.Run(fmt.Sprintf("%s/batched=%t", test.name, batched), func(t *testing.T) {
				recorder := &recordingDriver{}
				var backend driver.Driver = recorder
				if batched {
					batch := &recordingBatchDriver{}
					backend = batch
					recorder = &batch.recordingDriver
				}
				supportedDrivers = map[string]driver.Driver{recordingDriverName: backend}
				system := NewSystem()
				require.NoError(t, system.UpsertConnection(t.Context(), systemTestConnection("shared-name", recordingDriverName, nil, test.sources...)))
				for _, source := range []connectionv1alpha1.ConnectionSource{connectionv1alpha1.AuditSource, connectionv1alpha1.WebhookSource, connectionv1alpha1.RuntimeSource, "", unsupportedSource} {
					for _, subject := range []string{"audit-channel", "runtime"} {
						before := len(recorder.published)
						publishErr := system.Publish(t.Context(), source, "shared-name", subject, "single")
						batchErrors := system.PublishBatch(t.Context(), source, "shared-name", subject, []any{"first", "second"})
						require.Len(t, batchErrors, 2)
						if slices.Contains(test.allowed, source) {
							require.NoError(t, publishErr)
							require.NoError(t, batchErrors[0])
							require.NoError(t, batchErrors[1])
							require.Len(t, recorder.published, before+3)
						} else {
							require.Error(t, publishErr)
							require.Error(t, batchErrors[0])
							require.Error(t, batchErrors[1])
							require.Len(t, recorder.published, before, "disallowed source reached the backend")
						}
					}
				}
			})
		}
	}
}

func TestSystemSourceChangesAndInvalidReconfigurationRevokePublishing(t *testing.T) {
	oldDrivers := supportedDrivers
	t.Cleanup(func() { supportedDrivers = oldDrivers })
	recorder := &recordingDriver{}
	supportedDrivers = map[string]driver.Driver{recordingDriverName: recorder}
	system := NewSystem()
	require.NoError(t, system.UpsertConnection(t.Context(), systemTestConnection("shared-name", recordingDriverName, nil)))
	require.NoError(t, system.Publish(t.Context(), connectionv1alpha1.AuditSource, "shared-name", "runtime", "audit"))
	require.NoError(t, system.Publish(t.Context(), connectionv1alpha1.WebhookSource, "shared-name", "runtime", "admission"))

	sources := []connectionv1alpha1.ConnectionSource{connectionv1alpha1.RuntimeSource}
	require.NoError(t, system.UpsertConnection(t.Context(), systemTestConnection("shared-name", recordingDriverName, nil, sources...)))
	sources[0] = connectionv1alpha1.AuditSource
	require.Error(t, system.Publish(t.Context(), connectionv1alpha1.AuditSource, "shared-name", "runtime", "audit"))
	require.Error(t, system.Publish(t.Context(), connectionv1alpha1.WebhookSource, "shared-name", "runtime", "admission"))
	require.NoError(t, system.Publish(t.Context(), connectionv1alpha1.RuntimeSource, "shared-name", "runtime", "runtime"))

	for _, failure := range []struct {
		name      string
		driver    string
		sources   []connectionv1alpha1.ConnectionSource
		updateErr error
	}{
		{name: "invalid config", driver: recordingDriverName, sources: []connectionv1alpha1.ConnectionSource{connectionv1alpha1.AuditSource}, updateErr: errors.New("invalid config")},
		{name: "unsupported driver", driver: "unknown", sources: []connectionv1alpha1.ConnectionSource{connectionv1alpha1.RuntimeSource}},
		{name: "mixed runtime sources", driver: recordingDriverName, sources: []connectionv1alpha1.ConnectionSource{connectionv1alpha1.RuntimeSource, connectionv1alpha1.WebhookSource}},
		{name: "unknown source", driver: recordingDriverName, sources: []connectionv1alpha1.ConnectionSource{unsupportedSource}},
	} {
		t.Run(failure.name, func(t *testing.T) {
			recorder.updateErr = failure.updateErr
			require.Error(t, system.UpsertConnection(t.Context(), systemTestConnection("shared-name", failure.driver, nil, failure.sources...)))
			before := len(recorder.published)
			for _, source := range []connectionv1alpha1.ConnectionSource{connectionv1alpha1.AuditSource, connectionv1alpha1.WebhookSource, connectionv1alpha1.RuntimeSource} {
				require.Error(t, system.Publish(t.Context(), source, "shared-name", "runtime", "stale"))
				results := system.PublishBatch(t.Context(), source, "shared-name", "runtime", []any{"stale"})
				require.Len(t, results, 1)
				require.Error(t, results[0])
			}
			require.Len(t, recorder.published, before)
			recorder.updateErr = nil
			require.NoError(t, system.UpsertConnection(t.Context(), systemTestConnection("shared-name", recordingDriverName, nil, connectionv1alpha1.RuntimeSource)))
			require.NoError(t, system.Publish(t.Context(), connectionv1alpha1.RuntimeSource, "shared-name", "runtime", "recovered"))
		})
	}
	require.NoError(t, system.CloseConnection("shared-name"))
	require.Error(t, system.Publish(t.Context(), connectionv1alpha1.RuntimeSource, "shared-name", "runtime", "closed"))
}

func TestSystemConnectionBatchRequiresInitializedVersion(t *testing.T) {
	oldDrivers := supportedDrivers
	supportedDrivers = map[string]driver.Driver{disk.Name: disk.Connections}
	t.Cleanup(func() { supportedDrivers = oldDrivers })
	system := NewSystem()
	path := t.TempDir()
	connection := systemTestConnection("versioned-runtime", disk.Name, map[string]any{
		"path": path, "maxAuditResults": float64(3),
	}, connectionv1alpha1.RuntimeSource)
	connection.Namespace, connection.UID, connection.Generation = "gatekeeper-system", "original-uid", 1
	require.NoError(t, system.UpsertConnection(t.Context(), connection))
	t.Cleanup(func() { require.NoError(t, system.CloseConnection(connection.Name)) })
	messages := []any{exportutil.RuntimeFinding(`{"sequence":1}`), exportutil.RuntimeFinding(`{"sequence":2}`)}
	publish := func(connection *connectionv1alpha1.Connection) []error {
		return system.PublishBatchForConnection(t.Context(), connectionv1alpha1.RuntimeSource, connection, "runtime", messages)
	}
	for _, err := range publish(connection) {
		require.NoError(t, err)
	}
	for _, change := range []string{"namespace", "uid", "generation", "name", "missing"} {
		t.Run(change, func(t *testing.T) {
			requested := connection.DeepCopy()
			switch change {
			case "namespace":
				requested.Namespace = "different-namespace"
			case "uid":
				requested.UID = "replacement-uid"
			case "generation":
				requested.Generation++
			case "name":
				requested.Name = "different-name"
			case "missing":
				requested = nil
			}
			results := publish(requested)
			require.Len(t, results, len(messages))
			for _, err := range results {
				require.Error(t, err)
			}
		})
	}
	files, err := filepath.Glob(filepath.Join(path, "runtime", "*.open"))
	require.NoError(t, err)
	require.Len(t, files, 1)
	data, err := os.ReadFile(files[0])
	require.NoError(t, err)
	require.Equal(t, "{\"sequence\":1}\n{\"sequence\":2}\n", string(data), "mismatched versions must never reach the backend")

	old := connection.DeepCopy()
	connection.UID = "replacement-uid"
	for _, err := range publish(connection) {
		require.Error(t, err, "mutating the source object must not change initialized identity")
	}
	require.NoError(t, system.UpsertConnection(t.Context(), connection))
	for _, err := range publish(connection) {
		require.NoError(t, err)
	}
	for _, err := range publish(old) {
		require.Error(t, err)
	}
	connection.Generation++
	connection.Spec.Config.Value = "invalid config"
	require.Error(t, system.UpsertConnection(t.Context(), connection))
	for _, requested := range []*connectionv1alpha1.Connection{connection, old} {
		for _, err := range publish(requested) {
			require.Error(t, err, "failed reconfiguration must revoke every initialized identity")
		}
	}
}
