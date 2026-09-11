package export

import (
	"context"
	"fmt"
	"slices"
	"sync"

	connectionv1alpha1 "github.com/open-policy-agent/gatekeeper/v3/apis/connection/v1alpha1"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/export/dapr"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/export/disk"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/export/driver"
	"k8s.io/apimachinery/pkg/types"
)

var supportedDrivers = map[string]driver.Driver{
	dapr.Name: dapr.Connections,
	disk.Name: disk.Connections,
}

type Exporter interface {
	Publish(ctx context.Context, source connectionv1alpha1.ConnectionSource, connectionName string, subject string, msg interface{}) error
	UpsertConnection(ctx context.Context, connection *connectionv1alpha1.Connection) error
	CloseConnection(connectionName string) error
}

// BatchExporter is an optional extension for bounded batches. Returned errors
// correspond one-to-one with messages in input order. Callers fall back to
// Exporter.Publish when it is unavailable.
type BatchExporter interface {
	PublishBatch(ctx context.Context, source connectionv1alpha1.ConnectionSource, connectionName string, subject string, messages []any) []error
}

// ConnectionBatchExporter publishes only through the exact Connection version
// supplied by the caller. Runtime producers require this interface so success
// cannot be attributed to a configuration the local driver has not applied.
type ConnectionBatchExporter interface {
	PublishBatchForConnection(ctx context.Context, source connectionv1alpha1.ConnectionSource, connection *connectionv1alpha1.Connection, subject string, messages []any) []error
}

type connectionIdentity struct {
	namespace  string
	uid        types.UID
	generation int64
}

func identityForConnection(connection *connectionv1alpha1.Connection) connectionIdentity {
	return connectionIdentity{namespace: connection.Namespace, uid: connection.UID, generation: connection.Generation}
}

type System struct {
	mux                sync.RWMutex
	connectionToDriver map[string]string
	connectionSources  map[string][]connectionv1alpha1.ConnectionSource
	connectionIdentity map[string]connectionIdentity
}

func NewSystem() *System {
	return &System{
		connectionToDriver: map[string]string{},
		connectionSources:  map[string][]connectionv1alpha1.ConnectionSource{},
		connectionIdentity: map[string]connectionIdentity{},
	}
}

func (s *System) Publish(ctx context.Context, source connectionv1alpha1.ConnectionSource, connectionName string, subject string, msg interface{}) error {
	s.mux.RLock()
	defer s.mux.RUnlock()
	if err := s.requireSource(connectionName, source); err != nil {
		return err
	}
	if dName, ok := s.connectionToDriver[connectionName]; ok {
		return supportedDrivers[dName].Publish(ctx, connectionName, msg, subject)
	}
	return fmt.Errorf("connection is not initialized, name: %s ", connectionName)
}

func (s *System) PublishBatch(ctx context.Context, source connectionv1alpha1.ConnectionSource, connectionName string, subject string, messages []any) []error {
	s.mux.RLock()
	defer s.mux.RUnlock()
	return s.publishBatch(ctx, source, connectionName, subject, messages)
}

func (s *System) PublishBatchForConnection(ctx context.Context, source connectionv1alpha1.ConnectionSource, connection *connectionv1alpha1.Connection, subject string, messages []any) []error {
	if connection == nil {
		return batchErrors(len(messages), fmt.Errorf("connection is required for publishing"))
	}
	s.mux.RLock()
	defer s.mux.RUnlock()
	identity, ok := s.connectionIdentity[connection.Name]
	if !ok || identity != identityForConnection(connection) {
		return batchErrors(len(messages), fmt.Errorf("connection configuration is not initialized: %s", connection.Name))
	}
	return s.publishBatch(ctx, source, connection.Name, subject, messages)
}

// publishBatch runs with the System read lock held, keeping identity and source
// checks atomic with the backend operation and Connection reconfiguration.
func (s *System) publishBatch(ctx context.Context, source connectionv1alpha1.ConnectionSource, connectionName string, subject string, messages []any) []error {
	if err := s.requireSource(connectionName, source); err != nil {
		return batchErrors(len(messages), err)
	}
	driverName, ok := s.connectionToDriver[connectionName]
	if !ok {
		return batchErrors(len(messages), fmt.Errorf("connection is not initialized, name: %s ", connectionName))
	}
	connectionDriver := supportedDrivers[driverName]
	if batchDriver, ok := connectionDriver.(driver.BatchDriver); ok {
		return batchDriver.PublishBatch(ctx, connectionName, messages, subject)
	}
	errorsByMessage := make([]error, len(messages))
	for i := range messages {
		errorsByMessage[i] = connectionDriver.Publish(ctx, connectionName, messages[i], subject)
	}
	return errorsByMessage
}

func batchErrors(count int, err error) []error {
	errorsByMessage := make([]error, count)
	for i := range errorsByMessage {
		errorsByMessage[i] = err
	}
	return errorsByMessage
}

// requireSource checks the producer independently of the configurable subject.
// The System lock keeps source changes atomic with driver reconfiguration.
func (s *System) requireSource(connectionName string, source connectionv1alpha1.ConnectionSource) error {
	if !slices.Contains(s.connectionSources[connectionName], source) {
		return fmt.Errorf("connection does not allow export source %q: %s", source, connectionName)
	}
	return nil
}

func (s *System) UpsertConnection(ctx context.Context, connection *connectionv1alpha1.Connection) error {
	if connection == nil {
		return fmt.Errorf("connection is required for initialization")
	}
	s.mux.Lock()
	defer s.mux.Unlock()
	connectionName, newDriver := connection.Name, connection.Spec.Driver
	// Revoke the old source policy before touching the driver. Failed updates
	// must not keep publishing through an older configuration.
	s.connectionSources[connectionName] = nil
	delete(s.connectionIdentity, connectionName)
	if connection.Spec.Config == nil {
		return fmt.Errorf("connection config is required: %s", connectionName)
	}
	config := connection.Spec.Config.Value
	sources := connection.Spec.Sources
	if connection.AllowsRuntimeSource() {
		sources = []connectionv1alpha1.ConnectionSource{connectionv1alpha1.RuntimeSource}
	}
	if len(sources) == 0 {
		sources = []connectionv1alpha1.ConnectionSource{connectionv1alpha1.AuditSource, connectionv1alpha1.WebhookSource}
	}
	for _, source := range sources {
		switch source {
		case connectionv1alpha1.AuditSource, connectionv1alpha1.WebhookSource:
		case connectionv1alpha1.RuntimeSource:
			if len(sources) != 1 {
				return fmt.Errorf("runtime must be the only source in a Connection")
			}
		default:
			return fmt.Errorf("unsupported export source %q", source)
		}
	}
	// Check if the connection already exists.
	if oldDriver, ok := s.connectionToDriver[connectionName]; ok {
		// If the provider is the same, update the existing connection.
		if oldDriver == newDriver {
			if err := supportedDrivers[newDriver].UpdateConnection(ctx, connectionName, config); err != nil {
				return err
			}
			s.connectionSources[connectionName] = slices.Clone(sources)
			s.connectionIdentity[connectionName] = identityForConnection(connection)
			return nil
		}
	}
	// Check if the provider is supported.
	if d, ok := supportedDrivers[newDriver]; ok {
		err := d.CreateConnection(ctx, connectionName, config)
		if err != nil {
			return err
		}

		// Close the existing connection after successfully creating the new one.
		if err := s.closeConnection(connectionName); err != nil {
			return err
		}
		// Add the new connection and provider to the maps.
		s.connectionToDriver[connectionName] = newDriver
		s.connectionSources[connectionName] = slices.Clone(sources)
		s.connectionIdentity[connectionName] = identityForConnection(connection)
		return nil
	}
	return fmt.Errorf("driver %s is not supported", newDriver)
}

func (s *System) CloseConnection(connectionName string) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	return s.closeConnection(connectionName)
}

func (s *System) closeConnection(connectionName string) error {
	delete(s.connectionSources, connectionName)
	delete(s.connectionIdentity, connectionName)
	if driverName, ok := s.connectionToDriver[connectionName]; ok {
		// connection should be deleted from the map before closing it to make sure old connection is not accessible if close fails
		// also avoids not respecting the latest connection with the same name if close fails
		delete(s.connectionToDriver, connectionName)
		if conn, ok := supportedDrivers[driverName]; ok {
			err := conn.CloseConnection(connectionName)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
