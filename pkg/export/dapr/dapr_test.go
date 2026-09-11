package dapr

import (
	"context"
	"net"
	"os"
	"testing"

	pb "github.com/dapr/go-sdk/dapr/proto/runtime/v1"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/export/driver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

var testClient driver.Driver

func TestMain(m *testing.M) {
	c, f := FakeConnection()
	testClient = c
	r := m.Run()
	f()

	if r != 0 {
		os.Exit(r)
	}
}

func TestCreate(t *testing.T) {
	tests := []struct {
		name                string
		config              interface{}
		expectedConnections int
		errorMsg            string
	}{
		{
			name:                "invalid config",
			config:              "test",
			expectedConnections: 1,
			errorMsg:            "invalid type assertion, config is not in expected format",
		},
		{
			name:                "config with missing component",
			config:              map[string]interface{}{"enableBatching": true},
			expectedConnections: 1,
			errorMsg:            "failed to get value of component",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := testClient.CreateConnection(context.TODO(), "another-test", tc.config)
			tmp, ok := testClient.(*Dapr)
			if !ok {
				t.Errorf("failed to type assert")
			}
			assert.Equal(t, tc.expectedConnections, len(tmp.openConnections))
			assert.EqualError(t, err, tc.errorMsg)
		})
	}
}

func TestDapr_Publish(t *testing.T) {
	ctx := context.Background()

	type args struct {
		ctx            context.Context
		data           interface{}
		topic          string
		connectionName string
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "test publish",
			args: args{
				ctx: ctx,
				data: map[string]interface{}{
					"test": "test",
				},
				topic:          "test",
				connectionName: "test",
			},
			wantErr: false,
		},
		{
			name: "test publish without data",
			args: args{
				ctx:            ctx,
				data:           nil,
				topic:          "test",
				connectionName: "test",
			},
			wantErr: false,
		},
		{
			name: "test publish without topic",
			args: args{
				ctx: ctx,
				data: map[string]interface{}{
					"test": "test",
				},
				topic:          "",
				connectionName: "test",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := testClient
			if err := r.Publish(tt.args.ctx, tt.args.connectionName, tt.args.data, tt.args.topic); (err != nil) != tt.wantErr {
				t.Errorf("Dapr.Publish() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDapr_Update(t *testing.T) {
	tests := []struct {
		name           string
		config         interface{}
		connectionName string
		wantErr        bool
	}{
		{
			name: "test update connection",
			config: map[string]interface{}{
				"component": "foo",
			},
			wantErr:        false,
			connectionName: "test",
		},
		{
			name: "test update connection with invalid config",
			config: map[string]interface{}{
				"foo": "bar",
			},
			connectionName: "test",
			wantErr:        true,
		},
		{
			name:           "test update connection with nil config",
			config:         nil,
			connectionName: "test",
			wantErr:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := testClient
			if err := r.UpdateConnection(context.Background(), tt.connectionName, tt.config); (err != nil) != tt.wantErr {
				t.Errorf("Dapr.Update() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				cmp, ok := tt.config.(map[string]interface{})["component"].(string)
				assert.True(t, ok)
				tmp, ok := r.(*Dapr)
				assert.True(t, ok)
				assert.Equal(t, cmp, tmp.openConnections[tt.connectionName].component)
			}
		})
	}
}

func TestDaprConnectionsHaveIndependentLifecycles(t *testing.T) {
	const componentKey = "component"
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	pb.RegisterDaprServer(server, &testDaprServer{})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	t.Setenv("DAPR_GRPC_PORT", port)

	connections := &Dapr{openConnections: make(map[string]Connection)}
	t.Cleanup(func() {
		for name := range connections.openConnections {
			require.NoError(t, connections.CloseConnection(name))
		}
	})
	config := map[string]interface{}{componentKey: "pubsub"}
	for _, name := range []string{"first", "second"} {
		require.NoError(t, connections.CreateConnection(t.Context(), name, config))
		require.NoError(t, connections.Publish(t.Context(), name, "before close", "runtime"))
	}

	require.NoError(t, connections.CloseConnection("first"))
	require.NoError(t, connections.Publish(t.Context(), "second", "after peer close", "runtime"))
	require.NoError(t, connections.CreateConnection(t.Context(), "first", config))
	require.NoError(t, connections.Publish(t.Context(), "first", "after recreate", "runtime"))
	require.NoError(t, connections.UpdateConnection(t.Context(), "second", map[string]interface{}{componentKey: "other"}))
	require.NoError(t, connections.CloseConnection("second"))
	require.NoError(t, connections.Publish(t.Context(), "first", "after second peer close", "runtime"))

	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	require.Error(t, connections.CreateConnection(canceled, "canceled", config))
	require.NotContains(t, connections.openConnections, "canceled")
}
