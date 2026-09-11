package dapr

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"

	daprClient "github.com/dapr/go-sdk/client"
)

type Connection struct {
	// Name of the component object to use in Dapr
	component string

	client daprClient.Client
}

// Dapr represents driver to use Dapr.
type Dapr struct {
	openConnections map[string]Connection
}

const (
	Name = "dapr"
)

var Connections = &Dapr{
	openConnections: make(map[string]Connection),
}

func (r *Dapr) Publish(ctx context.Context, connectionName string, data interface{}, topic string) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("error marshaling data: %w", err)
	}

	conn, ok := r.openConnections[connectionName]
	if !ok {
		return fmt.Errorf("connection not found: %s for Dapr driver", connectionName)
	}
	err = conn.client.PublishEvent(ctx, conn.component, topic, jsonData)
	if err != nil {
		return fmt.Errorf("error publishing message to dapr: %w", err)
	}

	return nil
}

func (r *Dapr) CloseConnection(connectionName string) error {
	conn, ok := r.openConnections[connectionName]
	if !ok {
		return fmt.Errorf("connection %s not found for Dapr driver", connectionName)
	}
	defer delete(r.openConnections, connectionName)
	conn.client.Close()
	return nil
}

func (r *Dapr) UpdateConnection(_ context.Context, connectionName string, config interface{}) error {
	cfg, ok := config.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid type assertion, config is not in expected format")
	}
	component, ok := cfg["component"].(string)
	if !ok {
		return fmt.Errorf("failed to get value of component")
	}
	conn := r.openConnections[connectionName]
	conn.component = component
	r.openConnections[connectionName] = conn
	return nil
}

func (r *Dapr) CreateConnection(ctx context.Context, connectionName string, config interface{}) error {
	var conn Connection
	cfg, ok := config.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid type assertion, config is not in expected format")
	}
	conn.component, ok = cfg["component"].(string)
	if !ok {
		return fmt.Errorf("failed to get value of component")
	}

	port := os.Getenv("DAPR_GRPC_PORT")
	if port == "" {
		port = "50001"
	}
	// NewClient returns a process-wide singleton. Each Connection owns its
	// client so closing one cannot close every Dapr Connection in the pod.
	tmp, err := daprClient.NewClientWithAddressContext(ctx, net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		return err
	}

	conn.client = tmp
	r.openConnections[connectionName] = conn
	return nil
}
