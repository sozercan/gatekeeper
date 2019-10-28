package metrics

import (
	"fmt"
	"os"
	"strings"

	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

var log = logf.Log.WithName("controller").WithValues("metaKind", "metrics")

// metricsBackend specifies the backend to use for metrics
type metricsBackend string

const (
	defaultBackendEnvName = "DEFAULT_METRICS_BACKEND"

	// Prometheus is used for Prometheus backend
	Prometheus metricsBackend = "prometheus"
)

type metricsConfig struct {
	component string

	// The metrics backend destination.
	backendDestination metricsBackend

	prometheusPort int
}

func createMetricsConfig() (*metricsConfig, error) {
	var mc metricsConfig

	// Read backend setting from environment variable first
	backend := os.Getenv(defaultBackendEnvName)
	if backend == "" {
		// Use Prometheus if DEFAULT_METRICS_BACKEND does not exist or is empty
		backend = string(Prometheus)
	}
	lb := metricsBackend(strings.ToLower(backend))
	switch lb {
	case Prometheus:
		mc.backendDestination = lb
	default:
		return nil, fmt.Errorf("unsupported metrics backend value %q", backend)
	}

	if mc.backendDestination == Prometheus {
		mc.prometheusPort = 8888
	}

	return &mc, nil
}
