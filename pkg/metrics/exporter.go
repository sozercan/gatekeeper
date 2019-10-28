package metrics

import (
	"fmt"
	"sync"

	"go.opencensus.io/stats/view"
)

var (
	curMetricsExporter view.Exporter
	curMetricsConfig   *metricsConfig
	metricsMux         sync.RWMutex
)

func NewMetricsExporter() (view.Exporter, error) {
	config, err := createMetricsConfig()
	if err != nil {
		return nil, err
	}

	ce := getCurMetricsExporter()
	// If there is a Prometheus Exporter server running, stop it.
	resetCurPromSrv()

	if ce != nil {
		// UnregisterExporter is idempotent and it can be called multiple times for the same exporter
		// without side effects.
		view.UnregisterExporter(ce)
	}
	var e view.Exporter
	switch config.backendDestination {
	case Prometheus:
		e, err = newPrometheusExporter(config)
	default:
		err = fmt.Errorf("unsupported metrics backend %v", config.backendDestination)
	}
	if err != nil {
		return nil, err
	}
	return e, nil
}

func getCurMetricsExporter() view.Exporter {
	metricsMux.RLock()
	defer metricsMux.RUnlock()
	return curMetricsExporter
}

func SetCurMetricsExporter(e view.Exporter) {
	metricsMux.Lock()
	defer metricsMux.Unlock()
	view.RegisterExporter(e)
	curMetricsExporter = e
}
