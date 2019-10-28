package metrics

import (
	"fmt"
	"net/http"
	"sync"

	"contrib.go.opencensus.io/exporter/prometheus"
	"go.opencensus.io/stats/view"
)

var (
	curPromSrv    *http.Server
	curPromSrvMux sync.Mutex
)

func newPrometheusExporter(config *metricsConfig) (view.Exporter, error) {
	e, err := prometheus.NewExporter(prometheus.Options{Namespace: config.component})
	if err != nil {
		log.Error(err, "Failed to create the Prometheus exporter.")
		return nil, err
	}
	log.Info("Created Opencensus Prometheus exporter. Start the server for Prometheus exporter.")
	// Start the server for Prometheus scraping
	go func() {
		srv := startNewPromSrv(e, config.prometheusPort)
		srv.ListenAndServe()
	}()
	return e, nil
}

func getCurPromSrv() *http.Server {
	curPromSrvMux.Lock()
	defer curPromSrvMux.Unlock()
	return curPromSrv
}

func resetCurPromSrv() {
	curPromSrvMux.Lock()
	defer curPromSrvMux.Unlock()
	if curPromSrv != nil {
		curPromSrv.Close()
		curPromSrv = nil
	}
}

func startNewPromSrv(e *prometheus.Exporter, port int) *http.Server {
	sm := http.NewServeMux()
	sm.Handle("/metrics", e)
	curPromSrvMux.Lock()
	defer curPromSrvMux.Unlock()
	if curPromSrv != nil {
		curPromSrv.Close()
	}
	curPromSrv = &http.Server{
		Addr:    fmt.Sprintf(":%v", port),
		Handler: sm,
	}
	return curPromSrv
}
