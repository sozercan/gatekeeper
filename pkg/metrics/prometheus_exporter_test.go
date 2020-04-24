package metrics

import (
	"testing"
	"time"
)

func TestPrometheusExporter(t *testing.T) {
	const expectedAddr = ":8888"

	go func() {
		err := newPrometheusExporter()
		if err != nil {
			t.Error(err)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	curPromSrvMux.Lock()
	defer curPromSrvMux.Unlock()
	if curPromSrv.Addr != expectedAddr {
		t.Errorf("Expected address %v but got %v", expectedAddr, curPromSrv.Addr)
	}
}
