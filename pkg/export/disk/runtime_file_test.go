package disk

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	exportutil "github.com/open-policy-agent/gatekeeper/v3/pkg/export/util"
)

func TestRuntimeFindingBatchWritesValidatedJSONL(t *testing.T) {
	writer := newTestWriter(nil)
	connectionName := "runtime-connection"
	requireCreateConnection(t, writer, connectionName, diskConfig(t.TempDir(), 3))
	t.Cleanup(func() { _ = writer.CloseConnection(connectionName) })

	findings := []any{
		json.RawMessage(`{
  "apiVersion": "runtime.gatekeeper.sh/v1alpha1",
  "kind": "RuntimeFinding",
  "eventVersion": 1,
  "sequence": 1
}`),
		json.RawMessage(`{"apiVersion":"runtime.gatekeeper.sh/v1alpha1","kind":"RuntimeFinding","eventVersion":1,"sequence":2}`),
	}
	results := writer.PublishBatch(context.Background(), connectionName, findings, exportutil.RuntimeExportSubject)
	for index, result := range results {
		if result != nil {
			t.Fatalf("result %d: %v", index, result)
		}
	}

	writer.mu.Lock()
	stream := writer.openConnections[connectionName].admission.stream
	writer.mu.Unlock()
	if stream == nil || stream.topic != exportutil.RuntimeExportSubject {
		t.Fatalf("runtime stream=%#v", stream)
	}
	data, err := os.ReadFile(stream.openPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 || !json.Valid([]byte(lines[0])) || !json.Valid([]byte(lines[1])) {
		t.Fatalf("runtime JSONL=%q", data)
	}

	invalid := writer.PublishBatch(context.Background(), connectionName, []any{json.RawMessage(`[]`)}, exportutil.RuntimeExportSubject)
	if len(invalid) != 1 || invalid[0] == nil {
		t.Fatalf("invalid runtime finding results=%#v", invalid)
	}
}
