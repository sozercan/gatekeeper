package disk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	exportutil "github.com/open-policy-agent/gatekeeper/v3/pkg/export/util"
	"github.com/stretchr/testify/require"
)

func TestRuntimeFindingBatchWritesValidatedJSONL(t *testing.T) {
	writer := newTestWriter(nil)
	connectionName := "runtime-connection"
	requireCreateConnection(t, writer, connectionName, diskConfig(t.TempDir(), 3))
	t.Cleanup(func() { _ = writer.CloseConnection(connectionName) })

	findings := []any{
		exportutil.RuntimeFinding(`{
  "apiVersion": "runtime.gatekeeper.sh/v1alpha1",
  "kind": "RuntimeFinding",
  "eventVersion": 1,
  "sequence": 1
}`),
		exportutil.RuntimeFinding(`{"apiVersion":"runtime.gatekeeper.sh/v1alpha1","kind":"RuntimeFinding","eventVersion":1,"sequence":2}`),
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

	invalid := writer.PublishBatch(context.Background(), connectionName, []any{exportutil.RuntimeFinding(`[]`)}, exportutil.RuntimeExportSubject)
	if len(invalid) != 1 || invalid[0] == nil {
		t.Fatalf("invalid runtime finding results=%#v", invalid)
	}
}

func TestRuntimeFindingPreservesFormatAndRetention(t *testing.T) {
	for _, subject := range []string{exportutil.RuntimeExportSubject, "custom-channel"} {
		t.Run(subject, func(t *testing.T) {
			path := t.TempDir()
			writer := newAdmissionWriter()
			const connectionName = "runtime-retention"
			createAdmissionConnection(t, writer, connectionName, path, 1)
			var expected []string
			for index := range 3 {
				finding := exportutil.RuntimeFinding(fmt.Sprintf("{\n\"sequence\":%d, \"inode\":18446744073709551615, \"message\":\"line one\\nline two\"\n}", index))
				var compact bytes.Buffer
				require.NoError(t, json.Compact(&compact, finding))
				expected = append(expected, compact.String()+"\n")
				if index == 1 {
					results := writer.PublishBatch(t.Context(), connectionName, []any{finding}, subject)
					require.Len(t, results, 1)
					require.NoError(t, results[0])
				} else {
					require.NoError(t, writer.Publish(t.Context(), connectionName, finding, subject))
				}
			}
			files, err := filepath.Glob(filepath.Join(path, subject, "admission-*.log"))
			require.NoError(t, err)
			require.Len(t, files, 2, "runtime records must retain the spool count limit")
			var stored []string
			for _, file := range files {
				data, err := os.ReadFile(file)
				require.NoError(t, err)
				stored = append(stored, string(data))
			}
			require.ElementsMatch(t, expected[1:], stored, "JSON compaction must preserve large integers and escaped newlines")
			oversized := exportutil.RuntimeFinding(`{"message":"` + strings.Repeat("x", 2048) + `"}`)
			require.ErrorContains(t, writer.Publish(t.Context(), connectionName, oversized, subject), "exceeds maximum")
		})
	}
}

func TestRuntimeBatchValidatesPayloadTypesIndependently(t *testing.T) {
	path := t.TempDir()
	writer := newAdmissionWriter()
	const connectionName = "mixed-payloads"
	createAdmissionConnection(t, writer, connectionName, path, 100)
	finding := exportutil.RuntimeFinding(`{"kind":"RuntimeFinding","sequence":18446744073709551615}`)
	admission := admissionPayload(t, "denied-pod")
	results := writer.PublishBatch(t.Context(), connectionName, []any{
		finding,
		exportutil.ExportMsg{ID: "unsupported-batch-audit", Message: exportutil.AuditStartedMsg},
		admission,
		exportutil.RuntimeFinding(`[]`),
		exportutil.RuntimeFinding(nil),
		exportutil.RuntimeFinding(`{} {}`),
	}, exportutil.RuntimeExportSubject)
	require.Len(t, results, 6)
	for index, result := range results {
		if index == 0 || index == 2 {
			require.NoError(t, result)
		} else {
			require.Error(t, result, "invalid message %d must retain its own error", index)
		}
	}
	files, err := filepath.Glob(filepath.Join(path, exportutil.RuntimeExportSubject, "admission-*.open"))
	require.NoError(t, err)
	require.Len(t, files, 1)
	data, err := os.ReadFile(files[0])
	require.NoError(t, err)
	require.Equal(t, string(finding)+"\n"+string(admission)+"\n", string(data))
}
