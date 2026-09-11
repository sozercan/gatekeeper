/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	connectionv1alpha1 "github.com/open-policy-agent/gatekeeper/v3/apis/connection/v1alpha1"
	gatekeeperexport "github.com/open-policy-agent/gatekeeper/v3/pkg/export"
	exportutil "github.com/open-policy-agent/gatekeeper/v3/pkg/export/util"
	anythingtypes "github.com/open-policy-agent/gatekeeper/v3/pkg/mutation/types"
	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgofake "k8s.io/client-go/kubernetes/fake"
	clientgotesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const validRuntimeExportBody = `{
  "apiVersion":"runtime.gatekeeper.sh/export/v1alpha1",
  "kind":"RuntimeFindingBatch",
  "subject":"runtime",
  "findings":[{"apiVersion":"runtime.gatekeeper.sh/v1alpha1","kind":"RuntimeFinding","eventVersion":1}]
}`

type recordingRuntimeExporter struct {
	mu         sync.Mutex
	connection string
	source     connectionv1alpha1.ConnectionSource
	subject    string
	messages   []any
	publishErr error
}

func (exporter *recordingRuntimeExporter) Publish(_ context.Context, source connectionv1alpha1.ConnectionSource, connectionName, subject string, message interface{}) error {
	exporter.mu.Lock()
	defer exporter.mu.Unlock()
	exporter.connection = connectionName
	exporter.source = source
	exporter.subject = subject
	exporter.messages = append(exporter.messages, message)
	return exporter.publishErr
}

func (*recordingRuntimeExporter) UpsertConnection(context.Context, *connectionv1alpha1.Connection) error {
	return nil
}

func (*recordingRuntimeExporter) CloseConnection(string) error { return nil }

func (exporter *recordingRuntimeExporter) PublishBatchForConnection(_ context.Context, source connectionv1alpha1.ConnectionSource, connection *connectionv1alpha1.Connection, subject string, messages []any) []error {
	exporter.mu.Lock()
	defer exporter.mu.Unlock()
	exporter.connection = connection.Name
	exporter.source = source
	exporter.subject = subject
	exporter.messages = append(exporter.messages, messages...)
	results := make([]error, len(messages))
	for index := range results {
		results[index] = exporter.publishErr
	}
	return results
}

func TestRuntimeExportHandlerPublishesAuthorizedBatch(t *testing.T) {
	t.Parallel()
	exporter := &recordingRuntimeExporter{}
	var reviewed authorizationv1.SubjectAccessReviewSpec
	handler := newRuntimeExportTestHandler(t, exporter, []connectionv1alpha1.ConnectionSource{connectionv1alpha1.RuntimeSource}, nil, true, true, &reviewed)

	request := httptest.NewRequest(http.MethodPost, runtimeExportPathPrefix+"runtime-connection", strings.NewReader(validRuntimeExportBody))
	request.Header.Set("Authorization", "Bearer test-token")
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	if reviewed.User != "system:serviceaccount:gatekeeper-runtime-agent-system:gatekeeper-runtime-agent" || reviewed.NonResourceAttributes == nil || reviewed.NonResourceAttributes.Verb != "create" || reviewed.NonResourceAttributes.Path != request.URL.Path {
		t.Fatalf("subject access review=%#v", reviewed)
	}
	exporter.mu.Lock()
	defer exporter.mu.Unlock()
	if exporter.connection != "runtime-connection" || exporter.subject != "runtime" || len(exporter.messages) != 1 {
		t.Fatalf("publish=%q %q %#v", exporter.connection, exporter.subject, exporter.messages)
	}
	require.Equal(t, connectionv1alpha1.RuntimeSource, exporter.source)
	require.IsType(t, exportutil.RuntimeFinding(nil), exporter.messages[0])
}

func TestAddRuntimeExportWebhookRequiresConnectionAwareExporter(t *testing.T) {
	err := AddRuntimeExportWebhook(nil, Dependencies{RuntimeExportEnabled: true, ExportSystem: &fakeAdmissionExportSystem{}})
	require.ErrorContains(t, err, "Connection-aware batch exporter")
}

func TestRuntimeExportHandlerEnforcesAuthenticationAuthorizationAndSource(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		authenticated bool
		allowed       bool
		sources       []connectionv1alpha1.ConnectionSource
		authorization string
		wantStatus    int
	}{
		"missing bearer token": {authenticated: true, allowed: true, sources: []connectionv1alpha1.ConnectionSource{connectionv1alpha1.RuntimeSource}, wantStatus: http.StatusUnauthorized},
		"invalid token":        {allowed: true, sources: []connectionv1alpha1.ConnectionSource{connectionv1alpha1.RuntimeSource}, authorization: "Bearer test-token", wantStatus: http.StatusUnauthorized},
		"forbidden subject":    {authenticated: true, sources: []connectionv1alpha1.ConnectionSource{connectionv1alpha1.RuntimeSource}, authorization: "Bearer test-token", wantStatus: http.StatusForbidden},
		"runtime not enabled":  {authenticated: true, allowed: true, authorization: "Bearer test-token", wantStatus: http.StatusForbidden},
		"mixed source list":    {authenticated: true, allowed: true, sources: []connectionv1alpha1.ConnectionSource{connectionv1alpha1.RuntimeSource, connectionv1alpha1.AuditSource}, authorization: "Bearer test-token", wantStatus: http.StatusForbidden},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			exporter := &recordingRuntimeExporter{}
			handler := newRuntimeExportTestHandler(t, exporter, test.sources, nil, test.authenticated, test.allowed, nil)
			request := httptest.NewRequest(http.MethodPost, runtimeExportPathPrefix+"runtime-connection", strings.NewReader(validRuntimeExportBody))
			request.Header.Set("Content-Type", "application/json")
			if test.authorization != "" {
				request.Header.Set("Authorization", test.authorization)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d want=%d body=%q", response.Code, test.wantStatus, response.Body.String())
			}
			exporter.mu.Lock()
			defer exporter.mu.Unlock()
			if len(exporter.messages) != 0 {
				t.Fatalf("unauthorized request published %#v", exporter.messages)
			}
		})
	}
}

func TestRuntimeExportHandlerAcceptsManagedCRDAnnotationFallback(t *testing.T) {
	t.Parallel()
	exporter := &recordingRuntimeExporter{}
	handler := newRuntimeExportTestHandler(t, exporter, nil, map[string]string{
		connectionv1alpha1.RuntimeSourceAnnotation: string(connectionv1alpha1.RuntimeSource),
	}, true, true, nil)

	request := httptest.NewRequest(http.MethodPost, runtimeExportPathPrefix+"runtime-connection", strings.NewReader(validRuntimeExportBody))
	request.Header.Set("Authorization", "Bearer test-token")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestRuntimeExportHandlerRejectsInvalidBatchAndReportsBackendFailure(t *testing.T) {
	t.Parallel()
	exporter := &recordingRuntimeExporter{}
	handler := newRuntimeExportTestHandler(t, exporter, []connectionv1alpha1.ConnectionSource{connectionv1alpha1.RuntimeSource}, nil, true, true, nil)

	request := httptest.NewRequest(http.MethodPost, runtimeExportPathPrefix+"runtime-connection", strings.NewReader(`{"apiVersion":"wrong","kind":"RuntimeFindingBatch","subject":"runtime","findings":[]}`))
	request.Header.Set("Authorization", "Bearer test-token")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid status=%d body=%q", response.Code, response.Body.String())
	}

	exporter.publishErr = errors.New("backend unavailable")
	request = httptest.NewRequest(http.MethodPost, runtimeExportPathPrefix+"runtime-connection", strings.NewReader(validRuntimeExportBody))
	request.Header.Set("Authorization", "Bearer test-token")
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "backend unavailable") {
		t.Fatalf("backend status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestRuntimeExportHandlerWritesGKRFindings(t *testing.T) {
	// Use the complete gkr wire format and the real Connection disk driver.
	body, err := os.ReadFile(filepath.Join("..", "..", "test", "export", "runtime-finding-batch.json"))
	require.NoError(t, err)
	var batch runtimeFindingBatch
	require.NoError(t, json.Unmarshal(body, &batch))

	directory := t.TempDir()
	exporter := gatekeeperexport.NewSystem()
	t.Cleanup(func() { require.NoError(t, exporter.CloseConnection("runtime-connection")) })
	handler := newRuntimeExportTestHandler(t, exporter, []connectionv1alpha1.ConnectionSource{connectionv1alpha1.RuntimeSource}, nil, true, true, nil)
	connection := &connectionv1alpha1.Connection{}
	require.NoError(t, handler.reader.Get(t.Context(), client.ObjectKey{Namespace: "gatekeeper-system", Name: "runtime-connection"}, connection))
	connection.Spec.Driver = "disk"
	connection.Spec.Config = &anythingtypes.Anything{Value: map[string]any{"path": directory, "maxAuditResults": float64(3)}}
	require.NoError(t, exporter.UpsertConnection(t.Context(), connection))
	server := httptest.NewTLSServer(handler)
	defer server.Close()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+runtimeExportPathPrefix+"runtime-connection", bytes.NewReader(body))
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer test-token")
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusAccepted, response.StatusCode)

	files, err := filepath.Glob(filepath.Join(directory, "runtime", "*.open"))
	require.NoError(t, err)
	require.Len(t, files, 1)
	stored, err := os.ReadFile(files[0])
	require.NoError(t, err)
	records := bytes.Split(bytes.TrimSpace(stored), []byte{'\n'})
	require.Equal(t, len(batch.Findings), len(records), "each finding must occupy one JSONL record")
	for index, finding := range batch.Findings {
		require.JSONEq(t, string(finding), string(records[index]), "finding fields must survive export")
	}
}

func newRuntimeExportTestHandler(t *testing.T, exporter gatekeeperexport.ConnectionBatchExporter, sources []connectionv1alpha1.ConnectionSource, annotations map[string]string, authenticated, allowed bool, reviewed *authorizationv1.SubjectAccessReviewSpec) *runtimeExportHandler {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := connectionv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	connection := &connectionv1alpha1.Connection{
		ObjectMeta: metav1.ObjectMeta{Namespace: "gatekeeper-system", Name: "runtime-connection", Annotations: annotations},
		Spec:       connectionv1alpha1.ConnectionSpec{Sources: append([]connectionv1alpha1.ConnectionSource(nil), sources...)},
	}
	reader := clientfake.NewClientBuilder().WithScheme(scheme).WithObjects(connection).Build()
	authClient := clientgofake.NewSimpleClientset()
	authClient.PrependReactor("create", "tokenreviews", func(action clientgotesting.Action) (bool, runtime.Object, error) {
		create, ok := action.(clientgotesting.CreateAction)
		if !ok {
			return true, nil, errors.New("unexpected token review action")
		}
		review, ok := create.GetObject().(*authenticationv1.TokenReview)
		if !ok || review.Spec.Token != "test-token" {
			return true, nil, errors.New("unexpected token review")
		}
		return true, &authenticationv1.TokenReview{Status: authenticationv1.TokenReviewStatus{
			Authenticated: authenticated,
			User: authenticationv1.UserInfo{
				Username: "system:serviceaccount:gatekeeper-runtime-agent-system:gatekeeper-runtime-agent",
				UID:      "service-account-uid",
				Groups:   []string{"system:serviceaccounts", "system:authenticated"},
			},
		}}, nil
	})
	authClient.PrependReactor("create", "subjectaccessreviews", func(action clientgotesting.Action) (bool, runtime.Object, error) {
		create, ok := action.(clientgotesting.CreateAction)
		if !ok {
			return true, nil, errors.New("unexpected subject access review action")
		}
		review, ok := create.GetObject().(*authorizationv1.SubjectAccessReview)
		if !ok {
			return true, nil, errors.New("unexpected subject access review")
		}
		if reviewed != nil {
			*reviewed = review.Spec
		}
		return true, &authorizationv1.SubjectAccessReview{Status: authorizationv1.SubjectAccessReviewStatus{Allowed: allowed}}, nil
	})
	return &runtimeExportHandler{
		reader:               client.Reader(reader),
		exporter:             exporter,
		tokenReviews:         authClient.AuthenticationV1().TokenReviews(),
		subjectAccessReviews: authClient.AuthorizationV1().SubjectAccessReviews(),
		namespace:            "gatekeeper-system",
	}
}
