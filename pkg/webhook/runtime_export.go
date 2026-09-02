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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	connectionv1alpha1 "github.com/open-policy-agent/gatekeeper/v3/apis/connection/v1alpha1"
	gatekeeperexport "github.com/open-policy-agent/gatekeeper/v3/pkg/export"
	exportutil "github.com/open-policy-agent/gatekeeper/v3/pkg/export/util"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/util"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	typedauthenticationv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	typedauthorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const (
	runtimeExportPathPrefix       = "/v1/export/runtime/"
	runtimeExportBatchAPIVersion  = "runtime.gatekeeper.sh/export/v1alpha1"
	runtimeExportBatchKind        = "RuntimeFindingBatch"
	runtimeFindingAPIVersion      = "runtime.gatekeeper.sh/v1alpha1"
	runtimeFindingKind            = "RuntimeFinding"
	runtimeFindingEventVersion    = 1
	runtimeExportMaximumFindings  = 1000
	runtimeExportMaximumBodyBytes = 1 << 20
	runtimeExportMaximumItemBytes = 64 << 10
)

func init() {
	AddToManagerFuncs = append(AddToManagerFuncs, AddRuntimeExportWebhook)
}

// AddRuntimeExportWebhook exposes the authenticated external producer seam for
// Gatekeeper Connection drivers. It deliberately shares the existing webhook
// TLS server and certificate lifecycle.
func AddRuntimeExportWebhook(mgr manager.Manager, deps Dependencies) error {
	if !deps.RuntimeExportEnabled {
		return nil
	}
	if deps.ExportSystem == nil {
		return errors.New("runtime export requires an export system")
	}
	kubeClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		return fmt.Errorf("create runtime export authentication client: %w", err)
	}
	handler := &runtimeExportHandler{
		reader:               mgr.GetAPIReader(),
		exporter:             deps.ExportSystem,
		tokenReviews:         kubeClient.AuthenticationV1().TokenReviews(),
		subjectAccessReviews: kubeClient.AuthorizationV1().SubjectAccessReviews(),
		namespace:            util.GetNamespace(),
	}
	mgr.GetWebhookServer().Register(runtimeExportPathPrefix, handler)
	return nil
}

type runtimeExportHandler struct {
	reader               client.Reader
	exporter             gatekeeperexport.Exporter
	tokenReviews         typedauthenticationv1.TokenReviewInterface
	subjectAccessReviews typedauthorizationv1.SubjectAccessReviewInterface
	namespace            string
}

type runtimeFindingBatch struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Subject    string            `json:"subject"`
	Findings   []json.RawMessage `json:"findings"`
}

type runtimeFindingHeader struct {
	APIVersion   string `json:"apiVersion"`
	Kind         string `json:"kind"`
	EventVersion int    `json:"eventVersion"`
}

func (handler *runtimeExportHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	connectionName, err := runtimeExportConnectionName(request.URL.Path)
	if err != nil {
		http.Error(writer, "invalid runtime export path", http.StatusBadRequest)
		return
	}
	if err := requireJSONContentType(request.Header.Get("Content-Type")); err != nil {
		http.Error(writer, err.Error(), http.StatusUnsupportedMediaType)
		return
	}
	user, status, err := handler.authenticateAndAuthorize(request.Context(), request)
	if err != nil {
		http.Error(writer, http.StatusText(status), status)
		return
	}
	_ = user // Authentication details are intentionally not logged or returned.

	connection := &connectionv1alpha1.Connection{}
	key := types.NamespacedName{Namespace: handler.namespace, Name: connectionName}
	if err := handler.reader.Get(request.Context(), key, connection); err != nil {
		if apierrors.IsNotFound(err) {
			http.Error(writer, "connection not found", http.StatusNotFound)
			return
		}
		http.Error(writer, "connection lookup unavailable", http.StatusServiceUnavailable)
		return
	}
	if !connection.AllowsRuntimeSource() {
		http.Error(writer, "connection does not allow runtime exports", http.StatusForbidden)
		return
	}

	batch, status, err := decodeRuntimeFindingBatch(writer, request)
	if err != nil {
		http.Error(writer, err.Error(), status)
		return
	}
	failed := handler.publish(request.Context(), connectionName, batch.Findings)
	if failed != 0 {
		http.Error(writer, fmt.Sprintf("runtime export failed for %d finding(s)", failed), http.StatusServiceUnavailable)
		return
	}
	writer.WriteHeader(http.StatusAccepted)
}

func runtimeExportConnectionName(path string) (string, error) {
	if !strings.HasPrefix(path, runtimeExportPathPrefix) {
		return "", errors.New("path does not use the runtime export prefix")
	}
	name := strings.TrimPrefix(path, runtimeExportPathPrefix)
	if name == "" || strings.Contains(name, "/") || len(utilvalidation.IsDNS1123Subdomain(name)) != 0 {
		return "", errors.New("connection name must be one DNS subdomain path segment")
	}
	return name, nil
}

func requireJSONContentType(value string) error {
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil || mediaType != "application/json" {
		return errors.New("content type must be application/json")
	}
	return nil
}

func (handler *runtimeExportHandler) authenticateAndAuthorize(ctx context.Context, request *http.Request) (authenticationv1.UserInfo, int, error) {
	token, err := bearerToken(request.Header.Get("Authorization"))
	if err != nil {
		return authenticationv1.UserInfo{}, http.StatusUnauthorized, err
	}
	review, err := handler.tokenReviews.Create(ctx, &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{Token: token},
	}, metav1.CreateOptions{})
	if err != nil {
		return authenticationv1.UserInfo{}, http.StatusServiceUnavailable, err
	}
	if !review.Status.Authenticated || review.Status.User.Username == "" {
		return authenticationv1.UserInfo{}, http.StatusUnauthorized, errors.New("token was not authenticated")
	}
	extra := make(map[string]authorizationv1.ExtraValue, len(review.Status.User.Extra))
	for key, values := range review.Status.User.Extra {
		extra[key] = authorizationv1.ExtraValue(append([]string(nil), values...))
	}
	accessReview, err := handler.subjectAccessReviews.Create(ctx, &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   review.Status.User.Username,
			UID:    review.Status.User.UID,
			Groups: append([]string(nil), review.Status.User.Groups...),
			Extra:  extra,
			NonResourceAttributes: &authorizationv1.NonResourceAttributes{
				Verb: "create",
				Path: request.URL.Path,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return authenticationv1.UserInfo{}, http.StatusServiceUnavailable, err
	}
	if !accessReview.Status.Allowed {
		return authenticationv1.UserInfo{}, http.StatusForbidden, errors.New("runtime export was not authorized")
	}
	return review.Status.User, 0, nil
}

func bearerToken(value string) (string, error) {
	parts := strings.Fields(value)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", errors.New("a bearer token is required")
	}
	return parts[1], nil
}

func decodeRuntimeFindingBatch(writer http.ResponseWriter, request *http.Request) (runtimeFindingBatch, int, error) {
	request.Body = http.MaxBytesReader(writer, request.Body, runtimeExportMaximumBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var batch runtimeFindingBatch
	if err := decoder.Decode(&batch); err != nil {
		var maximumBytesError *http.MaxBytesError
		if errors.As(err, &maximumBytesError) {
			return runtimeFindingBatch{}, http.StatusRequestEntityTooLarge, errors.New("runtime export batch is too large")
		}
		return runtimeFindingBatch{}, http.StatusBadRequest, fmt.Errorf("invalid runtime export batch: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return runtimeFindingBatch{}, http.StatusBadRequest, errors.New("runtime export body must contain one JSON document")
	}
	if batch.APIVersion != runtimeExportBatchAPIVersion || batch.Kind != runtimeExportBatchKind || batch.Subject != exportutil.RuntimeExportSubject {
		return runtimeFindingBatch{}, http.StatusBadRequest, errors.New("unsupported runtime export envelope")
	}
	if len(batch.Findings) == 0 || len(batch.Findings) > runtimeExportMaximumFindings {
		return runtimeFindingBatch{}, http.StatusBadRequest, fmt.Errorf("runtime export batch must contain 1..%d findings", runtimeExportMaximumFindings)
	}
	for index, finding := range batch.Findings {
		if len(finding) == 0 || len(finding) > runtimeExportMaximumItemBytes {
			return runtimeFindingBatch{}, http.StatusBadRequest, fmt.Errorf("finding %d has an invalid size", index)
		}
		var header runtimeFindingHeader
		if err := json.Unmarshal(finding, &header); err != nil {
			return runtimeFindingBatch{}, http.StatusBadRequest, fmt.Errorf("finding %d is not a JSON object", index)
		}
		if header.APIVersion != runtimeFindingAPIVersion || header.Kind != runtimeFindingKind || header.EventVersion != runtimeFindingEventVersion {
			return runtimeFindingBatch{}, http.StatusBadRequest, fmt.Errorf("finding %d has an unsupported version or kind", index)
		}
	}
	return batch, 0, nil
}

func (handler *runtimeExportHandler) publish(ctx context.Context, connectionName string, findings []json.RawMessage) int {
	messages := make([]any, len(findings))
	for index := range findings {
		messages[index] = findings[index]
	}
	if batchExporter, ok := handler.exporter.(gatekeeperexport.BatchExporter); ok {
		results := batchExporter.PublishBatch(ctx, connectionName, exportutil.RuntimeExportSubject, messages)
		if len(results) != len(messages) {
			return len(messages)
		}
		failed := 0
		for _, result := range results {
			if result != nil {
				failed++
			}
		}
		return failed
	}
	failed := 0
	for _, message := range messages {
		if err := handler.exporter.Publish(ctx, connectionName, exportutil.RuntimeExportSubject, message); err != nil {
			failed++
		}
	}
	return failed
}
