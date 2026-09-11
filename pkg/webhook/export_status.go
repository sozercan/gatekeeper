package webhook

import (
	"sort"
	"time"

	statusv1alpha1 "github.com/open-policy-agent/gatekeeper/v3/apis/status/v1alpha1"
	exportutil "github.com/open-policy-agent/gatekeeper/v3/pkg/export/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	defaultExportStatusInterval  = 10 * time.Second
	defaultExportHealthyInterval = time.Minute
	exportStatusTimeout          = 2 * time.Second
)

// exportPublishState accumulates health between status intervals. Error
// classes are bounded so status failures cannot accumulate one error per event.
type exportPublishState struct {
	attempted       bool
	active          bool
	errors          map[string]error
	lastAttemptTime time.Time
	lastSuccessTime time.Time
}

func newExportPublishState() exportPublishState {
	return exportPublishState{errors: make(map[string]error)}
}

func (state *exportPublishState) record(now time.Time, err error) {
	state.attempted = true
	if now.After(state.lastAttemptTime) {
		state.lastAttemptTime = now
	}
	if err != nil {
		state.errors = exportutil.AddPublishError(state.errors, err)
		return
	}
	state.active = true
	if now.After(state.lastSuccessTime) {
		state.lastSuccessTime = now
	}
}

func (state *exportPublishState) merge(previous exportPublishState) {
	state.attempted = state.attempted || previous.attempted
	state.active = state.active || previous.active
	if previous.lastAttemptTime.After(state.lastAttemptTime) {
		state.lastAttemptTime = previous.lastAttemptTime
	}
	if previous.lastSuccessTime.After(state.lastSuccessTime) {
		state.lastSuccessTime = previous.lastSuccessTime
	}
	for _, err := range previous.errors {
		state.errors = exportutil.AddPublishError(state.errors, err)
	}
}

func (state *exportPublishState) status(source statusv1alpha1.ConnectionPublishSource) statusv1alpha1.ConnectionPublishStatus {
	keys := make([]string, 0, len(state.errors))
	for key := range state.errors {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	exportErrors := make([]*statusv1alpha1.ConnectionError, 0, len(keys))
	for _, key := range keys {
		exportErrors = append(exportErrors, &statusv1alpha1.ConnectionError{
			Type:    statusv1alpha1.PublishError,
			Message: exportutil.PublishErrorKey(state.errors[key]),
		})
	}
	lastAttemptTime := metav1.NewTime(state.lastAttemptTime)
	status := statusv1alpha1.ConnectionPublishStatus{
		Source:          source,
		Active:          state.active,
		LastAttemptTime: &lastAttemptTime,
		Errors:          exportErrors,
	}
	if !state.lastSuccessTime.IsZero() {
		lastSuccessTime := metav1.NewTime(state.lastSuccessTime)
		status.LastSuccessTime = &lastSuccessTime
	}
	return status
}
