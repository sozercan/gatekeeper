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

package v1alpha1

import (
	statusv1alpha1 "github.com/open-policy-agent/gatekeeper/v3/apis/status/v1alpha1"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/mutation/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ConnectionSpec defines the desired state of Connection.
type ConnectionSpec struct {
	// +kubebuilder:validation:Required
	// Driver is the name of one of the expected drivers i.e. dapr, disk
	Driver string `json:"driver"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:pruning:PreserveUnknownFields
	Config *types.Anything `json:"config"`
	// Sources restricts which producers may use this Connection. An omitted
	// list preserves the legacy audit/webhook behavior; external runtime
	// producers must be explicitly enabled with "runtime".
	// +kubebuilder:validation:MaxItems=3
	// +kubebuilder:validation:XValidation:rule="!self.exists(source, source == 'runtime') || self.size() == 1",message="runtime must be the only source in a Connection"
	// +listType=set
	Sources []ConnectionSource `json:"sources,omitempty"`
}

// ConnectionSource identifies a producer permitted to publish through a
// Connection.
// +kubebuilder:validation:Enum=audit;webhook;runtime
type ConnectionSource string

const (
	AuditSource   ConnectionSource = "audit"
	WebhookSource ConnectionSource = "webhook"
	RuntimeSource ConnectionSource = "runtime"
)

// AllowsSource reports whether source is explicitly enabled. Runtime is never
// implied by an omitted source list because it is an external producer.
func (spec ConnectionSpec) AllowsSource(source ConnectionSource) bool {
	for _, configured := range spec.Sources {
		if configured == source {
			return true
		}
	}
	return false
}

// ConnectionStatus defines the observed state of Connection.
type ConnectionStatus struct {
	ByPod []statusv1alpha1.ConnectionPodStatusStatus `json:"byPod,omitempty"`
}

// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// Connection is the Schema for the connections API.
type Connection struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ConnectionSpec   `json:"spec,omitempty"`
	Status ConnectionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ConnectionList contains a list of Connection.
type ConnectionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Connection `json:"items"`
}
