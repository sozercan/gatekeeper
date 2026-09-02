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

package runtimepolicy

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type Parameters struct {
	FailurePolicy   string                `json:"failurePolicy,omitempty"`
	Behaviors       Behaviors             `json:"behaviors"`
	DynamicSources  []DynamicSource       `json:"dynamicSources,omitempty"`
	StaleDataPolicy *StaleDataPolicy      `json:"staleDataPolicy,omitempty"`
	ResourceLimits  *PolicyResourceLimits `json:"resourceLimits,omitempty"`
}

type Match struct {
	NamespaceSelector  metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	PodSelector        metav1.LabelSelector `json:"podSelector,omitempty"`
	ContainerTypes     []string             `json:"containerTypes,omitempty"`
	ExcludedNamespaces []string             `json:"excludedNamespaces,omitempty"`
}

// PolicySubject is the v1alpha2 semantic one-of runtime subject. Exactly one
// field must be set.
type PolicySubject struct {
	Kubernetes *KubernetesSubject `json:"kubernetes,omitempty"`
	Substrate  *SubstrateSubject  `json:"substrate,omitempty"`
}

type KubernetesSubject struct {
	NamespaceSelector  metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	PodSelector        metav1.LabelSelector `json:"podSelector,omitempty"`
	ExcludedNamespaces []string             `json:"excludedNamespaces,omitempty"`
	RuntimeClassNames  []string             `json:"runtimeClassNames,omitempty"`
	ContainerTypes     []string             `json:"containerTypes,omitempty"`
	ContainerNames     []string             `json:"containerNames,omitempty"`
}

type SubstrateSubject struct {
	AtespacePatterns    []string             `json:"atespacePatterns"`
	ActorTemplate       *ActorTemplateMatch  `json:"actorTemplate,omitempty"`
	ActorTemplateLabels metav1.LabelSelector `json:"actorTemplateLabels,omitempty"`
	SandboxClasses      []string             `json:"sandboxClasses,omitempty"`
	ContainerNames      []string             `json:"containerNames,omitempty"`
}

type ActorTemplateMatch struct {
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	UID        string `json:"uid,omitempty"`
	Generation int64  `json:"generation,omitempty"`
}

type Behaviors struct {
	Process     *ProcessBehavior     `json:"process,omitempty"`
	File        *FileBehavior        `json:"file,omitempty"`
	Network     *NetworkBehavior     `json:"network,omitempty"`
	Observation *ObservationBehavior `json:"observation,omitempty"`
}

type ProcessBehavior struct {
	DefaultAction string           `json:"defaultAction,omitempty"`
	Executables   []ExecutableRule `json:"executables,omitempty"`
}

type ExecutableRule struct {
	Path   string `json:"path"`
	Action string `json:"action"`
}

type FileBehavior struct {
	DefaultAction string     `json:"defaultAction,omitempty"`
	Paths         []FileRule `json:"paths,omitempty"`
}

type FileRule struct {
	Path      string   `json:"path"`
	MatchType string   `json:"matchType"`
	Action    string   `json:"action"`
	Access    []string `json:"access,omitempty"`
}

type NetworkBehavior struct {
	DefaultAction string                   `json:"defaultAction,omitempty"`
	Destinations  []NetworkDestinationRule `json:"destinations,omitempty"`
	Services      []ServiceRule            `json:"services,omitempty"`
	Domains       []DomainRule             `json:"domains,omitempty"`
}

type NetworkDestinationRule struct {
	CIDR      string   `json:"cidr"`
	Ports     []int32  `json:"ports,omitempty"`
	Protocols []string `json:"protocols"`
	Action    string   `json:"action"`
}

type ServiceRule struct {
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	Mode      string   `json:"mode"`
	Ports     []int32  `json:"ports,omitempty"`
	Protocols []string `json:"protocols"`
	Action    string   `json:"action"`
}

type DomainRule struct {
	Name      string   `json:"name"`
	Ports     []int32  `json:"ports,omitempty"`
	Protocols []string `json:"protocols"`
	Action    string   `json:"action"`
}

type ObservationBehavior struct {
	DNS       bool                        `json:"dns,omitempty"`
	Protocols []string                    `json:"protocols,omitempty"`
	Arguments *ArgumentCollectionSettings `json:"arguments,omitempty"`
}

type ArgumentCollectionSettings struct {
	Enabled             bool  `json:"enabled,omitempty"`
	MaxArguments        int32 `json:"maxArguments,omitempty"`
	MaxBytesPerArgument int32 `json:"maxBytesPerArgument,omitempty"`
	MaxTotalBytes       int32 `json:"maxTotalBytes,omitempty"`
}

type DynamicSource struct {
	Name                string                     `json:"name"`
	OutputType          string                     `json:"outputType"`
	Required            *bool                      `json:"required,omitempty"`
	Projection          DynamicProjection          `json:"projection"`
	ConfigMapRef        *ConfigMapKeyReference     `json:"configMapRef,omitempty"`
	ExternalProviderRef *ExternalProviderReference `json:"externalProviderRef,omitempty"`
	CEL                 *CELSource                 `json:"cel,omitempty"`
}

type DynamicProjection struct {
	Action    string   `json:"action"`
	MatchType string   `json:"matchType,omitempty"`
	Access    []string `json:"access,omitempty"`
	Ports     []int32  `json:"ports,omitempty"`
	Protocols []string `json:"protocols,omitempty"`
}

type ConfigMapKeyReference struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Key       string `json:"key"`
}

type ExternalProviderReference struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
}

type CELSource struct {
	Expression string   `json:"expression"`
	Inputs     []string `json:"inputs,omitempty"`
}

type StaleDataPolicy struct {
	Action              string `json:"action,omitempty"`
	MaxStalenessSeconds int64  `json:"maxStalenessSeconds,omitempty"`
}

type PolicyResourceLimits struct {
	MaxCompiledEntries int32 `json:"maxCompiledEntries,omitempty"`
}
