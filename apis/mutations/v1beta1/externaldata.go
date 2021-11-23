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

package v1beta1

type ExternalData struct {
	// Provider is the name of the external data provider.
	Provider string `json:"provider,omitempty"`

	// DataSource represents external data source type for mutation.
	// +kubebuilder:validation:Enum=valueAtLocation;username
	DataSource DataSource `json:"dataSource,omitempty"`

	// FailurePolicy specifies the policy for handling external data failures.
	// +kubebuilder:validation:Enum=UseDefault;Fail;Ignore
	FailurePolicy FailurePolicy `json:"failurePolicy,omitempty"`

	// Default is the value to use if failure policy is set to UseDefault
	Default string `json:"default,omitempty"`
}

// DataSource represents external data source type for mutation.
type DataSource string

const (
	// ValueAtLocation represents the value of the location field.
	ValueAtLocation DataSource = "valueAtLocation"

	// Username represents the admission request username.
	Username DataSource = "username"
)

// FailurePolicy specifies the policy for handling external data failures.
type FailurePolicy string

const (
	// UseDefault represents the failure policy to use the default value.
	UseDefault FailurePolicy = "UseDefault"

	// Fail represents the failure policy to fail the mutation.
	Fail FailurePolicy = "Fail"

	// Ignore represents the failure policy to ignore the mutation.
	Ignore FailurePolicy = "Ignore"
)
