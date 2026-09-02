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

const (
	// TargetName is the ConstraintTemplate target used for runtime policies.
	TargetName = "runtime.gatekeeper.sh"

	// EngineName is the only policy engine accepted by runtime-target templates.
	// Runtime sources are declarative metadata, not executable Rego or CEL.
	EngineName = "Runtime"

	// SourceVersion is the legacy flat-Kubernetes declarative source contract.
	SourceVersion = "v1alpha1"

	// SubjectSourceVersion is the normalized one-of subject source contract.
	SubjectSourceVersion = "v1alpha2"

	// EnforcementPoint identifies runtime projection in Constraint status.
	EnforcementPoint = "runtime.gatekeeper.sh"

	RuntimePolicyAPIVersion         = "runtime.gatekeeper.sh/v1alpha1"
	RuntimePolicyAPIVersionV1Alpha2 = "runtime.gatekeeper.sh/v1alpha2"
	RuntimePolicyKind               = "RuntimePolicy"
	runtimePolicyModeEnforce        = "Enforce"
)
