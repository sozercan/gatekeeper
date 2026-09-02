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

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	pathpkg "path"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/open-policy-agent/gatekeeper/v3/pkg/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
)

var ErrInvalidRuntimeConstraint = errors.New("invalid runtime Constraint")

var namespaceExclusionPattern = regexp.MustCompile(`^\*?[-:a-z0-9]*\*?$`)

const (
	maxAtespacePatterns = 32
	maxAtespaceLength   = 63
	maxSubjectNames     = 64
)

// ParsedConstraint is a validated runtime Constraint ready for projection.
type ParsedConstraint struct {
	SourceVersion string
	Mode          string
	Match         Match
	Subject       PolicySubject
	Parameters    Parameters
	RawMatch      map[string]interface{}
	RawSubject    map[string]interface{}
	RawParameters map[string]interface{}
}

// ParseConstraint validates the bounded runtime policy contract carried by a
// Constraint. Runtime mode is derived from Gatekeeper enforcementAction:
// deny maps to Enforce and dryrun maps to Monitor.
func ParseConstraint(constraint *unstructured.Unstructured) (*ParsedConstraint, error) {
	return ParseConstraintForSource(constraint, SourceVersion)
}

// ParseConstraintForSource validates a Constraint against one declared runtime
// target source version. v1alpha1 accepts only the legacy flat Kubernetes
// match. v1alpha2 accepts only the normalized one-of subject.
func ParseConstraintForSource(constraint *unstructured.Unstructured, version string) (*ParsedConstraint, error) {
	if constraint == nil {
		return nil, fmt.Errorf("%w: object is required", ErrInvalidRuntimeConstraint)
	}

	enforcementAction, err := util.GetEnforcementAction(constraint.Object)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRuntimeConstraint, err)
	}
	mode := ""
	switch enforcementAction {
	case util.Deny:
		mode = runtimePolicyModeEnforce
	case util.Dryrun:
		mode = "Monitor"
	case util.Warn:
		return nil, fmt.Errorf("%w: enforcementAction %q has no synchronous runtime-warning semantics; use %q", ErrInvalidRuntimeConstraint, enforcementAction, util.Dryrun)
	case util.Scoped:
		return nil, fmt.Errorf("%w: scoped enforcement actions are not supported by the runtime target", ErrInvalidRuntimeConstraint)
	default:
		return nil, fmt.Errorf("%w: unsupported enforcementAction %q", ErrInvalidRuntimeConstraint, enforcementAction)
	}

	rawMatch, found, err := unstructured.NestedMap(constraint.Object, "spec", "match")
	if err != nil {
		return nil, fmt.Errorf("%w: spec.match: %w", ErrInvalidRuntimeConstraint, err)
	}
	if !found {
		rawMatch = map[string]interface{}{}
	}
	var match Match
	var subject PolicySubject
	var normalizedMatch, normalizedSubject map[string]interface{}
	switch version {
	case SourceVersion:
		match, normalizedMatch, err = decodeRuntimeMatch(rawMatch)
		if err != nil {
			return nil, fmt.Errorf("%w: spec.match: %w", ErrInvalidRuntimeConstraint, err)
		}
		if err := validateMatch(&match); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidRuntimeConstraint, err)
		}
	case SubjectSourceVersion:
		subject, normalizedSubject, err = decodeRuntimeSubject(rawMatch)
		if err != nil {
			return nil, fmt.Errorf("%w: spec.match: %w", ErrInvalidRuntimeConstraint, err)
		}
		if err := validateSubject(&subject); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidRuntimeConstraint, err)
		}
	default:
		return nil, fmt.Errorf("%w: unsupported source version %q", ErrInvalidRuntimeConstraint, version)
	}

	rawParameters, found, err := unstructured.NestedMap(constraint.Object, "spec", "parameters")
	if err != nil {
		return nil, fmt.Errorf("%w: spec.parameters: %w", ErrInvalidRuntimeConstraint, err)
	}
	if !found {
		return nil, fmt.Errorf("%w: spec.parameters is required", ErrInvalidRuntimeConstraint)
	}
	var parameters Parameters
	if err := decodeStrict(rawParameters, &parameters); err != nil {
		return nil, fmt.Errorf("%w: spec.parameters: %w", ErrInvalidRuntimeConstraint, err)
	}
	if err := validateParameters(mode, &parameters); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRuntimeConstraint, err)
	}

	return &ParsedConstraint{
		SourceVersion: version,
		Mode:          mode,
		Match:         match,
		Subject:       subject,
		Parameters:    parameters,
		RawMatch:      normalizedMatch,
		RawSubject:    normalizedSubject,
		RawParameters: rawParameters,
	}, nil
}

func decodeRuntimeSubject(raw map[string]interface{}) (PolicySubject, map[string]interface{}, error) {
	if len(raw) != 1 {
		if _, hasSubject := raw["subject"]; hasSubject {
			return PolicySubject{}, nil, errors.New("normalized subject cannot be combined with legacy or admission match fields")
		}
		return PolicySubject{}, nil, errors.New("source version v1alpha2 requires spec.match.subject")
	}
	rawSubject, ok := raw["subject"].(map[string]interface{})
	if !ok {
		return PolicySubject{}, nil, errors.New("subject must be an object")
	}
	var subject PolicySubject
	if err := decodeStrict(rawSubject, &subject); err != nil {
		return PolicySubject{}, nil, err
	}
	normalized, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&subject)
	if err != nil {
		return PolicySubject{}, nil, fmt.Errorf("normalize subject: %w", err)
	}
	return subject, normalized, nil
}

func decodeRuntimeMatch(raw map[string]interface{}) (Match, map[string]interface{}, error) {
	admissionOnlyFields := map[string]struct{}{
		"kinds": {}, "scope": {}, "namespaces": {}, "name": {}, "source": {},
	}
	runtimeFields := map[string]struct{}{
		"namespaceSelector": {}, "podSelector": {}, "containerTypes": {}, "excludedNamespaces": {},
	}
	normalized := make(map[string]interface{})
	for key, value := range raw {
		if _, found := runtimeFields[key]; found {
			normalized[key] = value
			continue
		}
		if key == "labelSelector" {
			if _, hasPodSelector := raw["podSelector"]; !hasPodSelector {
				normalized["podSelector"] = value
			}
			continue
		}
		if _, found := admissionOnlyFields[key]; found {
			continue
		}
		return Match{}, nil, fmt.Errorf("unknown field %q", key)
	}

	var match Match
	if err := decodeStrict(normalized, &match); err != nil {
		return Match{}, nil, err
	}
	encoded, err := json.Marshal(match)
	if err != nil {
		return Match{}, nil, fmt.Errorf("encode normalized match: %w", err)
	}
	normalized = make(map[string]interface{})
	if err := json.Unmarshal(encoded, &normalized); err != nil {
		return Match{}, nil, fmt.Errorf("decode normalized match: %w", err)
	}
	return match, normalized, nil
}

func validateMatch(match *Match) error {
	if len(match.NamespaceSelector.MatchExpressions) > 64 {
		return fmt.Errorf("spec.match.namespaceSelector.matchExpressions has %d entries; maximum is 64", len(match.NamespaceSelector.MatchExpressions))
	}
	if len(match.PodSelector.MatchExpressions) > 64 {
		return fmt.Errorf("spec.match.podSelector.matchExpressions has %d entries; maximum is 64", len(match.PodSelector.MatchExpressions))
	}
	for field, selector := range map[string]metav1.LabelSelector{
		"spec.match.namespaceSelector": match.NamespaceSelector,
		"spec.match.podSelector":       match.PodSelector,
	} {
		for i, expression := range selector.MatchExpressions {
			if len(expression.Values) > 256 {
				return fmt.Errorf("%s.matchExpressions[%d].values has %d entries; maximum is 256", field, i, len(expression.Values))
			}
		}
		if _, err := metav1.LabelSelectorAsSelector(&selector); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
	}
	if len(match.ContainerTypes) > 3 {
		return fmt.Errorf("spec.match.containerTypes has %d entries; maximum is 3", len(match.ContainerTypes))
	}
	seen := make(map[string]struct{}, len(match.ContainerTypes))
	for i, containerType := range match.ContainerTypes {
		switch containerType {
		case "Application", "Init", "Ephemeral":
		default:
			return fmt.Errorf("spec.match.containerTypes[%d] has unsupported value %q", i, containerType)
		}
		if _, found := seen[containerType]; found {
			return fmt.Errorf("spec.match.containerTypes[%d] duplicates %q", i, containerType)
		}
		seen[containerType] = struct{}{}
	}
	if len(match.ExcludedNamespaces) > 256 {
		return fmt.Errorf("spec.match.excludedNamespaces has %d entries; maximum is 256", len(match.ExcludedNamespaces))
	}
	seenNamespaces := make(map[string]struct{}, len(match.ExcludedNamespaces))
	for i, namespace := range match.ExcludedNamespaces {
		if len(namespace) > 253 || !namespaceExclusionPattern.MatchString(namespace) {
			return fmt.Errorf("spec.match.excludedNamespaces[%d] must be an exact namespace or a prefix/suffix wildcard", i)
		}
		if _, found := seenNamespaces[namespace]; found {
			return fmt.Errorf("spec.match.excludedNamespaces[%d] duplicates %q", i, namespace)
		}
		seenNamespaces[namespace] = struct{}{}
	}
	return nil
}

// NormalizeLegacyKubernetesSubject converts the v1alpha1 flat match to the
// v1alpha2 Kubernetes subject without changing legacy matching semantics.
func NormalizeLegacyKubernetesSubject(match *Match) (PolicySubject, error) {
	if match == nil {
		return PolicySubject{}, errors.New("legacy Kubernetes match is required")
	}
	if err := validateMatch(match); err != nil {
		return PolicySubject{}, err
	}
	containerTypes := append([]string(nil), match.ContainerTypes...)
	if len(containerTypes) == 0 {
		containerTypes = []string{"Application", "Init", "Ephemeral"}
	}
	return PolicySubject{Kubernetes: &KubernetesSubject{
		NamespaceSelector:  *match.NamespaceSelector.DeepCopy(),
		PodSelector:        *match.PodSelector.DeepCopy(),
		ExcludedNamespaces: append([]string(nil), match.ExcludedNamespaces...),
		ContainerTypes:     containerTypes,
	}}, nil
}

func validateSubject(subject *PolicySubject) error {
	set := 0
	if subject.Kubernetes != nil {
		set++
	}
	if subject.Substrate != nil {
		set++
	}
	if set != 1 {
		return errors.New("spec.match.subject must set exactly one of kubernetes or substrate")
	}
	if subject.Kubernetes != nil {
		return validateKubernetesSubject(subject.Kubernetes)
	}
	return validateSubstrateSubject(subject.Substrate)
}

func validateKubernetesSubject(subject *KubernetesSubject) error {
	if subject == nil {
		return errors.New("spec.match.subject.kubernetes is required")
	}
	if selectorEmpty(subject.NamespaceSelector) && selectorEmpty(subject.PodSelector) &&
		len(subject.ExcludedNamespaces) == 0 && len(subject.RuntimeClassNames) == 0 &&
		len(subject.ContainerTypes) == 0 && len(subject.ContainerNames) == 0 {
		return errors.New("spec.match.subject.kubernetes must contain at least one selector")
	}
	legacy := Match{
		NamespaceSelector: subject.NamespaceSelector, PodSelector: subject.PodSelector,
		ContainerTypes: subject.ContainerTypes, ExcludedNamespaces: subject.ExcludedNamespaces,
	}
	if err := validateMatch(&legacy); err != nil {
		return err
	}
	if err := validateDNSNames("spec.match.subject.kubernetes.runtimeClassNames", subject.RuntimeClassNames, utilvalidation.IsDNS1123Subdomain); err != nil {
		return err
	}
	return validateDNSNames("spec.match.subject.kubernetes.containerNames", subject.ContainerNames, utilvalidation.IsDNS1123Label)
}

func validateSubstrateSubject(subject *SubstrateSubject) error {
	if subject == nil {
		return errors.New("spec.match.subject.substrate is required")
	}
	if len(subject.AtespacePatterns) == 0 {
		return errors.New("spec.match.subject.substrate.atespacePatterns must not be empty")
	}
	if len(subject.AtespacePatterns) > maxAtespacePatterns {
		return fmt.Errorf("spec.match.subject.substrate.atespacePatterns has %d entries; maximum is %d", len(subject.AtespacePatterns), maxAtespacePatterns)
	}
	seen := make(map[string]struct{}, len(subject.AtespacePatterns))
	for i, pattern := range subject.AtespacePatterns {
		if err := validateAtespacePattern(pattern); err != nil {
			return fmt.Errorf("spec.match.subject.substrate.atespacePatterns[%d]: %w", i, err)
		}
		if _, found := seen[pattern]; found {
			return fmt.Errorf("spec.match.subject.substrate.atespacePatterns[%d] duplicates %q", i, pattern)
		}
		seen[pattern] = struct{}{}
	}
	if actorTemplate := subject.ActorTemplate; actorTemplate != nil {
		if errs := utilvalidation.IsDNS1123Label(actorTemplate.Namespace); len(errs) != 0 {
			return fmt.Errorf("spec.match.subject.substrate.actorTemplate.namespace: %s", strings.Join(errs, ", "))
		}
		if errs := utilvalidation.IsDNS1123Subdomain(actorTemplate.Name); len(errs) != 0 {
			return fmt.Errorf("spec.match.subject.substrate.actorTemplate.name: %s", strings.Join(errs, ", "))
		}
		if actorTemplate.Generation < 0 {
			return errors.New("spec.match.subject.substrate.actorTemplate.generation cannot be negative")
		}
		if actorTemplate.Generation > 0 && actorTemplate.UID == "" {
			return errors.New("spec.match.subject.substrate.actorTemplate.uid is required when generation is set")
		}
		if len(actorTemplate.UID) > 128 {
			return errors.New("spec.match.subject.substrate.actorTemplate.uid exceeds 128 bytes")
		}
	}
	if err := validateBoundedLabelSelector("spec.match.subject.substrate.actorTemplateLabels", subject.ActorTemplateLabels); err != nil {
		return err
	}
	if err := validateDNSNames("spec.match.subject.substrate.sandboxClasses", subject.SandboxClasses, utilvalidation.IsDNS1123Subdomain); err != nil {
		return err
	}
	return validateDNSNames("spec.match.subject.substrate.containerNames", subject.ContainerNames, utilvalidation.IsDNS1123Label)
}

func selectorEmpty(selector metav1.LabelSelector) bool {
	return len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0
}

func validateBoundedLabelSelector(field string, selector metav1.LabelSelector) error {
	if len(selector.MatchLabels) > 64 {
		return fmt.Errorf("%s.matchLabels has %d entries; maximum is 64", field, len(selector.MatchLabels))
	}
	if len(selector.MatchExpressions) > 64 {
		return fmt.Errorf("%s.matchExpressions has %d entries; maximum is 64", field, len(selector.MatchExpressions))
	}
	for i, expression := range selector.MatchExpressions {
		if len(expression.Values) > 256 {
			return fmt.Errorf("%s.matchExpressions[%d].values has %d entries; maximum is 256", field, i, len(expression.Values))
		}
	}
	if _, err := metav1.LabelSelectorAsSelector(&selector); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	return nil
}

func validateDNSNames(field string, values []string, validate func(string) []string) error {
	if len(values) > maxSubjectNames {
		return fmt.Errorf("%s has %d entries; maximum is %d", field, len(values), maxSubjectNames)
	}
	seen := make(map[string]struct{}, len(values))
	for i, value := range values {
		if errs := validate(value); len(errs) != 0 {
			return fmt.Errorf("%s[%d]: %s", field, i, strings.Join(errs, ", "))
		}
		if _, found := seen[value]; found {
			return fmt.Errorf("%s[%d] duplicates %q", field, i, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

// validateAtespacePattern accepts a lowercase DNS label or a trailing wildcard
// whose bounded prefix ends in '-'. Matching is bytewise and case-sensitive.
func validateAtespacePattern(pattern string) error {
	if pattern == "" {
		return errors.New("pattern is empty")
	}
	if len(pattern) > maxAtespaceLength {
		return fmt.Errorf("pattern is %d bytes; maximum is %d", len(pattern), maxAtespaceLength)
	}
	wildcards := strings.Count(pattern, "*")
	if wildcards == 0 {
		if errs := utilvalidation.IsDNS1123Label(pattern); len(errs) != 0 {
			return fmt.Errorf("exact atespace %q is invalid: %s", pattern, strings.Join(errs, ", "))
		}
		return nil
	}
	if wildcards != 1 || !strings.HasSuffix(pattern, "*") {
		return errors.New("wildcard must appear once at the end")
	}
	prefix := strings.TrimSuffix(pattern, "*")
	if len(prefix) < 3 || !strings.HasSuffix(prefix, "-") {
		return errors.New("wildcard prefix must be at least three bytes and end in '-'")
	}
	if errs := utilvalidation.IsDNS1123Label(prefix + "x"); len(errs) != 0 {
		return fmt.Errorf("wildcard prefix %q is invalid: %s", prefix, strings.Join(errs, ", "))
	}
	return nil
}

func validateParameters(mode string, parameters *Parameters) error {
	switch parameters.FailurePolicy {
	case "", "FailOpen":
	case "FailClosed":
		if mode != runtimePolicyModeEnforce {
			return errors.New("spec.parameters.failurePolicy FailClosed requires enforcementAction deny")
		}
	default:
		return fmt.Errorf("spec.parameters.failurePolicy has unsupported value %q", parameters.FailurePolicy)
	}

	behaviors := parameters.Behaviors
	if behaviors.Process == nil && behaviors.File == nil && behaviors.Network == nil && behaviors.Observation == nil {
		return errors.New("spec.parameters.behaviors must define process, file, network, or observation")
	}

	totalRules := 0
	if behavior := behaviors.Process; behavior != nil {
		if err := validateAction("spec.parameters.behaviors.process.defaultAction", behavior.DefaultAction, true); err != nil {
			return err
		}
		if len(behavior.Executables) > 1024 {
			return fmt.Errorf("spec.parameters.behaviors.process.executables has %d entries; maximum is 1024", len(behavior.Executables))
		}
		totalRules += len(behavior.Executables)
		for i, rule := range behavior.Executables {
			field := fmt.Sprintf("spec.parameters.behaviors.process.executables[%d]", i)
			if err := validatePath(field+".path", rule.Path); err != nil {
				return err
			}
			if err := validateAction(field+".action", rule.Action, false); err != nil {
				return err
			}
		}
	}

	if behavior := behaviors.File; behavior != nil {
		if err := validateAction("spec.parameters.behaviors.file.defaultAction", behavior.DefaultAction, true); err != nil {
			return err
		}
		if len(behavior.Paths) > 4096 {
			return fmt.Errorf("spec.parameters.behaviors.file.paths has %d entries; maximum is 4096", len(behavior.Paths))
		}
		totalRules += len(behavior.Paths)
		for i, rule := range behavior.Paths {
			field := fmt.Sprintf("spec.parameters.behaviors.file.paths[%d]", i)
			if err := validatePath(field+".path", rule.Path); err != nil {
				return err
			}
			if rule.MatchType != "Exact" && rule.MatchType != "Prefix" {
				return fmt.Errorf("%s.matchType has unsupported value %q", field, rule.MatchType)
			}
			if err := validateAction(field+".action", rule.Action, false); err != nil {
				return err
			}
			if err := validateSet(field+".access", rule.Access, 2, "Read", "Write"); err != nil {
				return err
			}
		}
	}

	if behavior := behaviors.Network; behavior != nil {
		if err := validateAction("spec.parameters.behaviors.network.defaultAction", behavior.DefaultAction, true); err != nil {
			return err
		}
		if len(behavior.Destinations) > 4096 {
			return fmt.Errorf("spec.parameters.behaviors.network.destinations has %d entries; maximum is 4096", len(behavior.Destinations))
		}
		if len(behavior.Services) > 512 {
			return fmt.Errorf("spec.parameters.behaviors.network.services has %d entries; maximum is 512", len(behavior.Services))
		}
		if len(behavior.Domains) > 512 {
			return fmt.Errorf("spec.parameters.behaviors.network.domains has %d entries; maximum is 512", len(behavior.Domains))
		}
		totalRules += len(behavior.Destinations) + len(behavior.Services) + len(behavior.Domains)
		for i, rule := range behavior.Destinations {
			field := fmt.Sprintf("spec.parameters.behaviors.network.destinations[%d]", i)
			if err := validateDestination(field+".cidr", rule.CIDR); err != nil {
				return err
			}
			if err := validateTransport(field, rule.Ports, rule.Protocols, rule.Action, 64, false); err != nil {
				return err
			}
		}
		for i, rule := range behavior.Services {
			field := fmt.Sprintf("spec.parameters.behaviors.network.services[%d]", i)
			if errs := utilvalidation.IsDNS1123Label(rule.Namespace); len(errs) != 0 {
				return fmt.Errorf("%s.namespace: %s", field, strings.Join(errs, ", "))
			}
			if errs := utilvalidation.IsDNS1123Label(rule.Name); len(errs) != 0 {
				return fmt.Errorf("%s.name: %s", field, strings.Join(errs, ", "))
			}
			if rule.Mode != "ClusterIP" && rule.Mode != "Endpoints" {
				return fmt.Errorf("%s.mode has unsupported value %q", field, rule.Mode)
			}
			if err := validateTransport(field, rule.Ports, rule.Protocols, rule.Action, 64, false); err != nil {
				return err
			}
		}
		for i, rule := range behavior.Domains {
			field := fmt.Sprintf("spec.parameters.behaviors.network.domains[%d]", i)
			if err := validateDomain(field+".name", rule.Name); err != nil {
				return err
			}
			if err := validateTransport(field, rule.Ports, rule.Protocols, rule.Action, 64, false); err != nil {
				return err
			}
		}
	}

	if behavior := behaviors.Observation; behavior != nil {
		argumentsEnabled := behavior.Arguments != nil && behavior.Arguments.Enabled
		if !behavior.DNS && len(behavior.Protocols) == 0 && !argumentsEnabled {
			return errors.New("spec.parameters.behaviors.observation must enable DNS, arguments, or an application protocol")
		}
		if err := validateSet("spec.parameters.behaviors.observation.protocols", behavior.Protocols, 3, "HTTP", "TLS", "SSH"); err != nil {
			return err
		}
		if arguments := behavior.Arguments; arguments != nil {
			if err := validateOptionalBound("spec.parameters.behaviors.observation.arguments.maxArguments", arguments.MaxArguments, 1, 16); err != nil {
				return err
			}
			if err := validateOptionalBound("spec.parameters.behaviors.observation.arguments.maxBytesPerArgument", arguments.MaxBytesPerArgument, 1, 128); err != nil {
				return err
			}
			if err := validateOptionalBound("spec.parameters.behaviors.observation.arguments.maxTotalBytes", arguments.MaxTotalBytes, 1, 1024); err != nil {
				return err
			}
		}
	}

	if err := validateDynamicSources(parameters.DynamicSources, behaviors); err != nil {
		return err
	}

	if stale := parameters.StaleDataPolicy; stale != nil {
		hasNetworkTargets := behaviors.Network != nil && (len(behaviors.Network.Services) != 0 || len(behaviors.Network.Domains) != 0)
		if len(parameters.DynamicSources) == 0 && !hasNetworkTargets {
			return errors.New("spec.parameters.staleDataPolicy requires a dynamic source, Service target, or domain target")
		}
		switch stale.Action {
		case "", "RetainLastKnown", "FailOpen", "FailClosed":
		default:
			return fmt.Errorf("spec.parameters.staleDataPolicy.action has unsupported value %q", stale.Action)
		}
		if stale.MaxStalenessSeconds < 0 || stale.MaxStalenessSeconds > 604800 {
			return errors.New("spec.parameters.staleDataPolicy.maxStalenessSeconds must be between 0 and 604800")
		}
	}

	maxEntries := 25000
	if limits := parameters.ResourceLimits; limits != nil && limits.MaxCompiledEntries != 0 {
		if limits.MaxCompiledEntries < 1 || limits.MaxCompiledEntries > 25000 {
			return errors.New("spec.parameters.resourceLimits.maxCompiledEntries must be between 1 and 25000")
		}
		maxEntries = int(limits.MaxCompiledEntries)
	}
	if totalRules > maxEntries {
		return fmt.Errorf("spec.parameters.behaviors has %d aggregate rules; maximum is %d", totalRules, maxEntries)
	}
	encoded, err := json.Marshal(parameters)
	if err != nil {
		return fmt.Errorf("spec.parameters cannot be encoded: %w", err)
	}
	if len(encoded) > 1<<20 {
		return fmt.Errorf("spec.parameters is %d encoded bytes; maximum is %d", len(encoded), 1<<20)
	}
	return nil
}

func validateAction(field, action string, allowEmpty bool) error {
	if allowEmpty && action == "" {
		return nil
	}
	if action != "Allow" && action != "Deny" {
		return fmt.Errorf("%s has unsupported value %q", field, action)
	}
	return nil
}

func validatePath(field, value string) error {
	switch {
	case value == "":
		return fmt.Errorf("%s is required", field)
	case len(value) > 4096:
		return fmt.Errorf("%s is %d bytes; maximum is 4096", field, len(value))
	case !utf8.ValidString(value):
		return fmt.Errorf("%s must be valid UTF-8", field)
	case strings.IndexByte(value, 0) >= 0:
		return fmt.Errorf("%s must not contain NUL", field)
	case value[0] != '/':
		return fmt.Errorf("%s must be absolute", field)
	case pathpkg.Clean(value) != value:
		return fmt.Errorf("%s must be canonical", field)
	default:
		return nil
	}
}

func validateTransport(field string, ports []int32, protocols []string, action string, maximumPorts int, allowUDP bool) error {
	if err := validateAction(field+".action", action, false); err != nil {
		return err
	}
	if len(ports) > maximumPorts {
		return fmt.Errorf("%s.ports has %d entries; maximum is %d", field, len(ports), maximumPorts)
	}
	seenPorts := make(map[int32]struct{}, len(ports))
	for i, port := range ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("%s.ports[%d] must be between 1 and 65535", field, i)
		}
		if _, found := seenPorts[port]; found {
			return fmt.Errorf("%s.ports[%d] duplicates %d", field, i, port)
		}
		seenPorts[port] = struct{}{}
	}
	if len(protocols) == 0 {
		return fmt.Errorf("%s.protocols must contain at least one protocol", field)
	}
	if err := validateSet(field+".protocols", protocols, 2, "TCP", "UDP"); err != nil {
		return err
	}
	if !allowUDP {
		for i, protocol := range protocols {
			if protocol == "UDP" {
				return fmt.Errorf("%s.protocols[%d] uses UDP, which is not qualified; only TCP connect is supported", field, i)
			}
		}
	}
	return nil
}

func validateSet(field string, values []string, maximum int, allowed ...string) error {
	if len(values) > maximum {
		return fmt.Errorf("%s has %d entries; maximum is %d", field, len(values), maximum)
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, value := range allowed {
		allowedSet[value] = struct{}{}
	}
	seen := make(map[string]struct{}, len(values))
	for i, value := range values {
		if _, ok := allowedSet[value]; !ok {
			return fmt.Errorf("%s[%d] has unsupported value %q", field, i, value)
		}
		if _, ok := seen[value]; ok {
			return fmt.Errorf("%s[%d] duplicates %q", field, i, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateDynamicSources(sources []DynamicSource, behaviors Behaviors) error {
	if len(sources) > 128 {
		return fmt.Errorf("spec.parameters.dynamicSources has %d entries; maximum is 128", len(sources))
	}

	sourceIndexes := make(map[string]int, len(sources))
	for i := range sources {
		source := &sources[i]
		field := fmt.Sprintf("spec.parameters.dynamicSources[%d]", i)
		if errs := utilvalidation.IsDNS1123Label(source.Name); len(errs) != 0 {
			return fmt.Errorf("%s.name: %s", field, strings.Join(errs, ", "))
		}
		if previous, found := sourceIndexes[source.Name]; found {
			return fmt.Errorf("%s.name duplicates spec.parameters.dynamicSources[%d].name", field, previous)
		}
		sourceIndexes[source.Name] = i

		references := 0
		if ref := source.ConfigMapRef; ref != nil {
			references++
			if errs := utilvalidation.IsDNS1123Label(ref.Namespace); len(errs) != 0 {
				return fmt.Errorf("%s.configMapRef.namespace: %s", field, strings.Join(errs, ", "))
			}
			if errs := utilvalidation.IsDNS1123Subdomain(ref.Name); len(errs) != 0 {
				return fmt.Errorf("%s.configMapRef.name: %s", field, strings.Join(errs, ", "))
			}
			if ref.Key == "" || len(ref.Key) > 253 {
				return fmt.Errorf("%s.configMapRef.key must contain 1 to 253 characters", field)
			}
		}
		if ref := source.ExternalProviderRef; ref != nil {
			references++
			if ref.APIVersion == "" || len(ref.APIVersion) > 253 {
				return fmt.Errorf("%s.externalProviderRef.apiVersion must contain 1 to 253 characters", field)
			}
			if ref.Kind == "" || len(ref.Kind) > 63 {
				return fmt.Errorf("%s.externalProviderRef.kind must contain 1 to 63 characters", field)
			}
			if ref.Namespace != "" {
				if errs := utilvalidation.IsDNS1123Label(ref.Namespace); len(errs) != 0 {
					return fmt.Errorf("%s.externalProviderRef.namespace: %s", field, strings.Join(errs, ", "))
				}
			}
			if errs := utilvalidation.IsDNS1123Subdomain(ref.Name); len(errs) != 0 {
				return fmt.Errorf("%s.externalProviderRef.name: %s", field, strings.Join(errs, ", "))
			}
		}
		if source.CEL != nil {
			references++
			if len(source.CEL.Expression) == 0 || len(source.CEL.Expression) > 8192 {
				return fmt.Errorf("%s.cel.expression must contain 1 to 8192 bytes", field)
			}
			if len(source.CEL.Inputs) > 128 {
				return fmt.Errorf("%s.cel.inputs has %d entries; maximum is 128", field, len(source.CEL.Inputs))
			}
			seenInputs := make(map[string]struct{}, len(source.CEL.Inputs))
			for inputIndex, input := range source.CEL.Inputs {
				inputField := fmt.Sprintf("%s.cel.inputs[%d]", field, inputIndex)
				if len(input) == 0 || len(input) > 63 {
					return fmt.Errorf("%s must contain 1 to 63 characters", inputField)
				}
				if input == source.Name {
					return fmt.Errorf("%s cannot reference its own source", inputField)
				}
				if _, found := seenInputs[input]; found {
					return fmt.Errorf("%s duplicates %q", inputField, input)
				}
				seenInputs[input] = struct{}{}
			}
		}
		if references != 1 {
			return fmt.Errorf("%s must set exactly one of configMapRef, externalProviderRef, or cel", field)
		}

		if err := validateDynamicProjection(field, source, behaviors); err != nil {
			return err
		}
	}

	for i := range sources {
		source := &sources[i]
		if source.CEL == nil {
			continue
		}
		for inputIndex, input := range source.CEL.Inputs {
			if _, found := sourceIndexes[input]; !found {
				return fmt.Errorf("spec.parameters.dynamicSources[%d].cel.inputs[%d] references unknown source %q", i, inputIndex, input)
			}
		}
	}
	if cycle := dynamicSourceCycle(sources, sourceIndexes); len(cycle) != 0 {
		return fmt.Errorf("spec.parameters.dynamicSources has CEL dependency cycle: %s", strings.Join(cycle, " -> "))
	}
	return nil
}

func validateDynamicProjection(field string, source *DynamicSource, behaviors Behaviors) error {
	projection := source.Projection
	if err := validateAction(field+".projection.action", projection.Action, false); err != nil {
		return err
	}
	switch source.OutputType {
	case "Executable":
		if behaviors.Process == nil {
			return fmt.Errorf("%s.outputType Executable requires process behavior", field)
		}
		if projection.MatchType != "" || len(projection.Access) != 0 || len(projection.Ports) != 0 || len(projection.Protocols) != 0 {
			return fmt.Errorf("%s.projection accepts only action for Executable output", field)
		}
	case "Path":
		if behaviors.File == nil {
			return fmt.Errorf("%s.outputType Path requires file behavior", field)
		}
		if projection.MatchType != "Exact" && projection.MatchType != "Prefix" {
			return fmt.Errorf("%s.projection.matchType must be Exact or Prefix", field)
		}
		if len(projection.Access) == 0 {
			return fmt.Errorf("%s.projection.access must contain at least one file access", field)
		}
		if err := validateSet(field+".projection.access", projection.Access, 2, "Read", "Write"); err != nil {
			return err
		}
		if len(projection.Ports) != 0 || len(projection.Protocols) != 0 {
			return fmt.Errorf("%s.projection ports and protocols apply only to CIDR or Domain output", field)
		}
	case "CIDR", "Domain":
		if behaviors.Network == nil {
			return fmt.Errorf("%s.outputType %s requires network behavior", field, source.OutputType)
		}
		if projection.MatchType != "" || len(projection.Access) != 0 {
			return fmt.Errorf("%s.projection matchType and access apply only to Path output", field)
		}
		if err := validateTransport(field+".projection", projection.Ports, projection.Protocols, projection.Action, 128, true); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s.outputType has unsupported value %q", field, source.OutputType)
	}
	return nil
}

func dynamicSourceCycle(sources []DynamicSource, sourceIndexes map[string]int) []string {
	const (
		unvisited = iota
		visiting
		visited
	)
	state := make(map[string]int, len(sources))
	stack := make([]string, 0, len(sources))
	var visit func(string) []string
	visit = func(name string) []string {
		if state[name] == visiting {
			start := 0
			for start < len(stack) && stack[start] != name {
				start++
			}
			return append(append([]string(nil), stack[start:]...), name)
		}
		if state[name] == visited {
			return nil
		}
		state[name] = visiting
		stack = append(stack, name)
		source := sources[sourceIndexes[name]]
		if source.CEL != nil {
			for _, input := range source.CEL.Inputs {
				if _, found := sourceIndexes[input]; !found {
					continue
				}
				if cycle := visit(input); len(cycle) != 0 {
					return cycle
				}
			}
		}
		stack = stack[:len(stack)-1]
		state[name] = visited
		return nil
	}
	for i := range sources {
		if cycle := visit(sources[i].Name); len(cycle) != 0 {
			return cycle
		}
	}
	return nil
}

func validateOptionalBound(field string, value, minimum, maximum int32) error {
	if value == 0 {
		return nil
	}
	if value < minimum || value > maximum {
		return fmt.Errorf("%s must be between %d and %d", field, minimum, maximum)
	}
	return nil
}

func validateDestination(field, value string) error {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		if prefix.Masked() != prefix {
			return fmt.Errorf("%s must be canonical; use %q", field, prefix.Masked().String())
		}
		if value != prefix.String() {
			return fmt.Errorf("%s must be canonical; use %q", field, prefix.String())
		}
		return validateAddress(field, prefix.Addr())
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return fmt.Errorf("%s must be an IP address or CIDR: %w", field, err)
	}
	if value != address.String() {
		return fmt.Errorf("%s must be canonical; use %q", field, address.String())
	}
	return validateAddress(field, address)
}

func validateAddress(field string, address netip.Addr) error {
	if !address.IsValid() || address.Zone() != "" || address.Is4In6() {
		return fmt.Errorf("%s address %q must be a native unzoned IPv4 or IPv6 address", field, address)
	}
	if address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
		return fmt.Errorf("%s address %q is outside the qualified unicast scope", field, address)
	}
	return nil
}

func validateDomain(field, value string) error {
	if value == "" || len(value) > 253 {
		return fmt.Errorf("%s must contain 1 to 253 characters", field)
	}
	if value != strings.ToLower(value) || strings.HasSuffix(value, ".") {
		return fmt.Errorf("%s must use lowercase canonical form without a trailing dot", field)
	}
	if strings.Contains(value, "*") {
		return fmt.Errorf("%s wildcard domains are unsupported", field)
	}
	if errs := utilvalidation.IsDNS1123Subdomain(value); len(errs) != 0 {
		return fmt.Errorf("%s: %s", field, strings.Join(errs, ", "))
	}
	return nil
}
