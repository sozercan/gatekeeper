package k8spsprequireddropcapabilities

violation[{"msg": msg, "details": {}}] {
    container := input_containers[_]
    capabilities := {x | x = container.securityContext.capabilities.drop[_]}
    not input_drop_capabilities_required(capabilities)
    msg := sprintf("One of the required drop capabilities %v is not dropped, pod: %v. Required drop capabilities: %v", [capabilities, container.name, input.parameters.capabilities])
}

# * may be used to drop all capabilities
input_drop_capabilities_required(capabilities) {
    input.parameters.capabilities[_] == "*"
}

input_drop_capabilities_required(capabilities) {
    not_allowed_set := {x | x = input.parameters.capabilities[_]}
    test := capabilities & not_allowed_set
    count(test) == 0
}

input_containers[c] {
    c := input.review.object.spec.containers[_]
}
input_containers[c] {
    c := input.review.object.spec.initContainers[_]
}
