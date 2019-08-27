package k8spspcapabilities

violation[{"msg": msg, "details": {}}] {
    container := input_containers[_]
    capabilities := container.securityContext.capabilities
    not input_capabilities(capabilities)
    msg := sprintf("One of the capabilities is not allowed, pod: %v", [container.name])
}

input_capabilities(capabilities) {
    input.parameters.addCapabilities[_] == "*"
}

input_capabilities(capabilities) {
    input.parameters.dropCapabilities[_] != "all"
}

input_capabilities(capabilities) {
    allowed_set := {x | x = input.parameters.addCapabilities[_]}
    add_capabilities := {x | x = capabilities.add[_]}
    test := add_capabilities - allowed_set
    count(test) == 0
}

input_capabilities(capabilities) {
    not_allowed_set := {x | x = input.parameters.dropCapabilities[_]}
    drop_capabilities := {x | x = capabilities.drop[_]}
    test := drop_capabilities - not_allowed_set
    not count(test) > 0
}

input_containers[c] {
    c := input.review.object.spec.containers[_]
}
input_containers[c] {
    c := input.review.object.spec.initContainers[_]
}
