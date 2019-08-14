package k8spspallowedaddcapabilities

violation[{"msg": msg, "details": {}}] {
    container := input_containers[_]
    capabilities := {x | x = container.securityContext.capabilities.add[_]}
    not input_add_capabilities_allowed(capabilities)
    msg := sprintf("One of the add capabilities %v is not allowed, pod: %v. Allowed capabilities: %v", [capabilities, container.name, input.parameters.capabilities])
}

# * may be used to allow all capabilities
input_add_capabilities_allowed(capabilities) {
    input.parameters.capabilities[_] == "*"
}

input_add_capabilities_allowed(capabilities) {
    allowed_set := {x | x = input.parameters.capabilities[_]}
    test := capabilities - allowed_set
    count(test) == 0
}

input_containers[c] {
    c := input.review.object.spec.containers[_]
}
input_containers[c] {
    c := input.review.object.spec.initContainers[_]
}
