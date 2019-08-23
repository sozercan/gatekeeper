package k8spspcapabilities

test_input_allowed_add_capabilities_allowed_all {
    input := { "review": input_review, "parameters": input_parameters_wildcard}
    results := violation with input as input
    count(results) == 0
}

test_input_allowed_add_capabilities_not_allowed_all {
    input := { "review": input_review, "parameters": input_parameters_wildcard}
    results := violation with input as input
    count(results) == 0
}

test_input_allowed_add_capabilities_allowed_in_list {
    input := { "review": input_review, "parameters": input_parameters_in_list}
    results := violation with input as input
    count(results) == 0
}

test_input_allowed_add_capabilities_allowed_not_in_list {
    input := { "review": input_review, "parameters": input_parameters_not_in_list}
    results := violation with input as input
    count(results) > 0
}

test_input_allowed_add_capabilities_allowed_in_list_many {
    input := { "review": input_review_many, "parameters": input_parameters_in_list}
    results := violation with input as input
    count(results) == 0
}

test_input_allowed_add_capabilities_allowed_not_in_list_many {
    input := { "review": input_review_many, "parameters": input_parameters_not_in_list}
    results := violation with input as input
    count(results) > 0
}

input_review = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": input_containers_one
      }
    }
}

input_review_drop_all = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": input_containers_wildcard
      }
    }
}

input_review_many = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": input_containers_many
      }
    }
}

input_containers_wildcard = [
{
    "name": "nginx",
    "image": "nginx",
    "securityContext": {
        "capabilities": {
            "drop": [
                "SYS_TIME"
            ]
        }
    }
}]

input_containers_one = [
{
    "name": "nginx",
    "image": "nginx",
    "securityContext": {
        "capabilities": {
            "add": [
                "SYS_TIME"
            ],
            "drop": [
                "SYS_ADMIN"
            ]
        }
    }
}]

input_containers_many = [
{
    "name": "nginx",
    "image": "nginx",
    "securityContext": {
        "capabilities": {
            "add": [
                "SYS_TIME"
            ],
            "drop": [
                "SYS_ADMIN"
            ]
        }
    }
},
{
    "name": "nginx2",
    "image": "nginx"
}]

input_parameters_wildcard = {
    "addCapabilities": [
        "*"
    ],
    "dropCapabilities": [
        "all"
    ]
}

input_parameters_in_list = {
    "addCapabilities": [
        "SYS_TIME"
    ],
    "dropCapabilities": [
        "SYS_ADMIN"
    ]
}

input_parameters_not_in_list = {
    "dropCapabilities": [
        "KILL"
    ],
    "addCapabilities": [
        "NET_ADMIN"
    ]
}
