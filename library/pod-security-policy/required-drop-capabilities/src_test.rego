package k8spsprequireddropcapabilities

test_input_required_drop_capabilities_all {
    input := { "review": input_review, "parameters": input_parameters_wildcard}
    results := violation with input as input
    count(results) == 1
}

test_input_required_drop_capabilities_in_list {
    input := { "review": input_review, "parameters": input_parameters_in_list}
    results := violation with input as input
    count(results) == 0
}

test_input_required_drop_capabilities_not_in_list {
    input := { "review": input_review, "parameters": input_parameters_not_in_list}
    results := violation with input as input
    count(results) > 0
}

test_input_required_drop_capabilities_in_list_many {
    input := { "review": input_review_many, "parameters": input_parameters_in_list}
    results := violation with input as input
    count(results) == 0
}

test_input_required_drop_capabilities_not_in_list_many {
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

input_containers_one = [
{
    "name": "nginx",
    "image": "nginx",
    "securityContext": {
        "capabilities": {
            "drop": [
                "SYS_TIME",
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
            "drop": [
                "SYS_TIME",
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
    "capabilities": [
        "all"
    ]
}

input_parameters_in_list = {
    "capabilities": [
        "SYS_TIME"
    ]
}

input_parameters_not_in_list = {
    "capabilities": [
        "NET_ADMIN",
        "SYS_NICE"
    ]
}
