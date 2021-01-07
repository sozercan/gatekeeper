#!/bin/bash
set -x

WAIT_TIME=240
SLEEP_TIME=5

wait_for_process() {
    wait_time="$1"
    sleep_time="$2"
    cmd="$3"
    while [ "$wait_time" -gt 0 ]; do
        if eval "$cmd"; then
            return 0
        else
            sleep "$sleep_time"
            wait_time=$((wait_time - sleep_time))
        fi
    done
    return 1
}

compare_generation() {
    kind="$1"
    constraint="$2"

    [[ "$(kubectl get ${kind}.constraints.gatekeeper.sh ${constraint} -o json | jq '.status.byPod[0].observedGeneration')" = "$(kubectl get ${kind}.constraints.gatekeeper.sh ${constraint} -o json | jq '.metadata.generation')" ]]
}

kubectl apply -f testing/gatekeeper/gk.yaml

wait_for_process $WAIT_TIME $SLEEP_TIME "kubectl wait -n gatekeeper-system --for=condition=Ready --timeout=60s pod -l control-plane=audit-controller"

wait_for_process $WAIT_TIME $SLEEP_TIME "kubectl wait -n gatekeeper-system --for=condition=Ready --timeout=60s pod -l control-plane=controller-manager"

wait_for_process $WAIT_TIME $SLEEP_TIME "kubectl wait --for condition=established --timeout=60s crd/constrainttemplates.templates.gatekeeper.sh"

wait_for_process $WAIT_TIME $SLEEP_TIME "kubectl wait --for condition=established --timeout=60s crd/configs.config.gatekeeper.sh"

# deploying templates
t="1"
while [ $t -le $NUMBER_TEMPLATES ]; do
    export TEMPLATE_NAME=template-$(openssl rand -hex 6)

    envsubst <testing/gatekeeper/allowedrepos-template-template.yaml >testing/gatekeeper/allowedrepos-template.yaml

    kubectl apply -f testing/gatekeeper/allowedrepos-template.yaml

    wait_for_process $WAIT_TIME $SLEEP_TIME "kubectl wait --for condition=established --timeout=60s crd/$TEMPLATE_NAME.constraints.gatekeeper.sh"

    t=$(($t + 1))

    # number of constraints per template
    c="1"
    while [ $c -le $NUMBER_CONSTRAINTS ]; do
        export CONSTRAINT_NAME=repo-$(openssl rand -hex 6)

        envsubst <testing/gatekeeper/allowedrepos-constraint-template.yaml >testing/gatekeeper/allowedrepos-constraint.yaml

        kubectl apply -f testing/gatekeeper/allowedrepos-constraint.yaml

        wait_for_process $WAIT_TIME $SLEEP_TIME "compare_generation $TEMPLATE_NAME $CONSTRAINT_NAME"

        c=$(($c + 1))
    done
done
