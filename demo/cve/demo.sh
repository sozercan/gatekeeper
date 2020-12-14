#!/bin/bash

. ../../third_party/demo-magic/demo-magic.sh

clear

echo "===== ENTER developer ====="
echo

pe "cat bad/service.yaml"

pe "kubectl apply -f bad/service.yaml"

echo "===== EXIT developer ====="
echo
wait

clear
echo
echo "===== ENTER admin ====="
echo

# namespace exclusion?
# pe "kubectl create ns staging"
# pe "cat config.yaml"
# pe "kubectl apply -f config.yaml"

# pe "cat templates/allowedrepos_template.yaml"
# pe "kubectl apply -f templates/allowedrepos_template.yaml"

pe "cat templates/externalips_template.yaml"

pe "kubectl apply -f templates/externalips_template.yaml"

# pe "cat constraints/allowedrepos_contraint-dryrun.yaml"
# pe "kubectl apply -f constraints/allowedrepos_constraint-dryrun.yaml"
# pe "kubectl get k8sallowedrepos.constraints.gatekeeper.sh -o yaml"

pe "cat constraints/externalips_constraint-dryrun.yaml"

pe "kubectl apply -f constraints/externalips_constraint-dryrun.yaml"

pe "kubectl get k8sexternalips.constraints.gatekeeper.sh external-ips -o yaml"

# Metrics

pe "kubectl delete -f bad/service.yaml"

pe "kubectl apply -f constraints/externalips_constraint.yaml"

pe "kubectl apply -f bad/service.yaml"

# pe "kubectl apply -f bad/service.yaml -n staging"

pe "cat good/service.yaml"

pe "kubectl apply -f good/service.yaml"

echo "===== EXIT admin ====="
echo

kubectl delete -f constraints
kubectl delete -f templates
kubectl delete -f good
kubectl delete ns staging
kubectl delete -f config.yaml
