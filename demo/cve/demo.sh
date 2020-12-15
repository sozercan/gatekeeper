#!/bin/bash

. ../../third_party/demo-magic/demo-magic.sh

clear

echo "===== ENTER developer ====="
echo

pe "kubectl get pods --all-namespaces"

pe "cat bad/service.yaml"

pe "kubectl apply -f bad/service.yaml"

echo "===== EXIT developer ====="
echo
wait

clear
echo
echo "===== ENTER admin ====="
echo

pe "cat templates/externalips_template.yaml"

pe "kubectl apply -f templates/externalips_template.yaml"

pe "cat constraints/externalips_constraint-dryrun.yaml"

pe "kubectl apply -f constraints/externalips_constraint-dryrun.yaml"

pe "kubectl get k8sexternalips.constraints.gatekeeper.sh external-ips -o yaml"

# Metrics

pe "kubectl delete -f bad/service.yaml"

pe "cat constraints/externalips_constraint.yaml"

pe "kubectl apply -f constraints/externalips_constraint.yaml"

pe "kubectl apply -f bad/service.yaml"

pe "cat good/service.yaml"

pe "kubectl apply -f good/service.yaml"

echo "===== EXIT admin ====="
echo
wait

clear
p "*** MUTATION FEATURE IS CURRENTLY IN DEVELOPMENT ***"

pe "cat assign/assign-externalip.yaml"

pe "kubectl apply -f assign/assign-externalip.yaml"

pe "kubectl apply -f bad/service.yaml"

pe "kubectl get svc disallowed-external-ip -o yaml"

pe "kubectl get k8sexternalips.constraints.gatekeeper.sh external-ips -o yaml"

kubectl delete -f constraints
kubectl delete -f templates
kubectl delete -f good
kubectl delete -f assign
