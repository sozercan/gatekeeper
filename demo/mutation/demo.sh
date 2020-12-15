#!/bin/bash

. ../../third_party/demo-magic/demo-magic.sh

clear

p "*** MUTATION FEATURE IS CURRENTLY IN DEVELOPMENT ***"

pe "cat templates/requiredlabels_template.yaml"

pe "kubectl apply -f templates/requiredlabels_template.yaml"

pe "cat constraints/requiredlabels_constraint.yaml"

pe "kubectl apply -f constraints/requiredlabels_constraint.yaml"

pe "kubectl create ns cloudnativekitchen"

pe "cat assignmetadata/assign-label.yaml"

pe "kubectl apply -f assignmetadata/assign-label.yaml"

pe "kubectl create ns cloudnativekitchen"

pe "kubectl get namespace cloudnativekitchen -o yaml"

pe "kubectl get k8srequiredlabels all-must-have-owner -o yaml"

p "THE END"

kubectl delete -f assignmetadata
