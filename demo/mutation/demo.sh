#!/bin/bash

. ../../third_party/demo-magic/demo-magic.sh

clear

p "*** MUTATION FEATURE IS CURRENTLY IN DEVELOPMENT ***"

pe "cat assignmetadata/assign-label.yaml"

pe "kubectl apply -f assignmetadata/assign-label.yaml"

pe "kubectl create ns cloudnativekitchen"

pe "kubectl get namespace cloudnativekitchen -o yaml"

p "THE END"

kubectl delete -f assignmetadata
