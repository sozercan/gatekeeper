FROM golang:1.26-trixie@sha256:f06b7122f888680048afb247c4e5f49c0069eb6c4c1ccae0f3f4834527a8d22c

RUN GO111MODULE=on go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.21.0
RUN GO111MODULE=on go install k8s.io/code-generator/cmd/conversion-gen@v0.29.3

RUN mkdir /gatekeeper
WORKDIR /gatekeeper
