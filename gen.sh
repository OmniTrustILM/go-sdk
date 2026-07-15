#!/bin/bash
# Regenerate every connector model package from its OpenAPI spec.
#
# For each entry below, runs the official openapi-generator docker image
# to produce Go DTOs under connector/model/<provider>/<version>/, then
# runs tools/fixoneof against the whole tree to replace the generator's
# broken oneOf UnmarshalJSON methods with discriminator-aware decoders
# (see tools/fixoneof/main.go for the rationale).
#
# Each table row is "spec_file:target_dir:package_name". Versioned specs
# (authority-v1, authority-v2, compliance-v1, compliance-v2) embed the
# spec generation in the file name; the rest default to v1.
set -euo pipefail

SPECS=(
    "authority-v1.json:connector/model/authority/v1:v1"
    "authority-v2.json:connector/model/authority/v2:v2"
    "authority-v3.json:connector/model/authority/v3:v3"
    "compliance-v1.json:connector/model/compliance/v1:v1"
    "compliance-v2.json:connector/model/compliance/v2:v2"
    "credential.json:connector/model/credential/v1:v1"
    "cryptography.json:connector/model/cryptography/v1:v1"
    "discovery.json:connector/model/discovery/v1:v1"
    "entity.json:connector/model/entity/v1:v1"
    "notification.json:connector/model/notification/v1:v1"
    "secret.json:connector/model/secret/v1:v1"
    "attributes-v2.json:connector/model/attributes/v2:v2"
)

OAPI_GEN_CLI_VER="v7.22.0"

for entry in "${SPECS[@]}"; do
    IFS=":" read -r spec target pkg <<< "$entry"
    echo "==> regenerating $spec -> $target (package $pkg)"
    docker run --rm \
        -v "$PWD:/local:Z" \
        --ulimit nproc=2048:4096 \
        --ulimit nofile=1024:2048 \
        --pids-limit 1024 \
        openapitools/openapi-generator-cli:${OAPI_GEN_CLI_VER} generate \
        -i "/local/connector/spec/$spec" \
        --generator-name go \
        -o "/local/$target" \
        --additional-properties=disallowAdditionalPropertiesIfNotPresent=false,packageName=$pkg,enumClassPrefix=true,outputAsLibrary=true \
        --global-property models,supportingFiles,apis=false,modelTests=false,modelDocs=false
done

echo "==> patching oneOf UnmarshalJSON across connector/model"
go run ./tools/fixoneof connector/model
