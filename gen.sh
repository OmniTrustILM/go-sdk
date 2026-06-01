#!/bin/bash
docker run --rm \
    -v "$PWD:/local:Z" \
    --ulimit nproc=2048:4096 \
    --ulimit nofile=1024:2048 \
    --pids-limit 1024 \
    openapitools/openapi-generator-cli:latest-release generate \
    -i /local/spec/compliance-v1.json \
    --generator-name go \
    -o /local/model/compliance/v1 \
    --additional-properties=disallowAdditionalPropertiesIfNotPresent=false,packageName=v1,enumClassPrefix=true,outputAsLibrary=true \
    --global-property models,supportingFiles,apis=false,modelTests=false,modelDocs=false

# Post-process the generated oneOf wrappers. The Go template emits a
# match-counting UnmarshalJSON that fails when two variants share the same
# Go struct shape (every V3 *AttributeContentV3 has {Reference, Data,
# ContentType}, so any string-shaped JSON matches String + Text + Date +
# Time + Object simultaneously). The patcher replaces these with
# discriminator-aware decoders that switch on the JSON discriminator field
# the spec defines for each oneOf.
go run ./tools/fixoneof connector/model
