#!/bin/bash

echo $CR_PAT | docker login ghcr.io --username $CR_USERNAME --password-stdin
docker buildx build --platform linux/arm64,linux/amd64 -t ghcr.io/$CR_USERNAME/goflowprobe . --push
