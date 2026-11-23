#!/usr/bin/env bash
# docker-image-check.sh <project_dir>: compare every image of a Compose project
# with its registry, without pulling anything (local digest vs registry digest,
# via docker buildx imagetools). Used by docker_check.yml.
#
# Output, one line per image:  image|status|detail
#   ok      the local image is the latest for its tag
#   update  the registry has a newer image for the tag (detail = remote digest)
#   pinned  pinned with @sha256 in the compose file: not checked
#   local   no registry digest (built locally, or not pulled yet)
#   error   could not be checked (detail = reason)
set -uo pipefail
dir="${1:-}"
cd "$dir" 2>/dev/null || { echo "$dir|error|project directory not found"; exit 0; }
images="$(docker compose config --images 2>/dev/null | sort -u)" \
  || { echo "$dir|error|docker compose config failed"; exit 0; }

for img in $images; do
  if [[ "$img" == *@sha256:* ]]; then echo "$img|pinned|pinned by digest"; continue; fi
  local_digests="$(docker image inspect --format '{{join .RepoDigests " "}}' "$img" 2>/dev/null)"
  if [[ -z "$local_digests" ]]; then echo "$img|local|no registry digest"; continue; fi
  remote="$(timeout 60 docker buildx imagetools inspect "$img" --format '{{.Manifest.Digest}}' 2>&1)" \
    || { echo "$img|error|${remote//$'\n'/ }"; continue; }
  # Only the digest is compared: the repository part can be written several ways.
  if [[ " $local_digests " == *"@$remote "* ]]; then echo "$img|ok|"; else echo "$img|update|$remote"; fi
done
