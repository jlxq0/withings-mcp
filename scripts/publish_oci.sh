#!/usr/bin/env bash
# Publish the already scanned OCI index, without another build or media conversion.
set -euo pipefail

layout=${1:?OCI layout directory required}
digest=${2:?scanned OCI index digest required}
repository=${3:?destination repository required}
version=${4:?immutable release tag required}
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
[[ "$repository" =~ ^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+$ ]]
test -d "$layout/blobs/sha256"
source="ocidir://${layout}@${digest}"
test "$(regctl image digest "$source")" = "$digest"

# A failed list is an error, not evidence that the tag is absent. Release tags
# are single-writer inputs; do not overwrite an existing different artifact.
tags=$(regctl tag ls "$repository")
if printf '%s\n' "$tags" | grep -Fx -- "$version" >/dev/null; then
  test "$(regctl image digest "${repository}:${version}")" = "$digest"
fi

# Copy the complete index recursively, including BuildKit's attestation
# manifests. Address by digest first, verify, then expose the release tags.
regctl image copy --force-recursive "$source" "${repository}@${digest}"
test "$(regctl image digest "${repository}@${digest}")" = "$digest"
regctl image copy --force-recursive "${repository}@${digest}" "${repository}:${version}"
test "$(regctl image digest "${repository}:${version}")" = "$digest"
regctl image copy --force-recursive "${repository}@${digest}" "${repository}:latest"
test "$(regctl image digest "${repository}:latest")" = "$digest"
printf 'Published scanned OCI index %s\n' "$digest"
