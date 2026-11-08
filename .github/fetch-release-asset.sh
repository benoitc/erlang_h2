#!/bin/sh
# Download one asset of a GitHub release through the GitHub API.
# The API asset endpoint keeps working when the public release download
# link fails with 5xx errors.
# Usage: fetch-release-asset.sh REPO TAG NAME DIR
set -eu
repo=$1
tag=$2
name=$3
dir=$4
mkdir -p "$dir"
id=$(gh api "repos/$repo/releases/tags/$tag" \
       --jq ".assets[] | select(.name == \"$name\") | .id")
for attempt in 1 2 3 4 5; do
    if gh api -H 'Accept: application/octet-stream' \
         "repos/$repo/releases/assets/$id" > "$dir/$name"; then
        exit 0
    fi
    echo "download failed (attempt $attempt), retrying"
    sleep $((attempt * 10))
done
exit 1
