#!/bin/sh
# Download the rebar3 escript of a release through the GitHub API.
# The API asset endpoint keeps working when the public release download
# link (and setup-beam, which uses it) fails with 5xx errors.
# Usage: fetch-rebar3.sh VERSION DIR
set -eu
version=$1
dir=$2
mkdir -p "$dir"
id=$(gh api "repos/erlang/rebar3/releases/tags/$version" \
       --jq '.assets[] | select(.name == "rebar3") | .id')
for attempt in 1 2 3 4 5; do
    if gh api -H 'Accept: application/octet-stream' \
         "repos/erlang/rebar3/releases/assets/$id" > "$dir/rebar3"; then
        chmod +x "$dir/rebar3"
        "$dir/rebar3" version
        exit 0
    fi
    echo "download failed (attempt $attempt), retrying"
    sleep $((attempt * 10))
done
exit 1
