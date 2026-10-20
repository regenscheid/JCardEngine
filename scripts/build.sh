#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_dir"
git submodule update --init --recursive
# Install the bundled API JARs before Maven resolves the multi-module reactor.
./mvnw -B -pl simulator initialize
exec ./mvnw -B clean verify "$@"
