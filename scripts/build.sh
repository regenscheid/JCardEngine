#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_dir"
if [[ ! -f .mvn/wrapper/maven-wrapper.jar ]] && ! command -v curl >/dev/null && ! command -v wget >/dev/null; then
    echo "Install curl or wget so the Maven wrapper can bootstrap itself." >&2
    exit 1
fi
git submodule update --init --recursive
# Install the bundled API JARs before Maven resolves the multi-module reactor.
./mvnw -B -pl simulator initialize
exec ./mvnw -B clean verify "$@"
