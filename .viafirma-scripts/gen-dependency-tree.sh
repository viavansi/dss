#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && git rev-parse --show-toplevel)"
docker run --rm --network host -v "$REPO_ROOT:/workspace" -v "$HOME/.m2/settings.xml:/root/.m2/settings.xml:ro" -w "/workspace" "maven:3.9.9-eclipse-temurin-21" bash -lc 'mvn -s /root/.m2/settings.xml -Dmaven.test.skip=true org.apache.maven.plugins:maven-dependency-plugin:3.7.0:tree -DoutputType=text -DoutputFile=dependency-tree.txt'
