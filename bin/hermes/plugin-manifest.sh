#!/usr/bin/env bash
# One hash for the files of a plugin directory: sha256 over the sorted "sha256  path" lines.
# Used on the pinned git tree to record the pin, and on the installed directory to check it.
# __pycache__ is left out: Python writes it, and it is not the plugin.
set -euo pipefail
dir=${1:?plugin directory}
cd "$dir"
find . -type f -not -path '*/__pycache__/*' -printf '%P\0' | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1
