#!/usr/bin/env bash
# macOS/Linux counterpart of Build-DKR-Runtime.cmd: prepares the decomp ELF,
# runs the static recompilation, and validates the runtime probe, entirely on
# this POSIX host. Pass your own DKR US 1.0 ROM on first run:
#
#   ./Build-DKR-Runtime-macOS.sh --rom ~/roms/dkr.us.z64
#
# Afterwards run ./Build-macOS.sh (or ./Build-Linux.sh) for the full package.
set -euo pipefail
project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${project_root}/scripts/prepare_dkr_runtime_posix.py" "$@"
