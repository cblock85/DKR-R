#!/usr/bin/env bash
set -euo pipefail

missing=0
for tool in cmake ninja c++ git pkg-config python3; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "Missing required tool: ${tool}" >&2
    missing=1
  fi
done

# Homebrew installs to /opt/homebrew on Apple Silicon and /usr/local on Intel.
# Surface the active prefix so pkg-config lookups below are explicable when a
# user has both an Intel and an Apple Silicon Homebrew on the same machine.
brew_prefix=""
if command -v brew >/dev/null 2>&1; then
  brew_prefix="$(brew --prefix)"
  export PKG_CONFIG_PATH="${brew_prefix}/lib/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
fi

if command -v pkg-config >/dev/null 2>&1; then
  if ! pkg-config --exists sdl2; then
    echo 'Missing development package exposed by pkg-config: sdl2' >&2
    missing=1
  fi
fi

if [[ "${missing}" -ne 0 ]]; then
  cat >&2 <<'MSG'

macOS build prerequisites:
  xcode-select --install
  brew install cmake ninja pkg-config sdl2 python3

Then rerun ./Setup-macOS.sh.
MSG
  exit 1
fi

host_arch="$(uname -m)"
echo "Host architecture: ${host_arch}"
[[ -n "${brew_prefix}" ]] && echo "Homebrew prefix: ${brew_prefix}"
if [[ "${host_arch}" == "arm64" && "${brew_prefix}" == "/usr/local" ]]; then
  echo 'Warning: an Intel Homebrew prefix is active on an Apple Silicon host.' >&2
  echo 'The build will link x86_64 dependencies unless you use /opt/homebrew.' >&2
fi

cmake --version | head -n1
c++ --version | head -n1
pkg-config --modversion sdl2
echo "macOS setup checks passed. Run ./Build-macOS.sh."
