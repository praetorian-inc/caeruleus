#!/usr/bin/env bash
# setup.sh — Install nRF5 SDK 17.1.0 toolchain on macOS
#
# Installs: ARM GCC, nRF Command Line Tools, nrfutil, nRF5 SDK
# Target:   caeruleus-target firmware build environment
#
# Usage:    ./setup.sh [--sdk-dir DIR]
#           Default SDK install: ~/nRF5_SDK_17.1.0_ddde560

set -euo pipefail

SDK_DIR="${1:-${HOME}/nRF5_SDK_17.1.0_ddde560}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*" >&2; }

# --------------------------------------------------------------------------
# Step 0: Prerequisites
# --------------------------------------------------------------------------

if ! command -v brew &>/dev/null; then
    error "Homebrew not found. Install from https://brew.sh"
    exit 1
fi

# --------------------------------------------------------------------------
# Step 1: ARM GCC Toolchain
# --------------------------------------------------------------------------

if command -v arm-none-eabi-gcc &>/dev/null; then
    info "ARM GCC already installed: $(arm-none-eabi-gcc --version | head -1)"
else
    info "Installing ARM GCC toolchain via Homebrew..."
    brew install --cask gcc-arm-embedded
    if command -v arm-none-eabi-gcc &>/dev/null; then
        info "ARM GCC installed: $(arm-none-eabi-gcc --version | head -1)"
    else
        error "ARM GCC installation failed. Try manually:"
        error "  brew install --cask gcc-arm-embedded"
        exit 1
    fi
fi

# --------------------------------------------------------------------------
# Step 2: nRF Command Line Tools (nrfjprog, mergehex)
# --------------------------------------------------------------------------

if command -v nrfjprog &>/dev/null; then
    info "nRF Command Line Tools already installed: $(nrfjprog --version 2>&1 | head -1)"
else
    info "Installing nRF Command Line Tools via Homebrew..."
    brew install --cask nordic-nrf-command-line-tools
    if command -v nrfjprog &>/dev/null; then
        info "nrfjprog installed: $(nrfjprog --version 2>&1 | head -1)"
    else
        warn "nrfjprog not found after install."
        warn "Download manually from: https://www.nordicsemi.com/Products/Development-tools/nRF-Command-Line-Tools/Download"
        warn "After install, add to PATH: export PATH=\"/Applications/Nordic Semiconductor/nRF Command Line Tools/bin:\$PATH\""
    fi
fi

# --------------------------------------------------------------------------
# Step 3: nrfutil (DFU package generation)
# --------------------------------------------------------------------------

if command -v nrfutil &>/dev/null; then
    info "nrfutil already installed: $(nrfutil version 2>&1 | head -1)"
else
    info "Installing nrfutil via pip..."
    if command -v pip3 &>/dev/null; then
        pip3 install nrfutil
    elif command -v pip &>/dev/null; then
        pip install nrfutil
    else
        warn "pip not found. Installing nrfutil via Homebrew Python..."
        brew install python3
        pip3 install nrfutil
    fi

    if command -v nrfutil &>/dev/null; then
        info "nrfutil installed: $(nrfutil version 2>&1 | head -1)"
    else
        warn "nrfutil not found on PATH after install."
        warn "Try: pip3 install nrfutil"
    fi
fi

# --------------------------------------------------------------------------
# Step 4: nRF5 SDK 17.1.0
# --------------------------------------------------------------------------

if [ -d "${SDK_DIR}" ]; then
    info "nRF5 SDK already exists at ${SDK_DIR}"
else
    info "Downloading nRF5 SDK 17.1.0..."
    SDK_ZIP="/tmp/nRF5_SDK_17.1.0_ddde560.zip"

    if [ ! -f "${SDK_ZIP}" ]; then
        curl -L -o "${SDK_ZIP}" \
            "https://nsscprodmedia.blob.core.windows.net/prod/software-and-other-downloads/sdks/nrf5/binaries/nrf5_sdk_17.1.0_ddde560.zip"
    fi

    info "Extracting to ${SDK_DIR}..."
    unzip -q "${SDK_ZIP}" -d "$(dirname "${SDK_DIR}")"

    if [ -d "${SDK_DIR}" ]; then
        info "nRF5 SDK 17.1.0 installed at ${SDK_DIR}"
    else
        # The zip might extract with a different name
        EXTRACTED=$(ls -d "$(dirname "${SDK_DIR}")"/nRF5_SDK* 2>/dev/null | head -1)
        if [ -n "${EXTRACTED}" ] && [ -d "${EXTRACTED}" ]; then
            mv "${EXTRACTED}" "${SDK_DIR}"
            info "nRF5 SDK 17.1.0 installed at ${SDK_DIR}"
        else
            error "SDK extraction failed. Check ${SDK_ZIP}"
            exit 1
        fi
    fi

    rm -f "${SDK_ZIP}"
fi

# --------------------------------------------------------------------------
# Step 5: Configure SDK toolchain path
# --------------------------------------------------------------------------

GNU_INSTALL_ROOT=""
if command -v arm-none-eabi-gcc &>/dev/null; then
    GCC_PATH="$(dirname "$(which arm-none-eabi-gcc)")"
    GNU_INSTALL_ROOT="${GCC_PATH}/"
fi

MAKEFILE_POSIX="${SDK_DIR}/components/toolchain/gcc/Makefile.posix"
if [ -f "${MAKEFILE_POSIX}" ]; then
    info "Configuring SDK GNU toolchain path..."
    # Back up original
    cp "${MAKEFILE_POSIX}" "${MAKEFILE_POSIX}.bak"
    cat > "${MAKEFILE_POSIX}" <<EOF
GNU_INSTALL_ROOT ?= ${GNU_INSTALL_ROOT}
GNU_VERSION ?= $(arm-none-eabi-gcc -dumpversion 2>/dev/null || echo "10.3.1")
GNU_PREFIX ?= arm-none-eabi
EOF
    info "Updated ${MAKEFILE_POSIX}"
fi

# --------------------------------------------------------------------------
# Step 6: Verify
# --------------------------------------------------------------------------

echo ""
echo "=========================================="
echo "  Toolchain Verification"
echo "=========================================="

PASS=true

check() {
    local name="$1"
    local cmd="$2"
    if command -v "${cmd}" &>/dev/null; then
        info "${name}: $(${cmd} --version 2>&1 | head -1)"
    else
        error "${name}: NOT FOUND"
        PASS=false
    fi
}

check "ARM GCC"    "arm-none-eabi-gcc"
check "nrfjprog"   "nrfjprog"
check "mergehex"   "mergehex"
check "nrfutil"    "nrfutil"

if [ -d "${SDK_DIR}" ]; then
    info "nRF5 SDK: ${SDK_DIR}"
else
    error "nRF5 SDK: NOT FOUND at ${SDK_DIR}"
    PASS=false
fi

echo ""
if [ "${PASS}" = true ]; then
    info "All tools installed. Ready to build."
    echo ""
    echo "  export SDK_ROOT=${SDK_DIR}"
    echo "  cd ${SCRIPT_DIR}/pca10056/s140/armgcc"
    echo "  make"
    echo ""
else
    warn "Some tools missing — see errors above."
fi

# --------------------------------------------------------------------------
# Step 7: Shell config hint
# --------------------------------------------------------------------------

echo "Add to your shell profile (~/.zshrc or ~/.bashrc):"
echo ""
echo "  export SDK_ROOT=${SDK_DIR}"
echo ""
