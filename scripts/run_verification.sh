#!/usr/bin/env bash
set -euo pipefail

# Requirement to run under linux:
#   1. compatible Rust toolchain for the architecture
#   2. qemu-user
#   3. gcc-{arch}-linux-gnu

set +u
if [ -z "$1" ]; then
    echo "Usage: $0 <architecture>"
    echo "Supported architectures: aarch64, riscv64, x86, x86_64"
    exit 1
fi
set -u

readonly ARCH=$1

pushd verification
trap popd EXIT

case $ARCH in
    "aarch64")
        CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc cargo build --release --target=aarch64-unknown-linux-gnu
        qemu-aarch64 -cpu cortex-a53 -L /usr/aarch64-linux-gnu ../target/aarch64-unknown-linux-gnu/release/verification
        ;;
    "riscv64")
        CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER=riscv64-linux-gnu-gcc cargo build --release --target=riscv64gc-unknown-linux-gnu --no-default-features --features=experimental_riscv
        qemu-riscv64 -cpu rv64,v=true,vlen=128,zvkn=true -L /usr/riscv64-linux-gnu ../target/riscv64gc-unknown-linux-gnu/release/verification
        ;;
    "x86")
        CARGO_TARGET_I686_UNKNOWN_LINUX_GNU_LINKER=i686-linux-gnu-gcc cargo build --release --target=i686-unknown-linux-gnu
        qemu-i386 -cpu Westmere -L /usr/i686-linux-gnu ../target/i686-unknown-linux-gnu/release/verification
        ;;
    "x86_64")
        CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc cargo build --release --target=x86_64-unknown-linux-gnu
        qemu-x86_64 -cpu Westmere -L /usr/x86-64-linux-gnu ../target/x86_64-unknown-linux-gnu/release/verification
        ;;
    *)
        echo "Error: Unknown architecture '$ARCH'"
        exit 1
        ;;
esac
