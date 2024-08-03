#!/usr/bin/env bash
# Requirement to run: compatible rust toolchain for the architecture, qemu-user, gcc-{arch}-linux-gnu

if [ -z "$1" ]; then
    echo "Usage: $0 <architecture>"
    echo "Supported architectures: aarch64, riscv64, x86_64"
    exit 1
fi

readonly ARCH=$1

case $ARCH in
    "aarch64")
        CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc cargo build --release --target=aarch64-unknown-linux-gnu --bin=verification --no-default-features --features=verification
        qemu-aarch64 -cpu a64fx -L /usr/aarch64-linux-gnu ./target/riscv64gc-unknown-linux-gnu/release/verification
        ;;
    "riscv64")
        CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER=riscv64-linux-gnu-gcc cargo +nightly build --release --target=riscv64gc-unknown-linux-gnu --bin=verification --no-default-features --features=verification
        qemu-riscv64 -cpu rv64,zicsr=true,f=true,d=true,v=true,zba=true,vlen=128,zk=true,zkn=true,zkne=true,zknd=true,zknh=true -L /usr/riscv64-linux-gnu ./target/riscv64gc-unknown-linux-gnu/release/verification
        ;;
    "x86_64")
        CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc cargo build --release --target=x86_64-unknown-linux-gnu --bin=verification --no-default-features --features=verification
        qemu-x86_64 -cpu Westmere -L /usr/x86-64-linux-gnu ./target/x86_64-unknown-linux-gnu/release/verification
        ;;
    *)
        echo "Error: Unknown architecture '$ARCH'"
        exit 1
        ;;
esac
