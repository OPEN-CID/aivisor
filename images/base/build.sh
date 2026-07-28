#!/bin/bash
# Build a minimal AIVisor base image.
# Produces a directory and optionally a squashfs.
# No Docker required — uses busybox tarball + debootstrap.

set -euo pipefail

ROOTFS_DIR="${1:-./output/rootfs}"
SQUASHFS="${2:-}"

if [ -d "$ROOTFS_DIR" ]; then
    echo "Cleaning existing rootfs at $ROOTFS_DIR"
    rm -rf "$ROOTFS_DIR"
fi

mkdir -p "$ROOTFS_DIR"

echo "Installing busybox + base packages..."

# Use apko or manual busybox extraction
BUSYBOX_URL="https://busybox.net/downloads/binaries/1.36.1/busybox-x86_64"
if command -v apko &>/dev/null; then
    echo "Using apko to build image..."
    apko build --output-dir "$ROOTFS_DIR" \
        images/base/apko.yaml \
        aivisor-base:latest
else
    echo "Using manual busybox setup..."
    mkdir -p "$ROOTFS_DIR/bin" "$ROOTFS_DIR/usr/bin" \
             "$ROOTFS_DIR/etc" "$ROOTFS_DIR/dev" \
             "$ROOTFS_DIR/proc" "$ROOTFS_DIR/sys" \
             "$ROOTFS_DIR/tmp" "$ROOTFS_DIR/workspace" \
             "$ROOTFS_DIR/usr/lib" "$ROOTFS_DIR/etc/ssl/certs"

    # Download and install busybox
    wget -q -O "$ROOTFS_DIR/bin/busybox" "$BUSYBOX_URL" 2>/dev/null || {
        echo "Warning: could not download busybox. Create a symlink for build testing:"
        ln -sf /bin/busybox "$ROOTFS_DIR/bin/busybox" 2>/dev/null || true
    }
    chmod +x "$ROOTFS_DIR/bin/busybox" 2>/dev/null || true

    # Install busybox applets
    if [ -x "$ROOTFS_DIR/bin/busybox" ]; then
        for applet in sh bash cat echo ls cp mv rm mkdir rmdir touch chmod chown \
                       ps mount umount grep sed awk wc head tail sort find tar gzip \
                       python3; do
            ln -sf /bin/busybox "$ROOTFS_DIR/bin/$applet" 2>/dev/null || true
        done
    fi

    # Create device nodes
    mknod -m 666 "$ROOTFS_DIR/dev/null" c 1 3 2>/dev/null || true
    mknod -m 666 "$ROOTFS_DIR/dev/zero" c 1 5 2>/dev/null || true
    mknod -m 666 "$ROOTFS_DIR/dev/random" c 1 8 2>/dev/null || true
    mknod -m 444 "$ROOTFS_DIR/dev/urandom" c 1 9 2>/dev/null || true

    # Minimal /etc
    echo "root:x:0:0:root:/root:/bin/sh" > "$ROOTFS_DIR/etc/passwd"
    echo "root:x:0:" > "$ROOTFS_DIR/etc/group"
    echo "nameserver 1.1.1.1" > "$ROOTFS_DIR/etc/resolv.conf"
fi

echo "Base image created at $ROOTFS_DIR"
echo "Size: $(du -sh "$ROOTFS_DIR" | cut -f1)"

if [ -n "$SQUASHFS" ]; then
    echo "Building squashfs..."
    mksquashfs "$ROOTFS_DIR" "$SQUASHFS" -comp zstd -noappend
    echo "Squashfs created: $SQUASHFS ($(du -sh "$SQUASHFS" | cut -f1))"
fi
