#!/bin/bash
# Build a minimal AIVisor base image.
# Produces a directory and optionally a squashfs.
# No Docker required — uses busybox tarball + debootstrap.

set -euo pipefail

ROOTFS_DIR="${1:-./output/rootfs}"
SQUASHFS="${2:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APKO_YAML="$SCRIPT_DIR/apko.yaml"

if [ -d "$ROOTFS_DIR" ]; then
    echo "Cleaning existing rootfs at $ROOTFS_DIR"
    rm -rf "$ROOTFS_DIR"
fi

mkdir -p "$ROOTFS_DIR"

echo "Installing busybox + base packages..."

BUSYBOX_URL="https://busybox.net/downloads/binaries/1.36.1/busybox-x86_64"
if command -v apko &>/dev/null && [ -f "$APKO_YAML" ]; then
    echo "Using apko to build image..."
    apko build --output-dir "$ROOTFS_DIR" "$APKO_YAML" aivisor-base:latest
else
    if command -v apko &>/dev/null; then
        echo "apko is installed but $APKO_YAML does not exist yet — falling back to manual busybox setup."
    fi
    echo "Using manual busybox setup..."
    # Every directory the runtime's built-in default policy
    # (aivisor-runtime::manager::default_policy) installs a Landlock rule
    # against MUST exist here — Landlock rule installation opens each rule
    # path and fails closed (denies the whole launch) if it's missing, per
    # that function's own doc comment. That's /workspace, /usr, /lib,
    # /lib64, /etc/ssl/certs, /tmp — not just /usr/lib.
    mkdir -p "$ROOTFS_DIR/bin" "$ROOTFS_DIR/usr/bin" \
             "$ROOTFS_DIR/etc" "$ROOTFS_DIR/dev" \
             "$ROOTFS_DIR/proc" "$ROOTFS_DIR/sys" \
             "$ROOTFS_DIR/tmp" "$ROOTFS_DIR/workspace" \
             "$ROOTFS_DIR/usr/lib" "$ROOTFS_DIR/lib" "$ROOTFS_DIR/lib64" \
             "$ROOTFS_DIR/etc/ssl/certs"

    # Download busybox. If that fails (offline build host), fall back to
    # copying the build host's own busybox binary — as a real copy, not a
    # symlink: a symlink to an absolute host path like /bin/busybox
    # resolves against the SANDBOX's own root after pivot_root, not the
    # host's, so it would end up dangling and useless inside every sandbox
    # built from this image. If neither source is available, leave /bin
    # empty and say so — a rootfs that silently claims to have a shell it
    # doesn't is worse than one that visibly doesn't.
    if ! wget -q -O "$ROOTFS_DIR/bin/busybox" "$BUSYBOX_URL"; then
        rm -f "$ROOTFS_DIR/bin/busybox"
        HOST_BUSYBOX="$(command -v busybox || true)"
        if [ -n "$HOST_BUSYBOX" ] && [ -f "$HOST_BUSYBOX" ]; then
            echo "Could not download busybox; copying host binary at $HOST_BUSYBOX instead."
            cp "$HOST_BUSYBOX" "$ROOTFS_DIR/bin/busybox"
        else
            echo "Warning: no busybox available (download failed, none found on host)." >&2
            echo "         $ROOTFS_DIR/bin will have no shell/coreutils." >&2
        fi
    fi
    if [ -f "$ROOTFS_DIR/bin/busybox" ]; then
        chmod +x "$ROOTFS_DIR/bin/busybox"

        # Real busybox applet names only (no "python3" — busybox has never
        # had a python3 applet; that entry produced a permanently-dangling
        # symlink here previously).
        for applet in sh bash cat echo ls cp mv rm mkdir rmdir touch chmod chown \
                       ps mount umount grep sed awk wc head tail sort find tar gzip; do
            ln -sf /bin/busybox "$ROOTFS_DIR/bin/$applet"
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
    # A real base image would ship a genuine, restrictively-permissioned
    # /etc/shadow — this placeholder exists so hostile.rs's
    # test_cannot_read_etc_shadow has a real file to attempt reading.
    # Without it, the read fails with ENOENT (no such file), which the
    # test correctly classifies as UNVERIFIED rather than DENIED: ENOENT
    # proves nothing about confinement, only that the path is absent.
    echo "root:!:19000:0:99999:7:::" > "$ROOTFS_DIR/etc/shadow"
    chmod 0640 "$ROOTFS_DIR/etc/shadow"
fi

echo "Base image created at $ROOTFS_DIR"
echo "Size: $(du -sh "$ROOTFS_DIR" | cut -f1)"

if [ -n "$SQUASHFS" ]; then
    echo "Building squashfs..."
    mksquashfs "$ROOTFS_DIR" "$SQUASHFS" -comp zstd -noappend
    echo "Squashfs created: $SQUASHFS ($(du -sh "$SQUASHFS" | cut -f1))"
fi
