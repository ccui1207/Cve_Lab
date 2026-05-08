#!/usr/bin/env bash

set -e

OUT_DIR=${1:-"."}
OUT_FILE="$OUT_DIR/device_info.txt"

mkdir -p "$OUT_DIR"

{
  echo "=== Android Device Info ==="
  echo

  echo "[Manufacturer]"
  adb shell getprop ro.product.manufacturer || true
  echo

  echo "[Model]"
  adb shell getprop ro.product.model || true
  echo

  echo "[Device]"
  adb shell getprop ro.product.device || true
  echo

  echo "[Android Release]"
  adb shell getprop ro.build.version.release || true
  echo

  echo "[SDK]"
  adb shell getprop ro.build.version.sdk || true
  echo

  echo "[Security Patch]"
  adb shell getprop ro.build.version.security_patch || true
  echo

  echo "[Build Fingerprint]"
  adb shell getprop ro.build.fingerprint || true
  echo

  echo "[Kernel]"
  adb shell uname -a || true
  echo

  echo "[SELinux]"
  adb shell getenforce || true
  echo

  echo "[ADB Devices]"
  adb devices || true
} | tee "$OUT_FILE"

echo
echo "Saved to: $OUT_FILE"
