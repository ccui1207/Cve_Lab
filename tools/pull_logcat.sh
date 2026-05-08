#!/usr/bin/env bash

set -e

OUT_DIR=${1:-"./logs"}
OUT_FILE="$OUT_DIR/logcat_$(date +%Y%m%d_%H%M%S).txt"

mkdir -p "$OUT_DIR"

echo "Clearing old logcat..."
adb logcat -c

echo "Start collecting logcat."
echo "Press Ctrl+C to stop."
adb logcat | tee "$OUT_FILE"
