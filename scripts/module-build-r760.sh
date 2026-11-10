#!/bin/bash
# The controller supplies the exact patch, target repository, HEAD and digest.
# --build-only is called by build_transaction after the patch has been applied.
set -o pipefail
# The server's controlled build profile supplies these paths. They must refer
# to the private prepared view; no host-specific source/output defaults exist.
AOSP="${AOSP_AGENT_SOURCE_ROOT:?configured isolated source root required}"
OUT="${AOSP_AGENT_OUT_DIR:?configured isolated output root required}"
BUILD_TMP="${AOSP_AGENT_TMPDIR:?configured build temporary directory required}"
LUNCH_TARGET="${AOSP_AGENT_LUNCH:?configured product and variant required}"
BUILD_LOCK="${AOSP_AGENT_BUILD_LOCK:?configured build lock required}"
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
if [ "${1:-}" != "--build-only" ] && [ "${1:-}" != "--baseline" ]; then
  export PYTHONPATH="$SCRIPT_DIR/..${PYTHONPATH:+:$PYTHONPATH}"
  exec "${AOSP_AGENT_PYTHON:-python3}" -m aosp_agent.build_transaction \
    --source-root "$AOSP" --lock "$BUILD_LOCK" \
    -- "$SCRIPT_DIR/module-build-r760.sh" --build-only "$@"
fi
mode="$1"
shift
if [ "$mode" = "--baseline" ]; then
  [ "${AOSP_AGENT_BASELINE_ACTIVE:-}" = 1 ] || { echo "baseline controller contract required" >&2; exit 120; }
else
  [ "${AOSP_AGENT_TRANSACTION_ACTIVE:-}" = 1 ] || { echo "build transaction required" >&2; exit 120; }
fi
[ "$#" -gt 0 ] || { echo "explicit build modules required" >&2; exit 120; }
WORKTREE="$AOSP_AGENT_WORKTREE"
ARTIFACT_DIR="${AOSP_AGENT_ARTIFACT_DIR:-$WORKTREE/out-artifacts}"
mkdir -p "$ARTIFACT_DIR" || exit 120
export OUT_DIR="$OUT"
export TMPDIR="$BUILD_TMP"
mkdir -p "$OUT" "$TMPDIR" || exit 120
cd "$AOSP" || exit 120
source build/envsetup.sh || exit 117
lunch "$LUNCH_TARGET" || exit 117
if [ -n "${AOSP_AGENT_EXPECTED_ARCH:-}" ]; then
  actual_arch="$(get_build_var TARGET_ARCH)" || exit 117
  if [ "$actual_arch" != "$AOSP_AGENT_EXPECTED_ARCH" ]; then
    echo "configured architecture differs from lunch target: $actual_arch" >&2
    exit 117
  fi
fi
m "$@"
rc=$?
echo "MODULE_BUILD_EXIT=$rc"
[ "$rc" -eq 0 ] || exit "$rc"
[ "$mode" != "--baseline" ] || exit 0
PRODUCT_OUT_ROOT="$(get_build_var PRODUCT_OUT)" || exit 117
[[ "$PRODUCT_OUT_ROOT" = /* ]] || PRODUCT_OUT_ROOT="$AOSP/$PRODUCT_OUT_ROOT"
PRODUCT_OUT_ROOT="$(cd -- "$PRODUCT_OUT_ROOT" && pwd -P)" || exit 125
OUT_CANONICAL="$(cd -- "$OUT" && pwd -P)" || exit 125
[[ "$PRODUCT_OUT_ROOT" = "$OUT_CANONICAL"/* ]] || { echo "product output escapes controlled output view" >&2; exit 125; }
for t in "$@"; do
  src=""
  for pat in "$t.apk" "$t.jar" "lib$t.so" "$t.so" "$t"; do
    src=$(find "$PRODUCT_OUT_ROOT" -name "$pat" -type f -print -quit)
    [ -n "$src" ] && break
  done
  if [ -n "$src" ]; then
    cp -- "$src" "$ARTIFACT_DIR/" || exit 125
    echo "artifact collected: $(basename "$src")"
  else
    echo "artifact not found for module: $t" >&2
  fi
done
exit 0
