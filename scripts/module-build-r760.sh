#!/bin/bash
# The controller supplies the exact patch, target repository, HEAD and digest.
# --build-only is called by build_transaction after the patch has been applied.
set -o pipefail
AOSP=/data/junjie/aosp
OUT=/data/junjie/out-48550
PRODUCT_OUT_ROOT="$OUT/target/product"
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
if [ "${1:-}" != "--build-only" ]; then
  export PYTHONPATH="$SCRIPT_DIR/..${PYTHONPATH:+:$PYTHONPATH}"
  exec "${AOSP_AGENT_PYTHON:-python3}" -m aosp_agent.build_transaction \
    --source-root "$AOSP" --lock /data/junjie/.module-build-r760.lock \
    -- "$SCRIPT_DIR/module-build-r760.sh" --build-only "$@"
fi
shift
[ "${AOSP_AGENT_TRANSACTION_ACTIVE:-}" = 1 ] || { echo "build transaction required" >&2; exit 120; }
[ "$#" -gt 0 ] || { echo "explicit build modules required" >&2; exit 120; }
WORKTREE="$AOSP_AGENT_WORKTREE"
mkdir -p "$WORKTREE/out-artifacts" || exit 120
export OUT_DIR="$OUT"
export TMPDIR=/data/junjie/out-48550-tmp
cd "$AOSP" || exit 120
source build/envsetup.sh || exit 117
lunch sdk_phone_x86_64-userdebug || exit 117
m "$@"
rc=$?
echo "MODULE_BUILD_EXIT=$rc"
[ "$rc" -eq 0 ] || exit "$rc"
for t in "$@"; do
  src=""
  if [ "$t" = services ]; then
    src=$(find "$PRODUCT_OUT_ROOT" -name services.jar -type f -print -quit)
  else
    for pat in "$t.apk" "$t.jar" "lib$t.so" "$t.so" "$t"; do
      src=$(find "$PRODUCT_OUT_ROOT" -name "$pat" -type f -print -quit)
      [ -n "$src" ] && break
    done
  fi
  if [ -n "$src" ]; then
    cp -- "$src" "$WORKTREE/out-artifacts/" || exit 125
    echo "artifact collected: $(basename "$src")"
  else
    echo "artifact not found for module: $t" >&2
  fi
done
exit 0
