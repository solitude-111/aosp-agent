#!/bin/bash
# Same controller contract and transaction as the Android module runner.
set -o pipefail
KROOT=/data/junjie/kern510/kernel
KOUT=/data/junjie/kern510-out
CLANG=/data/junjie/aosp/prebuilts/clang/host/linux-x86/clang-r416183b
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
if [ "${1:-}" != "--build-only" ]; then
  export PYTHONPATH="$SCRIPT_DIR/..${PYTHONPATH:+:$PYTHONPATH}"
  exec "${AOSP_AGENT_PYTHON:-python3}" -m aosp_agent.build_transaction \
    --source-root "$KROOT" --lock /data/junjie/.module-build-r760.lock \
    -- "$SCRIPT_DIR/module-build-kernel.sh" --build-only "$@"
fi
shift
[ "${AOSP_AGENT_TRANSACTION_ACTIVE:-}" = 1 ] || { echo "build transaction required" >&2; exit 120; }
WORKTREE="$AOSP_AGENT_WORKTREE"
ARTIFACT_DIR="${AOSP_AGENT_ARTIFACT_DIR:-$WORKTREE/out-artifacts}"
mkdir -p "$KOUT" "$ARTIFACT_DIR" || exit 120
export PATH="$CLANG/bin:$PATH"
build=(make -C "$KROOT" "O=$KOUT" ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu- -j32)
if [ ! -f "$KOUT/.config" ]; then
  "${build[@]}" gki_defconfig || exit 117
fi
"${build[@]}" security/selinux/built-in.a
rc=$?
echo "MODULE_BUILD_EXIT=$rc"
[ "$rc" -eq 0 ] || exit "$rc"
cp -- "$KOUT/security/selinux/built-in.a" "$ARTIFACT_DIR/" || exit 125
exit 0
