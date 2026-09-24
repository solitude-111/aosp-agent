#!/bin/bash
# android_module_build 验证阶段（r760 机器）。引擎 verify() 以 cwd=迁移 worktree 调用本脚本。
# 用法: module-build-r760.sh [soong 目标 ...]    默认目标: services FrameworksUiServicesTests
#
# 流程（2026-09-23 在 48550 上全链路验证过）:
#   基线快照 → 真树 frameworks/base 临时 apply 候选补丁 → 树外 OUT_DIR 增量编译
#   → 产物拷回 <worktree>/out-artifacts/（供引擎哈希）→ EXIT trap 强制还原 + 四项验证
#
# 固化的教训:
#   - 不用 set -u：envsetup.sh 引用未定义变量（TOP/ZSH_VERSION）会杀死 shell，
#     且 || 兜底分支不会执行；还原必须用 trap，不能用分支。
#   - 还原验证四项: HEAD / status 字节相等 / 索引指纹 / diff HEAD 为空。
WORKTREE="$(pwd)"
RUN_DIR="$(cd "$WORKTREE/../.." && pwd)"
PATCH="$RUN_DIR/backport.patch"
AOSP=/data/junjie/aosp
FB="$AOSP/frameworks/base"
OUT=/data/junjie/out-48550          # 共享增量产物（真树 sdk_phone_x86_64-userdebug 基线）
# 关键：envsetup/lunch/m 会把通用变量名 OUT 改写为 ANDROID_PRODUCT_OUT（实测
# OUT 变成 .../target/product/emulator_x86_64），必须在 source 之前固化产物根，
# 否则 find "$OUT/target/product" 永远指向不存在的嵌套路径，产物"失踪"。
PRODUCT_OUT_ROOT="$OUT/target/product"
SNAP="$RUN_DIR/module-build-restore"

if [ $# -eq 0 ]; then
  set -- services FrameworksUiServicesTests
fi

[ -f "$PATCH" ] || { echo "candidate patch not found: $PATCH" >&2; exit 121; }
[ -d "$FB" ] || { echo "frameworks/base missing: $FB" >&2; exit 122; }
mkdir -p "$SNAP" "$WORKTREE/out-artifacts"

snapshot() {
  cd "$FB" || return 1
  git rev-parse HEAD > "$SNAP/HEAD"
  git status --porcelain=v1 -z --untracked-files=all > "$SNAP/status-z"
  git ls-files -s | sha256sum > "$SNAP/lsfiles-sha"
}

restore() {
  echo "[module-build restore] 还原真树 frameworks/base"
  cd "$FB" || return 1
  git diff --name-only -z HEAD | xargs -0 -r -- git checkout --
  if ! git diff --cached --quiet; then
    git reset -q
    git diff --name-only -z HEAD | xargs -0 -r -- git checkout --
  fi
  git ls-files --others --exclude-standard -z | while IFS= read -r -d '' f; do
    echo "  rm: $f"; rm -f -- "$f"
  done
  fail=0
  [ "$(git rev-parse HEAD)" = "$(cat "$SNAP/HEAD")" ] || { echo "VERIFY_FAIL: HEAD 不一致"; fail=1; }
  git status --porcelain=v1 -z --untracked-files=all > /tmp/.mb-status-now
  cmp -s /tmp/.mb-status-now "$SNAP/status-z" || { echo "VERIFY_FAIL: status 与基线不一致"; fail=1; }
  [ "$(git ls-files -s | sha256sum)" = "$(cat "$SNAP/lsfiles-sha")" ] || { echo "VERIFY_FAIL: 索引指纹不一致"; fail=1; }
  git diff --quiet HEAD || { echo "VERIFY_FAIL: diff HEAD 非空"; fail=1; }
  if [ "$fail" = 0 ]; then echo "RESTORE_VERIFIED_OK"; else echo "RESTORE_VERIFICATION_FAILED"; fi
  return "$fail"
}
trap 'restore' EXIT
trap 'restore; exit 130' INT TERM

snapshot || { echo "baseline snapshot failed" >&2; exit 123; }
if [ -s "$SNAP/status-z" ]; then
  echo "真树基线不干净，拒绝构建" >&2
  git -C "$FB" status --porcelain | head >&2
  exit 120
fi

cd "$FB" && git apply --binary "$PATCH" || {
  echo "candidate patch does not apply to the real tree" >&2
  exit 118
}
echo "[module-build] 补丁已临时应用于真树，开始增量编译: $*"

export OUT_DIR="$OUT"
export TMPDIR=/data/junjie/out-48550-tmp
cd "$AOSP"
source build/envsetup.sh
lunch sdk_phone_x86_64-userdebug
m "$@"
rc=$?
echo "MODULE_BUILD_EXIT=$rc"

# 产物拷回 worktree（引擎对声明产物做存在性检查与哈希）
echo "[module-build] artifact search: PRODUCT_OUT_ROOT=$PRODUCT_OUT_ROOT exists=$([ -d "$PRODUCT_OUT_ROOT" ] && echo yes || echo no) args=$*" >&2
for t in "$@"; do
  if [ "$t" = "services" ]; then
    src=$(find "$PRODUCT_OUT_ROOT" -name "services.jar" 2>/dev/null | head -1)
  else
    src=$(find "$PRODUCT_OUT_ROOT" -name "$t.apk" 2>/dev/null | head -1)
  fi
  if [ -n "$src" ]; then
    cp "$src" "$WORKTREE/out-artifacts/" && echo "artifact collected: $(basename "$src")"
  else
    echo "artifact missing after build: $t" >&2
  fi
done

# 还原由 EXIT trap 统一执行；编译退出码即本阶段结果
exit "$rc"
