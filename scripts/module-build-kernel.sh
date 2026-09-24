#!/bin/bash
# android_module_build 内核版（r760）：SELinux 子树编译验证。
# 引擎 verify() 以 cwd=迁移 worktree 调用。流程与 soong 版同构：
#   基线快照 → 5.10 内核真树临时 apply 候选补丁 → LLVM 编译 security/selinux
#   → built-in.a 拷回 worktree → EXIT trap 强制还原 + 四项验证
# 教训同 soong 版：不用 set -u；还原用 trap；编译输出缓存于 KOUT（首次配置慢，
# 预热后每个候选补丁只增量编译 selinux 对象，分钟级）。
WORKTREE="$(pwd)"
# 引擎布局 run_root/<CVE>/<仓库路径>，补丁在 CVE 目录。仓库路径段数不一
# （frameworks/base 两段、kernel 一段），固定层级推导会 overshoot——改为
# 向上搜索 backport.patch（最多 4 层），对任意仓库深度都正确。
RUN_DIR=""
for d in "$PWD" "$PWD/.." "$PWD/../.." "$PWD/../../.."; do
  [ -f "$d/backport.patch" ] && { RUN_DIR="$(cd "$d" && pwd)"; break; }
done
PATCH="$RUN_DIR/backport.patch"
KROOT=/data/junjie/kern510/kernel          # android12-5.10 目标内核仓（真树）
KOUT=/data/junjie/kern510-out              # 共享内核编译输出（缓存 .config 与对象）
CLANG=/data/junjie/aosp/prebuilts/clang/host/linux-x86/clang-r416183b
SNAP="$RUN_DIR/module-build-restore"

[ -f "$PATCH" ] || { echo "candidate patch not found: $PATCH" >&2; exit 121; }
[ -d "$KROOT" ] || { echo "kernel tree missing: $KROOT" >&2; exit 122; }
mkdir -p "$SNAP" "$KOUT" "$WORKTREE/out-artifacts"

snapshot() {
  cd "$KROOT" || return 1
  git rev-parse HEAD > "$SNAP/HEAD"
  git status --porcelain=v1 -z --untracked-files=all > "$SNAP/status-z"
  git ls-files -s | sha256sum > "$SNAP/lsfiles-sha"
}

restore() {
  echo "[kernel-build restore] 还原内核真树"
  cd "$KROOT" || return 1
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
  git status --porcelain=v1 -z --untracked-files=all > /tmp/.kb-status-now
  cmp -s /tmp/.kb-status-now "$SNAP/status-z" || { echo "VERIFY_FAIL: status 与基线不一致"; fail=1; }
  [ "$(git ls-files -s | sha256sum)" = "$(cat "$SNAP/lsfiles-sha")" ] || { echo "VERIFY_FAIL: 索引指纹不一致"; fail=1; }
  git diff --quiet HEAD || { echo "VERIFY_FAIL: diff HEAD 非空"; fail=1; }
  if [ "$fail" = 0 ]; then echo "RESTORE_VERIFIED_OK"; else echo "RESTORE_VERIFICATION_FAILED"; fi
  return "$fail"
}
trap 'restore' EXIT
trap 'restore; exit 130' INT TERM

snapshot || { echo "baseline snapshot failed" >&2; exit 123; }
if [ -s "$SNAP/status-z" ]; then
  echo "内核真树基线不干净，拒绝构建" >&2
  git -C "$KROOT" status --porcelain | head >&2
  exit 120
fi

cd "$KROOT" && git apply --binary "$PATCH" || {
  echo "candidate patch does not apply to the kernel tree" >&2
  exit 118
}
echo "[kernel-build] 补丁已临时应用，编译 security/selinux"

export PATH="$CLANG/bin:$PATH"
# 5.10 的 Makefile.clang 只有在给出 CROSS_COMPILE 时才会推导 --target，
# 仅 LLVM=1 会以宿主 x86_64 目标编译 arm64 代码（sp 寄存器/I 约束报错）；
# LLVM_IAS=1 用 clang 集成汇编器（本机无 GNU 交叉 as）。
MAKE="make -C $KROOT O=$KOUT ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu- -j32"
if [ ! -f "$KOUT/.config" ]; then
  $MAKE gki_defconfig || { echo "defconfig failed" >&2; exit 117; }
fi
$MAKE security/selinux/built-in.a
rc=$?
echo "MODULE_BUILD_EXIT=$rc"

if cp "$KOUT/security/selinux/built-in.a" "$WORKTREE/out-artifacts/" 2>/dev/null; then
  echo "artifact collected: built-in.a"
else
  echo "artifact missing after build: built-in.a" >&2
fi

exit "$rc"
