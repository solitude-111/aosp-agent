# AOSP agent 运行契约

`Case` 提供固定提交、仓库、允许编辑文件和控制器验证配置；`patches.py` 只分解补丁；`sdk_runtime.py` 只管理官方 SDK 会话；`engine.py` 负责证据核实、状态转换、Git 隔离、补丁导出与验证反馈。

```text
输入事实 → 固定提交/独立工作树 → donor hunk 文本检查
                              ↓
                       SDK 只读影响判断
                              ↓
                 Git 引用核实 ← 只读纠正
                       ↓            ↓
                   AFFECTED      UNKNOWN/NOT_AFFECTED 终止
                       ↓
                 SDK workspace_write 迁移
                       ↓
                路径/HEAD/原 checkout 审计
                       ↓
                 含新增文件的候选补丁
                       ↓
          独立干净 worktree 重放 + 分层验证 → 失败反馈修订
```

证据摘录必须是指定 Git 版本、文件和行范围中的连续真实片段。该检查不是语义正确性证明。只有 AFFECTED 才允许进入补丁阶段；原始 checkout 的 HEAD、状态和 tracked diff 摘要需保持不变。子会话 sandbox 限制工作目录写入，文件白名单由控制器在每次模型回合后审计，不能把事后审计宣传为操作系统级逐文件权限。

验证配置不作为参考答案注入初始模型 prompt。控制器只把实际失败输出回传。检查可声明验证阶段和预期产物，结果保存 argv、退出码、日志及产物哈希。新文件与已暂存修改均进入补丁；导出后在全新 target worktree 重放，空补丁不能算成功，验证不得悄悄修改被验证候选。没有检查或没有运行检查分别标明 NOT_CONFIGURED/NOT_REQUESTED。

多 Git 项目目前以单案例一个 repository 为执行单位，donor 可来自独立 bare store。跨仓库依赖与完整 repo manifest/Soong 构建仍需后续适配。当前没有通用 Android 设备 runner，也没有把历史人工构建产物绑定到新候选的流水线。

所有验证仅限防御性源码检查、正常功能测试和修复回归；不构造、下载或执行利用 PoC。运行结果准确报告实际覆盖范围，不从编译或文本可应用性推出产品安全结论。
