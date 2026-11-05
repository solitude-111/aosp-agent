# AOSP Backport Agent

基于官方 Codex Python SDK 的 AOSP 影响判断与补丁迁移原型。借鉴 RetroPatch 的提交比较、hunk 分析、代码定位和验证反馈流程，当前首个真实案例为 CVE-2025-48550（Android 16 → 固定 Android 12）。

历史记录中的三个轻量 `frameworks/base` 案例为 CVE-2021-0799、CVE-2021-0927 和 CVE-2021-0970；此前的状态不能作为新映射/门禁实现的验证成绩。本轮按用户要求未重跑真实案例。

## 运行方式

在自己的项目虚拟环境安装固定依赖，SDK 自带匹配的 Codex runtime：

```sh
python3 -m venv .venv-sdk
.venv-sdk/bin/python -m pip install -r aosp_agent/requirements-sdk.txt
.venv-sdk/bin/python -m aosp_agent run CVE-2025-48550 \
  --source-root /home/guolei/aosp-agent-48550/source \
  --donor-root /home/guolei/aosp-agent-48550/donor-git \
  --run-root /home/guolei/aosp-agent-48550/runs/<新的实验名> \
  --model glm-5.3 --model-provider ZAI --verify --max-attempts 2
```

每次使用新的运行目录。`--inspect-only`（兼容名 `--no-codex`）只做固定提交的输入发现，不调用模型或创建迁移 worktree，返回 `DISCOVERED`。`--turn-timeout` 默认 900 秒。认证由运行账户的 Codex SDK 环境提供，不把凭据放入项目。

模型后端为 GLM（智谱）：`~/.codex/config.toml` 配置 ZAI provider（`glm-5.3`、`model_reasoning_effort`）与 `~/.codex/models.json` 模型目录，API key 写在 config.toml 的 `experimental_bearer_token`。agent 不指定 `--model`/`--model-provider`/effort 时全部回落到该配置；显式传参仅用于单次覆盖。

SDK 执行层为 `sdk_runtime.py`，使用 `AsyncCodex`、官方 streaming turn、明确 sandbox、结构化输出、超时中断和 JSONL 事件。它没有 Chat Completions 自动降级；旧 `direct_api.py` 仅保留历史代码，不由当前主流程调用。官方说明：[Codex SDK](https://learn.chatgpt.com/docs/codex-sdk)。

## 当前流程

1. 固定 donor 修复及其真实父提交；run/diff 共用只读发现和映射前端，生成不可变 MappingPlan 与运行时 Case，创建干净的目标 detached worktree。
2. 分解 donor hunk，用独立临时 Git index 检查文本可应用性，保留冲突信息。
3. SDK 以只读权限分析目标源码与相关 API，返回 AFFECTED、NOT_AFFECTED、ALREADY_FIXED 或 UNKNOWN 及源码证据。
4. 控制器检查引用的 Git blob、文件、行范围和连续摘录；`AFFECTED` 还必须索引覆盖 donor 故障、donor 修复、目标等价故障和目标危害的因果链证据。不一致时在同一线程请求只读纠正。
5. 仅 AFFECTED 进入迁移。SDK 在独立工作树修改允许文件；每回合后审计路径、HEAD、符号链接和原始 checkout。
6. 导出暂存、未暂存及新增测试文件，在新的干净 detached worktree 中独立重放补丁；执行控制器持有的分层验证命令并按失败反馈修订。
7. 多仓候选完成后，在同一组最终补丁上复核本地检查并执行联合检查。普通仓库失败不阻止其他仓库继续；联合失败使用相关仓库剩余的 `--max-attempts` 预算修复，仍保留完整逐 hunk 门禁。

迁移回合必须为输入的每个 donor hunk 提供恰好一条 `HUNK-RESULT` 声明。排除
hunk 不能只写“outside scope”，必须携带受控证据类别。该账本由控制器根据
donor diff 统一生成，不依赖按 CVE 手工配置的必需 hunk 白名单。
对于仅差一个显式版本目录的 donor 路径，控制器会在结果唯一命中目标 allowlist
时建立路径映射；多候选或无候选均按未映射处理。声明 implemented 的映射 hunk
必须在最终候选 diff 的对应目标文件中提供语义证据（归一化行或标识符重合），
不能只因为该文件发生了其他修改而通过。

大补丁另输出 `hunk-review-groups.json`：按 donor 文件分成最多8个 hunk 的阅读批次，保留所有原始 ID、补丁哈希和分类线索原文。权限、边界、锁等标签只是词法提示；测试、构建配置、文件操作和不支持的补丁也保留独立审查义务。版本复制判断不再删减模型收到的原始 diff；分组不改变逐 hunk 门禁。

`dataset/cases/` 提供提交身份和目标基线，CLI 忽略其中历史 `files`/`validation`。文件范围来自核实映射，冒烟检查来自 donor 新增行，构建目标来自固定目标树配置；独立人工验收需用 `--validation` 显式覆盖。`dataset/oracles/` 和历史人工补丁只供离线评价。源码引用检查不能自动证明模型推理正确或所有产品可达性。

## 状态与证据

| 状态 | 含义 | CLI 退出码 |
| --- | --- | --- |
| DISCOVERED | 仅完成固定基线的候选发现，模型未运行 | 0 |
| NOT_AFFECTED | 模型给出不受影响判断且引用通过核实，未迁移 | 0 |
| INCONCLUSIVE | 证据不足，停止迁移 | 4 |
| PATCH_UNVERIFIED | 未配置完整检查、仅冒烟通过，或缺少多仓联合验证 | 3 |
| VALIDATED | 当前候选通过所配置的检查，仅限其覆盖范围 | 0 |
| VALIDATION_FAILED | 验证重试耗尽，保留候选和失败证据 | 5 |
| MIGRATION_INCOMPLETE | 文本迁移的映射覆盖、逐 hunk 证据或新增文件接入未通过 | 6 |
| FAILED | SDK、证据、路径或执行错误 | 2 |

顶层产物包括 `run.json`、`mapping-plan.json`、`validation-plans/`、`patch-bundle.json` 和全任务 `hunk-ledger.json`。各仓库的运行时 Case、因果判断（有 donor 时）、逐 hunk 账本、候选补丁和验证输出位于 `repositories/<key>/`。

验证配置既可使用旧的 argv 列表，也可使用带 `stage` 和 `artifacts` 的 `checks` 对象。每个检查记录命令、退出码、日志、阶段和产物哈希；未配置的 JVM、模块构建、设备运行和 PoC 层明确保持 `NOT_CONFIGURED`/`NOT_RUN`。这些有限检查不能代替完整 Android 验证，`VALIDATED` 只表示当前配置覆盖范围内通过。

## 多仓联合验收

`run` 和 `diff` 均支持 `--joint-validation checks.json`。文件包含固定 argv 检查列表（格式同单仓 checks），命令工作目录为组合后的 `workspace/`；仓库路径仍以各自 key 为前缀。显式联合检查声明覆盖整组候选，因此应选择确实检查组合行为的回归脚本。`source_contract` 单独通过不能升级为 `VALIDATED`。不传 `--verify` 时不执行这些命令。

多仓的 `android_module_build` 自动延后到联合阶段。相同显式 `--build-runner` 的字面量模块名取并集后执行；其他命令独立执行。`--joint-validation` 按 stage 覆盖自动联合检查，显式空列表禁用自动联合检查。缺少完整联合覆盖时，多仓结果最多为 `PATCH_UNVERIFIED`。

联合构建传入 `AOSP_AGENT_PATCH_BUNDLE`、`AOSP_AGENT_BUNDLE_SHA256`、`AOSP_AGENT_WORKTREE`、`AOSP_AGENT_RUN_DIR` 和每次调用唯一的 `AOSP_AGENT_VALIDATION_ID`。runner 应调用 `aosp_agent.build_transaction`：在同一锁内预检每个补丁和只读依赖，再临时同时应用全部补丁、构建、逐仓恢复，输出本次 bundle 的恢复回执。返回 0 但缺少新鲜回执的构建不会通过。任一恢复状态异常会失败并保留意外改动。

联合构建产物写入 `AOSP_AGENT_ARTIFACT_DIR`，即运行目录的 `joint-artifacts/`；配置中的产物路径也使用这个前缀。每次检查前归档旧产物，防止上一轮文件充当本轮输出。固定计划、最终补丁集合及联合检查记录分别保存在 `joint-validation-plan.json`、`joint-patch-bundle.json`、`joint-verification.json`。本地验收缓存绑定整组补丁哈希，依赖仓库变化后必须重新检查。

## 开发测试

```sh
.venv-sdk/bin/python -m unittest discover -s aosp_agent/tests -v
```

测试包含临时真实 Git 仓库、补丁重新应用、验证失败修订、证据拒绝和 SDK 事件处理。多数模型回合使用替身，必须与真实模型运行证据分开。历史人工 Android 验证见 `experiments/CVE-2025-48550`，验收边界见 `docs/aosp-agent-acceptance.md`。
