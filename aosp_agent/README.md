# AOSP Backport Agent

基于官方 Codex Python SDK 的 AOSP 影响判断与补丁迁移原型。借鉴 RetroPatch 的提交比较、hunk 分析、代码定位和验证反馈流程，当前首个真实案例为 CVE-2025-48550（Android 16 → 固定 Android 12）。

另外三个轻量 `frameworks/base` 案例已完成真实 SDK 回移并标记为 `VALIDATED`：CVE-2021-0799、CVE-2021-0927 和 CVE-2021-0970。它们均只修改一个生产文件，验证覆盖源码级检查（0799 另有普通 JVM key 语义测试）；Android 全量模块、设备运行和 PoC 仍按案例记录的范围区分。

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

每次使用新的运行目录。`--inspect-only`（兼容名 `--no-codex`）只做 Git 准备与 hunk 检查，不调用模型。`--turn-timeout` 默认 900 秒。认证由运行账户的 Codex SDK 环境提供，不把凭据放入项目。33 机器现有 Codex 程序和配置仍受用户“不操作”的约束，私有 SDK 依赖与实际认证需先确认。

模型后端为 GLM（智谱）：`~/.codex/config.toml` 配置 ZAI provider（`glm-5.3`、`model_reasoning_effort`）与 `~/.codex/models.json` 模型目录，API key 写在 config.toml 的 `experimental_bearer_token`。agent 不指定 `--model`/`--model-provider`/effort 时全部回落到该配置；显式传参仅用于单次覆盖。

SDK 执行层为 `sdk_runtime.py`，使用 `AsyncCodex`、官方 streaming turn、明确 sandbox、结构化输出、超时中断和 JSONL 事件。它没有 Chat Completions 自动降级；旧 `direct_api.py` 仅保留历史代码，不由当前主流程调用。官方说明：[Codex SDK](https://learn.chatgpt.com/docs/codex-sdk)。

## 当前流程

1. 固定 donor 修复及其真实父提交，创建干净的 Android 12 detached worktree。
2. 分解 donor hunk，用独立临时 Git index 检查文本可应用性，保留冲突信息。
3. SDK 以只读权限分析目标源码与相关 API，返回 AFFECTED、NOT_AFFECTED、ALREADY_FIXED 或 UNKNOWN 及源码证据。
4. 控制器检查引用的 Git blob、文件、行范围和连续摘录；不一致时在同一线程请求只读纠正。
5. 仅 AFFECTED 进入迁移。SDK 在独立工作树修改允许文件；每回合后审计路径、HEAD、符号链接和原始 checkout。
6. 导出暂存、未暂存及新增测试文件，在新的干净 detached worktree 中独立重放补丁；执行控制器持有的分层验证命令并按失败反馈修订。

`dataset/cases/` 是运行事实；`dataset/oracles/` 和历史人工补丁只供离线评价。模型输入不包含参考影响结论、迁移方案或验证实现。源码引用检查能证明引用真实，不能自动证明模型推理正确或所有产品可达性。

## 状态与证据

| 状态 | 含义 | CLI 退出码 |
| --- | --- | --- |
| PREPARED | 仅完成准备，模型未运行 | 0 |
| NOT_AFFECTED | 模型给出不受影响判断且引用通过核实，未迁移 | 0 |
| INCONCLUSIVE | 证据不足，停止迁移 | 4 |
| PATCH_UNVERIFIED | 已生成候选，但未请求或未配置验证 | 3 |
| VALIDATED | 当前候选通过所配置的检查，仅限其覆盖范围 | 0 |
| VALIDATION_FAILED | 验证重试耗尽，保留候选和失败证据 | 5 |
| FAILED | SDK、证据、路径或执行错误 | 2 |

主要产物：`run.json`、`sdk-events.jsonl`、`inspection.json`、`impact.json`、`diff-audit.json`、逐次 `candidate-N.patch`、最终 `backport.patch`、`verification.json` 和验证原始输出。

验证配置既可使用旧的 argv 列表，也可使用带 `stage` 和 `artifacts` 的 `checks` 对象。每个检查记录命令、退出码、日志、阶段和产物哈希；未配置的 JVM、模块构建、设备运行和 PoC 层明确保持 `NOT_CONFIGURED`/`NOT_RUN`。这些有限检查不能代替完整 Android 验证，`VALIDATED` 只表示当前配置覆盖范围内通过。

## 开发测试

```sh
.venv-sdk/bin/python -m unittest discover -s aosp_agent/tests -v
```

测试包含临时真实 Git 仓库、补丁重新应用、验证失败修订、证据拒绝和 SDK 事件处理。多数模型回合使用替身，必须与真实模型运行证据分开。历史人工 Android 验证见 `experiments/CVE-2025-48550`，验收边界见 `docs/aosp-agent-acceptance.md`。
