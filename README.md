# AOSP Backport Agent

AOSP Backport Agent 是一个数据驱动的 Android 安全补丁回移系统。它以 donor 修复提交和固定版本的 Android 目标仓为输入，依次完成影响判断、补丁迁移、源码契约检查、模块编译验证和补丁后业务影响评估，并输出可审计的补丁与完整运行证据。

当前模型执行层使用官方 OpenAI Codex Python SDK。已验证的后端配置为 GLM `glm-5.3`（ZAI provider）；模型和认证由运行账户的 Codex 配置提供，仓库不包含任何 API key。

## 功能概览

### CVE 驱动的主流程

`aosp_agent run` 执行以下流程：

1. 读取案例 JSON，固定 donor 修复提交、父提交、目标提交、允许修改文件和验证命令。
2. 从 donor 裸仓提取修复 diff，做 hunk 分解、donor diff 预处理和安全变更分类。
3. 为目标提交创建隔离 detached worktree，避免直接修改原始 checkout。
4. 先尝试机械 hunk 迁移，再让模型在允许文件范围内完成跨版本适配。
5. 审计每轮修改：HEAD、tracked/untracked 文件、路径 allowlist、符号链接、原始 checkout。
6. 导出候选补丁，并在新的干净 worktree 中独立重放。
7. 按案例执行源码契约检查；配置 `--verify` 时执行编译验证。
8. 对 `VALIDATED` 补丁做补丁后影响分析，记录兼容性、性能和测试建议。
9. 生成 `run.json`、impact/post-fix 报告、候选补丁、最终补丁、验证输出和 SDK 事件留痕。

影响判断不是简单关键词匹配。系统会结合 donor diff、符号预扫、漏洞类别搜索策略和源码证据；当跨版本重构导致符号或关键词变化时，提示词要求模型沿行为等价路径继续定位目标实现。

### 证据核实与失败恢复

- 模型申报的文件、行号和摘录会与 Git blob 中的内容逐字核实。
- 未知、证据不足、空补丁、路径越界和验证失败均 fail-closed，不会默认视为成功。
- 迁移阶段使用 T1–T6 六级策略阶梯，根据 apply、diff audit、验证和编译失败反馈自动重试。
- 诊断信息包含实际 argv、stdout/stderr、补丁重放结果和结构化失败原因。
- `VALIDATED` 只表示通过当前案例配置的验证范围，不自动等价于完整设备安全证明。

### 其他工作流

- **diff 输入工作流**：`aosp_agent diff` 从一个独立 unified diff 发现目标仓库、判断影响并迁移，不要求预先编写 CVE 案例。
- **跨标签继承分析**：`aosp_agent inherit` 比较已验证补丁与两个标签间的差异，判断旧标签是否继承修复，并给出需要重跑的测试。
- **donor 历史加深**：`scripts/deepen_donor.sh` 由使用者手动执行，用于补齐 donor Git 对象；agent 自身禁用 Git 网络访问。

## 仓库内容

```text
aosp_agent/
  engine.py             CVE 主工作流和状态机
  diff_engine.py        仅从 diff 输入的发现/评估/迁移工作流
  diff_analysis.py      donor diff 预处理与漏洞类别推断
  sdk_runtime.py        官方 Codex SDK streaming 运行时
  prompts.py            影响判断、迁移、补丁后影响和继承分析提示词
  agent_tools.py        受控只读代码工具
  symbols.py            donor 符号预扫和近似定位
  patches.py            unified diff/hunk 分解
  patch_repair.py       机械 hunk 修复
  diagnosis.py          apply/验证失败诊断
  ladder.py             T1–T6 策略阶梯
  inherit.py            跨标签继承分析
  case.py               案例输入契约和路径安全校验
  dataset/cases/        原始轻量案例
  dataset/cases-r760/   R760 使用的 13 个 Android 安全案例描述
  tests/                单元测试（真实临时 Git 仓 + mock runtime）
scripts/
  deepen_donor.sh       手动 donor 历史加深
  module-build-r760.sh  Android 模块编译验证
  module-build-kernel.sh Linux kernel 模块编译验证
  r760-build-module.sh  兼容包装脚本
```

仓库包含 agent 源码、测试、案例输入契约和验证脚本。它不包含：

- API key、token 或其他凭据；
- AOSP / kernel 源码树；
- donor Git 对象和完整 Git 历史；
- run 输出、最终补丁、验证日志或编译产物；
- Python 虚拟环境和缓存；
- 私有服务器配置。

## 安装

需要 Python 3.11+、Git，以及可访问目标源码和 donor 对象的运行环境。

```sh
git clone -b liujunjie/r760-glm https://github.com/solitude-111/aosp-agent.git
cd aosp-agent
python3 -m venv .venv-sdk
.venv-sdk/bin/python -m pip install -r aosp_agent/requirements-sdk.txt
```

模型认证必须配置在使用者的 `~/.codex/` 中，而不是提交到仓库。先按组织内部方式配置 ZAI / GLM provider，并确认 Codex runtime 能用该账户配置启动。CLI 参数 `--model` 和 `--model-provider` 只做单次覆盖；不传时会回落到用户 Codex 配置。

## 准备源码与 donor

每个案例 JSON 记录了 `repository`、`source_commit`、`source_parent`、`target_commit` 和允许修改的文件。运行前需要准备：

1. **目标源码根**：`--source-root` 指向包含案例仓库的 AOSP 或多仓源码根，目标仓库中必须已有目标提交对象，原始 checkout 应保持干净。
2. **donor 裸仓根**：`--donor-root` 指向包含 donor 裸仓的目录。命名规则是把仓库路径中的 `/` 替换为 `-` 并加 `.git`，例如 `frameworks/base` 对应 `frameworks-base.git`。
3. **完整 donor 对象**：裸仓必须包含修复提交、真实父提交以及相关 tree/blob 历史。若历史不足，由使用者手动运行 `scripts/deepen_donor.sh` 补齐。

agent 会在 `--run-root` 下创建隔离 worktree。编译脚本会在受控流程中临时应用补丁、编译并在退出时还原目标真树，同时做 HEAD/status/index/diff 四项还原验证。

## 运行

列出 R760 案例：

```sh
.venv-sdk/bin/python -m aosp_agent \
  --dataset aosp_agent/dataset/cases-r760 list
```

运行一个案例：

```sh
.venv-sdk/bin/python -m aosp_agent \
  --dataset aosp_agent/dataset/cases-r760 \
  run CVE-2025-48550 \
  --source-root /path/to/aosp \
  --donor-root /path/to/donor-git \
  --run-root /path/to/runs \
  --verify --max-attempts 6 --turn-timeout 3600
```

只准备和检查输入，不调用模型：

```sh
.venv-sdk/bin/python -m aosp_agent run CVE-2025-48550 \
  --source-root /path/to/aosp \
  --donor-root /path/to/donor-git \
  --run-root /path/to/runs \
  --no-codex
```

从独立 diff 运行：

```sh
.venv-sdk/bin/python -m aosp_agent diff \
  --patch /path/to/fix.diff \
  --target-root /path/to/target-git-or-aosp \
  --run-root /path/to/runs \
  --verify
```

分析补丁是否可继承到旧标签：

```sh
.venv-sdk/bin/python -m aosp_agent \
  --dataset aosp_agent/dataset/cases-r760 \
  inherit CVE-2025-48550 \
  --source-root /path/to/repository \
  --fix-patch /path/to/run/CVE-2025-48550/backport.patch \
  --tag1 newer-validated-tag \
  --tag2 older-target-tag
```

## 输出与状态

每个 run 目录通常包含：

```text
run.json                 完整状态机记录和验证证据
inspection.json          只读检查记录
impact.json              影响判断、根因分类和源码证据
diff-audit.json          每轮修改审计
candidate-N.patch        每轮候选补丁
backport.patch           最终导出补丁
verification.json        分层验证结果
post-fix-impact.json     补丁后业务影响评估
sdk-events.jsonl         SDK streaming 事件
tool-usage.jsonl         受控工具调用留痕
validation-*.stdout/stderr 验证原始输出
module-build-restore/    编译前快照与还原证据
out-artifacts/           编译产物哈希输入
```

主要状态：

| 状态 | 含义 | 退出码 |
| --- | --- | ---: |
| `PREPARED` | 仅完成输入准备，未调用模型 | 0 |
| `NOT_AFFECTED` | 影响判断为不受影响且证据通过核实 | 0 |
| `ALREADY_FIXED` | 目标已包含等效修复 | 0 |
| `VALIDATED` | 候选补丁通过当前配置的验证 | 0 |
| `PATCH_UNVERIFIED` | 已生成候选，但验证未配置或未执行 | 3 |
| `INCONCLUSIVE` | 证据不足，停止迁移 | 4 |
| `VALIDATION_FAILED` | 重试后仍未通过验证 | 5 |
| `FAILED` | 控制器、SDK、路径或证据错误 | 2 |

## 编译环境适配

`scripts/module-build-r760.sh` 和 `scripts/module-build-kernel.sh` 记录了当前 R760 验证环境的 AOSP、kernel、工具链和增量输出路径。这些路径是机器绑定配置；在其他机器复现编译验证前，需要按本机环境调整脚本顶部的源码、输出和工具链变量，并确认相应 Android/kernel 构建依赖可用。

未配置的验证阶段会在记录中显式标记为 `NOT_CONFIGURED`，不会被悄悄当作通过。

## 测试

```sh
.venv-sdk/bin/python -m unittest discover -s aosp_agent/tests -v
```

当前推送分支包含 147 项测试（1 项按条件跳过），覆盖 Git 准备、diff 分解、路径审计、证据核实、机械迁移、补丁重放、SDK 事件解析、策略阶梯、根因分类、继承分析和失败反馈。

## 边界与安全原则

- 不构造、下载或执行 PoC。
- agent 的 Git 命令禁用网络协议和交互式提示。
- 模型只能修改案例声明的安全路径；新增文件也会进入审计。
- 编译阶段必须先快照，退出时还原并验证目标真树。
- 运行时和设备验证尚未默认配置，`VALIDATED` 不声称运行时安全已被证明。
- 多仓案例可以声明 manifest，但当前主流程不编排多个仓库同时迁移。
