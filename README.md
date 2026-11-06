# AOSP Backport Agent

AOSP Backport Agent 是一个数据驱动的 Android 安全补丁回移系统。它以 donor 修复提交和固定版本的 Android 目标仓为输入，依次完成影响判断、补丁迁移、配置的检查、模块编译验证和补丁后业务影响评估，并输出可审计的补丁与完整运行证据。自动提取的 donor 符号仅用于调查提示，不作为修复正确性的验收条件。

当前模型执行层使用官方 OpenAI Codex Python SDK。GLM `glm-5.3`（ZAI provider）是历史使用配置；新的受控工具流程仍需在目标环境与实际 provider 上验收，本地 SDK 和脚本化服务测试不能代替这项验收。模型和认证由运行账户的 Codex 配置提供，仓库不包含任何 API key。

## 功能概览

### CVE 驱动的主流程

`aosp_agent run` 执行以下流程：

1. 读取案例 JSON 中的 donor 身份、真实父提交和目标基线，忽略历史 `files`、`validation` 与参考答案字段。
2. 从 donor 裸仓提取修复 diff，使用与 diff 入口相同的发现和映射核验，固定 `MappingPlan` 与自动验收计划。
3. 从核实的映射推导每个仓库的运行时 Case 和允许修改文件，创建隔离 detached worktree。
4. 各仓库接入原 run 后端的因果证据判断、机械迁移、策略阶梯与逐 hunk 账本；映射和答题使用独立 SDK 会话。
5. 审计每轮修改：HEAD、tracked/untracked 文件、路径 allowlist、符号链接、原始 checkout。
6. 导出候选补丁，并在新的干净 worktree 中独立重放。
7. `--verify` 执行控制器固定的验收计划；编译需要显式 `--build-runner` 且构建归属解析完整。冒烟单独通过不升级 `VALIDATED`。
8. 对最终候选做补丁后影响分析，记录兼容性、性能和测试建议；构建合格且当前候选复核为低风险才返回 `VALIDATED`，复核未完成或中高风险返回 `NEEDS_REVIEW`。
9. 生成 `run.json`、impact/post-fix 报告、候选补丁、最终补丁、验证输出和 SDK 事件留痕。

影响判断不是简单关键词匹配。系统会结合 donor diff、符号预扫、漏洞类别搜索策略和源码证据；当跨版本重构导致符号或关键词变化时，提示词要求模型沿行为等价路径继续定位目标实现。`AFFECTED` 结论必须提供可索引证据组成的因果链，覆盖 donor 父提交故障状态、donor 修复语义、目标等价故障和目标下游危害；仅凭历史注释、结构性相似或未核实的外部 API 假设不能通过。

### 证据核实与失败恢复

- 模型申报的文件、行号和摘录会与 Git blob 中的内容逐字核实。
- 未知、证据不足、空补丁、路径越界和验证失败均 fail-closed，不会默认视为成功。
- 新生产源码（含 donor 原生新增、已暂存的新增文件）必须提供目标端接入证据：当前支持
  基线已有函数中的调用（新增调用或改变其实际导入绑定）和 AndroidManifest 组件注册。生产门禁读取
  新增源码的实际声明，核对调用处的导入、包名及局部遮蔽；不能只凭文件名或同名标识符放行。
  注释、字符串、孤立 import、测试调用、
  新建孤立调用函数和 Soong 通配编译均不能满足此门禁。此检查是保守的结构证据，不能证明
  全程序或产品运行时可达性；尚不支持的反射、JNI 或动态注册需额外证据适配。
- 迁移阶段使用 T1–T6 六级策略阶梯，根据 apply、diff audit、验证和编译失败反馈自动重试。
- 诊断信息包含实际 argv、stdout/stderr、补丁重放结果和结构化失败原因。
- `VALIDATED` 要求本次候选的生产构建及还原凭据、所有已配置检查通过，以及绑定当前候选的完整低风险复核；不等价于完整设备安全证明。普通检查通过会保留 PASS，但缺少构建证据时总结果仍为 `PATCH_UNVERIFIED`。`build_validation`、`review_status`、`delivery_status` 分别记录构建、复核与交付准备结论。

### 其他工作流

- **diff 输入工作流**：`aosp_agent diff` 从一个独立 unified diff 发现目标仓库、判断影响并迁移，不要求预先编写 CVE 案例。
- **跨标签继承分析**：`aosp_agent inherit` 比较已验证补丁与两个标签间的差异，判断旧标签是否继承修复，并给出需要重跑的测试。
- **donor 历史加深**：`scripts/deepen_donor.sh` 由使用者手动执行，用于补齐 donor Git 对象；agent 自身禁用 Git 网络访问。

## 仓库内容

```text
aosp_agent/
  project_first.py     先分析选仓，再按证据扩仓的共同入口
  project_catalog.py   固定 manifest 的轻量项目目录
  runtime_input.py     四字段运行输入及来源序列契约
  runtime_batch.py     串行批次、资源预算与失败隔离
  engine.py            因果证据、迁移策略、逐 hunk 账本和验证后端
  diff_engine.py       共用发现/映射编排及无 donor 的受限流程
  mapping_plan.py      映射核验与不可变运行时范围
  mapped_run.py        案例身份输入适配，不采用预填目标文件
  mapped_backend.py    按仓接入原 run 后端与结果汇总
  validation_plan.py   可溯源的自动验收和显式 stage 覆盖
  build_discovery.py   保守的静态构建归属与未确定消费者
  build_metadata.py    按提交及解析策略复用固定构建元数据
  blueprint_literals.py / blueprint_glob.py 受限构建表达式与文件匹配
  build_transaction.py 受控构建契约、锁和精确恢复
  tool_broker.py       模型源码/文件工具的控制器代理
  lifecycle.py / resume.py 运行锁、恢复门禁与显式续跑
  output_budget.py / object_cache.py 受管输出和缓存额度
  delivery.py          构建、复核与交付状态分别判定
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
  dataset/cases-r760/   R760 使用的 16 个 Android 安全案例描述
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
- 模型认证配置。

示例构建脚本包含部署环境的路径和产品选择，使用前需按目标环境核对；这些示例不能当作新环境已通过资格验证的证明。完整验收范围和未完成项见 [验收矩阵](aosp_agent/ARCHITECTURE.md#验收范围与尚未完成的资格验证)。

## 安装

需要 Python 3.10+、Git，以及可访问目标源码和 donor 对象的运行环境。

```sh
git clone -b liujunjie/r760-glm https://github.com/solitude-111/aosp-agent.git
cd aosp-agent
python3 -m venv .venv-sdk
.venv-sdk/bin/python -m pip install -r aosp_agent/requirements-sdk.txt
```

模型认证必须配置在使用者的 `~/.codex/` 中，而不是提交到仓库。先按组织内部方式配置 ZAI / GLM provider，并确认 Codex runtime 能用该账户配置启动。CLI 参数 `--model` 和 `--model-provider` 只做单次覆盖；不传时会回落到用户 Codex 配置。

## 准备源码与 donor

案例 JSON 记录 `repository`、`source_commit`、`source_parent`、`target_commit` 等输入身份；`files` 和 `validation` 可省略，CLI 不再以它们作为出题依据。运行前需要准备：

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
  --build-runner /absolute/path/to/module-build-r760.sh \
  --verify --max-attempts 6 --turn-timeout 3600
```

需要保留独立人工验收时，使用 `--validation /path/to/overrides.json` 显式提供按仓库 key 分组的检查；旧 dataset 验收不会自动沿用。
`--mapping-model` 可单独指定只读出题会话的模型，默认继承 `--model`；答题会话无权改写映射和验收计划。
有核实 donor 的 run/diff 都接回原 run 后端；只有 diff 文本时保留受限源码证据流程，但同样执行映射区域账本检查。
多仓分别完成迁移和重试，失败不抹掉其他仓库的产物；尚无联合验证时，分别通过也只报告 `PATCH_UNVERIFIED`。

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

默认流程先分析补丁与轻量项目目录，只读取被选定的项目；需要其他项目时，通过带源码证据的请求扩展。`--repository frameworks/base` 可指定初始项目，重复传入可指定多个；旧全仓发现需显式 `--exhaustive-discovery`。`--inspect-only` 不调用模型，元数据不足以确定范围时返回 UNKNOWN 并要求指定项目，不隐式扫描全仓。`diff --target-revision TAG` 通过该版本的 repo manifest 固定目标项目版本，缺少标签或对象时停止，不能回退到当前 HEAD。

四字段 JSONL 输入示例：

```json
{"source_commit_sequence":["SOURCE_SHA"],"source_parent_sequence":["PARENT_SHA"],"donor_repositories":["https://android.googlesource.com/platform/frameworks/base"],"target_revision":"android-12.0.0_r1"}
```

SHA 占位符需替换成真实 Git 对象 ID。提交与父提交按位置配对；donor 列表是候选集合，不按位置与提交强行配对，不填目标文件或参考影响结论。

```sh
.venv-sdk/bin/python -m aosp_agent batch \
  --input /path/to/input.jsonl --target-root /path/to/aosp \
  --donor-root /path/to/donor-git --run-root /path/to/runs \
  --verify --build-runner /absolute/path/to/module-build-r760.sh
```

Android donor 默认使用 `<donor-root>/<去掉 platform/ 后斜杠换成连字符>.git`；可用 `--donor-map /path/to/map.json` 显式映射来源 URL 到本地 Git 仓库，其他域名必须显式映射。只读取本地对象，不自动下载。单来源保留既有 run 因果核验后端；多来源保留每步独立身份和依赖边，经完整映射与文本迁移执行，不丢弃后续提交。批次串行执行，重复行也独立留档，失败行不吞掉后续行。`batch-status.json` 中 COMPLETED 只表示所有行已终态，不代表所有行通过；查看 counts 和逐行 run.json。

调查默认总预算为 900 秒、2000 次控制器 Git / 工具操作、48 次模型调用、最多 12 个项目和 3 轮映射。分别用 `--investigation-seconds`、`--max-git-operations`、`--max-model-turns`、`--max-projects`、`--max-rounds` 调整。SDK 内部格式纠正也计入调用预算；生产模型通过控制器工具访问源码，不提供原生 shell。工具请求及其 Git 子查询分别计数，共用调查截止时间；编译验证使用独立的超时和清理流程。固定提交对象缓存可通过 `--cache-root` 指定，验证 PASS 不缓存。

所选仓库内部也按阶段定位：先读取直接路径及版本目录归一化候选；缺少完整 diff 侧文本线索时，再查询邻近目录，最后才扩大到仓库文件名或标识符搜索。同名但内容无关的文件会继续触发扩展。各阶段共享每来源单元、每仓库的候选文件读取上限。`location.json` 记录检索范围和 `DEFERRED`，表示尚未搜索；文本匹配不证明语义相同、依赖齐全或漏洞不存在。模型仍须查明调用方、其他实现和跨仓依赖，排除结论继续接受独立复核。

Ctrl-C 或 SIGTERM 会停止后续任务，并为验证子进程留出事务恢复时间。使用实际锁状态核对是否仍在运行；明确恢复会创建新尝试，保留旧记录，不沿用旧候选或旧 PASS：

```sh
.venv-sdk/bin/python -m aosp_agent status --record /path/to/task/run.json
.venv-sdk/bin/python -m aosp_agent resume --record /path/to/task/run.json
.venv-sdk/bin/python -m aosp_agent resume --record /path/to/batch/batch-status.json
```

恢复沿持久化的 `resumed_to` / `resumed_from` 关联查找最新执行，并持有途经记录的租约。最新执行已完成时拒绝重复恢复；缺失、循环或身份不一致的关联阻断恢复。新执行在启动前保存调用参数、固定目录及关联，支持创建后、运行前中断。恢复前必须通过输入校验和、原始源码基线和构建恢复检查；已有活进程、源码变化或 PENDING/FAIL 恢复回执都会阻止恢复。批次只继续取消中或未开始的行，已终态行保留原结果。崩溃后的恢复同样需要显式命令，不由旧状态文件自动重启。

可选地为 diff 接入本地 donor 历史（修复提交、直接父提交和输入 diff 必须一致）：

```sh
.venv-sdk/bin/python -m aosp_agent diff \
  --patch /path/to/fix.diff --target-root /path/to/target \
  --run-root /path/to/runs --donor-repo /path/to/donor.git \
  --source-commit FIX_SHA --source-parent PARENT_SHA
```

三个 donor 参数须一起提供。不提供时记录 `NOT_PROVIDED / diff_lines_only`；提供但缺对象、
父提交错误或 diff 不一致时停止，不静默退回文本模式。核实成功后可使用受控 `hunk-history`、
`show-commit`、`view-code` 工具。所有 Git 子进程通过空的 `GIT_ALLOW_PROTOCOL` 禁止传输，
即使旧 Git 忽略 `GIT_NO_LAZY_FETCH` 或仓库设置单独的协议许可，也不能隐式下载对象。

diff 在映射核实后、迁移前生成 `validation-plans/<仓库>/plan.json`：
自动词法提示仅从上游新增行抽取目标基线没有的符号，在 `provenance` 中保存 hunk、行号、原文和目标路径。
这些提示不生成验收命令：缺少同名符号不能否决等价改写，出现符号也不能提供验证通过信用。
显式配置的 `source_contract` 等检查仍须真实执行并通过；没有充分生产构建证据时仍报告 `PATCH_UNVERIFIED`。
Android.bp 支持有界的静态变量、列表/字符串/映射拼接、整数求和、引用前的本地 `+=`，
以及父目录变量继承；求值后的源码列表继续用于 glob 和 filegroup 归属查询。
变量不可重赋值，子文件不能修改继承变量；未定义变量、非法修改或超限不会导出部分结果。
条件源码、含源码的 defaults、namespace/include 解析、重名模块及未覆盖文件仍保留为 `UNRESOLVED`。
`build.metadata_inputs` 记录参与求值的固定版本配置文件摘要。
构建归属不等于产品可达性，不能替代运行时安全验证。

提供 `--build-runner /absolute/path/to/module-build-r760.sh` 后，仅在全部写入路径
都有明确构建归属时生成 `android_module_build` 检查。没有 runner 就不执行构建。
`--validation` 的 JSON 按仓库 key 提供检查，同名 stage 整体覆盖自动检查，其他 stage 合并；
仓库值为 `[]` 可关闭该仓库自动验收。`--no-auto-validation` 关闭全部自动生成，仍保留显式检查。
未传 `--verify` 时不执行任何验收命令。

run/diff 的验证器都会显式传入 `AOSP_AGENT_PATCH_FILE`、`PATCH_SHA256`、`TARGET_REPO`、
`TARGET_COMMIT`、`WORKTREE`、`RUN_DIR`（后五项同样带 `AOSP_AGENT_` 前缀）。
模块 runner 通过共用锁执行“核实干净基线 → 校验哈希和 HEAD → 应用 → 构建 → 精确恢复”。
恢复只处理补丁涉及的文件；意外改动被保留并使验证失败。超时先停止构建进程组并留出恢复时间，
恢复结果记录在仓库运行目录的 `module-build-restore/transaction.json`。

分析补丁是否可继承到旧标签：

```sh
.venv-sdk/bin/python -m aosp_agent \
  --dataset aosp_agent/dataset/cases-r760 \
  inherit CVE-2025-48550 \
  --source-root /path/to/repository \
  --fix-patch /path/to/run/CVE-2025-48550/backport.patch \
  --tag1 newer-validated-tag \
  --tag2 older-target-tag \
  --run-root /path/to/runs/inherit
```

跨标签分析在 `--run-root` 下创建独立目录并保存结果和事件日志，不在输入补丁旁写入。
默认输出根为当前目录下的 `runs/inherit`；直接 API 也可传入 `run_root`。
输出根位于原始源码树内（包括符号链接别名）时拒绝执行；从源码树内启动命令须显式指定外部输出根。

## 输出与状态

每个 run 目录通常包含：

```text
run.json                 完整状态机记录和验证证据
inspection.json          只读检查记录
impact.json              影响判断、根因分类和源码证据
diff-audit.json          每轮修改审计
candidate-N.patch        每轮候选补丁
backport.patch           最终导出补丁
new-file-audit-N.json    新增文件分类与既有目标代码接入证据
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
| `DISCOVERED` | 默认前端仅完成固定基线的候选发现，未调用模型 | 0 |
| `PREPARED` | 仅完成输入准备，未调用模型 | 0 |
| `NOT_AFFECTED` | 影响判断为不受影响且证据通过核实 | 0 |
| `ALREADY_FIXED` | 目标已包含等效修复 | 0 |
| `VALIDATED` | 当前候选的生产构建/还原及全部配置检查通过，且当前组合复核完整、各仓均为低风险 | 0 |
| `NEEDS_REVIEW` | 构建证据合格，但当前候选复核未完成、已过期或有中高风险 | 7 |
| `PATCH_UNVERIFIED` | 已生成候选，但验证未执行、未配置，或缺少所需生产构建覆盖 | 3 |
| `INCONCLUSIVE` | 证据不足，停止迁移 | 4 |
| `BLOCKED` | 源码树被占用或恢复前提未满足，后续行不启动 | 4 |
| `VALIDATION_FAILED` | 重试后仍未通过验证 | 5 |
| `FAILED` | 控制器、SDK、路径或证据错误 | 2 |

## 编译环境适配

`scripts/module-build-r760.sh` 和 `scripts/module-build-kernel.sh` 记录了当前 R760 验证环境的 AOSP、kernel、工具链和增量输出路径。这些路径是机器绑定配置；在其他机器复现编译验证前，需要按本机环境调整脚本顶部的源码、输出和工具链变量，并确认相应 Android/kernel 构建依赖可用。

未配置的验证阶段会在记录中显式标记为 `NOT_CONFIGURED`，不会被悄悄当作通过。

## 测试

```sh
.venv-sdk/bin/python -m unittest discover -s aosp_agent/tests -v
```

测试覆盖 Git 准备、离线部分克隆、donor 来源核实、diff 分解、路径审计、新文件接入门禁、证据核实、机械迁移、补丁重放、SDK 事件解析、策略阶梯、根因分类、继承分析和失败反馈。数量和跳过项以测试命令输出为准。

## 边界与安全原则

- 不构造、下载或执行 PoC。
- agent 的 Git 命令禁用网络协议和交互式提示。
- 候选补丁必须通过声明路径审计，新增文件也需核实接入；默认模型执行器使用命名权限配置限制原生工具的读写路径，并禁用外部工具入口。平台适配必须通过原生沙箱测试，不能静默退回全盘只读。
- 编译阶段必须先快照，退出时还原并验证目标真树。
- 运行时和设备验证尚未默认配置，`VALIDATED` 不声称运行时安全已被证明。
- 多仓任务按仓串行迁移；需要联合检查通过才能将整个补丁包判为已验证。

项目优先入口、旧 diff 初始化与执行、dataset 适配器及直接后端准备/执行/验证按真实源码范围持有租约；同一主机、同一 OS 用户下的协作任务不能通过更换输出目录、符号链接或选择父子源码目录绕过互斥。批次恢复会先持有旧子任务租约并核实恢复证据，活任务和恢复失败阻断整个批次。验证及受控构建进程继承源码租约，控制器退出后仍存活的构建进程继续占用它。此协调不约束绕过本系统的外部写入；原源码审计和构建事务仍然必需。

当前 checkout 模式读取选中的 manifest XML、include 和按文件名排序的 `local_manifests/*.xml`，保存元数据摘要，再按需固定项目 HEAD。指定 `--target-revision` 或 JSONL 发布版本时只使用该版本的 manifest，不混入本地覆盖。无法读取或支持的 manifest 明确失败，不静默丢弃项目。首次选仓的项目键及单元遗漏错误使用 `--max-attempts` 有限纠正，仍受总模型与调查预算限制；耗尽保持 UNKNOWN/INCONCLUSIVE，不退回全仓扫描。

任务/批次控制器输出默认共享累计 256 MiB 额度，可由 `--max-output-bytes` 配置。日志或记录超额会停止新工作，并保留最小阻断状态；进程清理和源码恢复不因普通输出额度耗尽而跳过。该额度不覆盖外部编译产物和候选工作树，详细范围见 [agent 文档](aosp_agent/README.md)。
