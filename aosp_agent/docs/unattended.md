# 无人值守运行

`run-patches` 接收一次四字段 JSONL 和一份服务器配置，使用现有 project-first 流程逐案执行。环境准备、预算、候选、验证和恢复记录仍保存在同一批次目录中。阶段 5 的完整 20 案正式验收由使用者另行执行，本轮不执行；这里的使用说明和本地测试不表示正式验收已经通过。

## 环境和配置

需要 Linux、Git、Python 运行环境，以及支持 user namespace、mount namespace 和 OverlayFS 的主机。入口通过 `unshare` 创建私有挂载命名空间；源码、构建输出和临时目录使用独立持久 upper。无法建立或核实隔离时明确阻塞，不回退到修改共享 checkout。目录必须互不覆盖，尤其不能把缓存或隔离层放入源码、构建输出目录。

复制 [server.example.json](server.example.json)，将路径和模型提供方改为本机配置。示例不包含真实账号、凭据或案例答案，默认关闭编译。运行账号需要事先完成模型认证。`credential_reference` 只记录环境或既有 Codex 配置的引用名称，不会替你创建或导入凭据；不要将密钥写入 JSON、JSONL 或仓库。

`source_root` 是已有 AOSP 源码输入；`donor_root` 是已有 donor 对象来源；`cache_root` 保存控制器允许获取的对象；`isolation_root` 保存每案隔离层；`run_root` 保存启动器和批次证据。缺失对象只能由准备控制器从 `allowed_upstreams` 获取，模型工具仍然离线。`donor_map` 可以配置来源到本地对象目录的映射，但不能配置每案目标仓库、文件或模块。

```sh
export AOSP_AGENT_SERVER_CONFIG=/absolute/path/server.json
export AOSP_AGENT_PYTHON=/absolute/path/aosp-agent/.venv-sdk/bin/python
./run-patches --print-config
```

`--print-config` 校验并显示有效配置，不调用模型、不启动编译，也不证明服务器隔离或源码完整性已经通过。也可以每次传入 `--config /absolute/path/server.json`。入口暴露的模型、预算和目录参数可以覆盖配置；实际配置及其哈希会保存到新启动目录的 `effective-config.json`。

## 当前源码准备边界

主流程直接使用 `source_root` 指向的已有源码，在私有 namespace 中建立每案修改层及输出层。fs-verity、SquashFS、loop 均不是自动入口的前置条件；当前服务器配置没有启用 `source_base`。历史实现与登记说明移至 [底座实验归档](source-base-experiment.md)，不作为本轮操作步骤。

**跨任务源码准备结果复用目前没有生效。** 已有对象会优先使用，只有缺失对象才获取、只有提交不同才切换，但每个新案例仍从空的 `materialized` 集合开始。构建时 `materialize_all()` 会检查完整目标向量；这不能描述为已经实现“仅处理变化仓库”。

可以复用与不能复用的证据必须分开：

- 固定 manifest 和项目提交向量可在同一批次恢复时复用；新的独立批次仍会重新冻结引用。它们证明目标版本，不能证明磁盘工作区未变化。
- 对象缓存保存已有对象；使用某个目标快照时仍须检查需要的 commit/tree/blob 是否完整。缺失对象只补对应仓库。
- 同一个仍活动、已完整准备的父视图可供新派生视图继承。派生视图只准备提交发生变化的仓库，使用新的修改层、输出层；父视图身份和完整准备依据不足时明确阻塞。
- 跨任务的旧准备收据不能直接证明普通可写源码目录未变化。当前没有外部修改记录；HEAD、索引或顶层目录时间戳也不能排除深层源码文件被改动。此缺口尚未解决，不能用一个已验证标记跳过检查。

当前构建前后的完整源码审计仍保留；减少派生视图的重复准备不等于取消全仓审计。上述限制未解决前，不启动要求跨任务免全量检查的真实案例，也不自动退回完整重跑。

runner 脚本字节、输出路径和构建参数属于构建证据。它们改变时需重新验证构建缓存；脚本内容变化本身不表示源码变化。不过现有配置恢复仍按整份配置校验，输出路径等配置变化会阻止旧任务直接恢复。这与源码证据如何复用是两件未完全解耦的事，不能修改旧记录强行续跑。

## 输入和执行

每行恰好包含四个字段。以下 SHA 是格式占位符，执行前必须替换为真实提交及其父提交：

```json
{"source_commit_sequence":["1111111111111111111111111111111111111111"],"source_parent_sequence":["2222222222222222222222222222222222222222"],"donor_repositories":["https://android.googlesource.com/platform/frameworks/base"],"target_revision":"android-12.0.0_r1"}
```

`target_revision` 指向 manifest 的 tag、branch 或 commit，不是某个目标仓库的 SHA。准备阶段将完整项目清单固定为不可变提交向量；执行过程中不重新解析移动分支。输入不能额外加入 CVE、目标仓库、目标文件、模块或参考补丁答案。

项目清单中的可变 branch/tag 优先从对应 checkout 读取本地快照。项目路径及 `.git`、`commondir` 和实际配置文件必须位于 `source_root` 内；本地任意 remote 名称的 HTTPS URL 还须与 manifest 项目来源匹配，比较时归一化末尾 `.git`。控制器先精确枚举 branch/tag 名称，再解引用 tag；同名歧义直接拒绝，不能忽略坏 ref 后选择另一个。所有本地 Git 命令禁止网络和惰性对象获取，每条最多 3 秒、stdout/stderr 合计 64 KiB。

本地来源不可信、ref 缺失或无法可靠解析时，才从允许的 HTTPS 上游精确查询 `git ls-remote` 广告，单次最多 30 秒、64 KiB。记录注明本地来源或远程广告、完整 ref、OID 和观测时间；本地结果是冻结时看到的本地快照，不承诺上游最新。两种路径都不导入未选中目标项目的对象，也不证明 OID 是 commit 或 tree/blob 已齐备；选择该项目后才物化并严格核对类型、完整性及 checkout 的固定提交。开启完整编译时，才需要物化整个固定向量。

一次批次冻结中，所有 manifest 按 `(origin, requested_revision)` 共用结果，包括失败结果；resume 使用已保存的固定向量，不重新解析。比如三行输入共有 1048 个待解析的来源/ref 对，且全部本地命中，只需 1048 次本地探查，不逐行重复三轮；本地探查后再回退远程的对会另计一次远程查询。完整固定 SHA 不需要解析 ref。独立新批次重新观测本地 ref，并仅在必要时查询远程。`allow_fetch: false` 禁止远程广告和对象获取，仍允许可信本地 ref 解析；需要的固定对象缺失时明确阻塞。

```sh
./run-patches cases.jsonl --config /absolute/path/server.json
```

入口串行处理各行。输出包含 `record` 指向的 `batch-status.json` 和 `launcher` 指向的启动器状态。只检查准备和发现、不调用模型时使用 `--inspect-only`。四字段自动模块编译需要 `build.enabled=true` 且 `agent.auto_validation=true`（未指定时使用程序默认值 true），由系统解析构建归属，不给每案预填模块。`auto_validation=false` 会关闭自动验证计划；专项 harness 手动调用构建的结果不能证明这个自动入口已经完成构建。

## 默认预算

这些是当前默认值；实际运行以 `effective-config.json`、`execution-budget.json` 和 `effective_stage_limits` 为准。

| 范围 | 默认值 |
| --- | --- |
| 单次模型调用超时 | 900 秒 |
| 单案模型调用总量 | 48 次，包括 SDK 纠错调用 |
| 调查轮次、最多项目数 | 3 轮、12 个项目 |
| 调查时间、整案活动执行时间 | 900 秒、7200 秒 |
| 单案工具操作、模型工具读取字节 | 2000 次、64 MiB |
| 定位、影响判断、候选修改 | 3 次、3 次、6 次；候选额度跨仓库和轮次累计 |
| 报告纠错 | 全案共享 6 次，不为各层另发额度 |
| 有新证据时的调查延长 | 最多 1 次、300 秒；不解除模型、读取和整案硬限 |
| 单案输出、整批输出 | 256 MiB、1 GiB |
| 准备阶段总时间 | 最多 3600 秒，覆盖查询、对象准备等受控 Git 操作 |
| 准备本地命令 | 未指定独立超时的命令默认最多 60 秒 |
| 准备对象获取 | 最多 128 次 fetch，每次最多 180 秒 |
| 准备 ref 解析 | 本地探查与远程查询合计最多 4096 次，与 fetch 独立计数 |
| 本地 ref 探查 | 每条 Git 命令最多 3 秒、stdout/stderr 合计 64 KiB；一次探查最多 3 条命令 |
| 远程 ref 广告 | 单次最多 30 秒、stdout/stderr 合计 64 KiB |
| 准备缓存与空间 | 单次 fetch 文件 512 MiB、缓存 32 GiB、最少剩余 2 GiB |
| 终态重试 | 最多 1 次，仅符合条件的模型超时；不重置已用额度 |

还可通过 `batch_limits` 显式设置整批模型调用数、执行时间及最低磁盘空间。64 MiB 限制受控 ToolIO 边界：模型工具的 Git 捕获、文件读取、请求和回复，包括失败及重试的实际字节；它不是整台主机或编译器的磁盘 I/O 上限。没有 ReadBudget/ToolIO 的可信控制器 Git 也计入整案 `tool_operations`，其直接捕获字节只记 telemetry，不扣该 64 MiB 额度。暂停调查计时不会免除整案命令次数。

`preparation-budget.json` 持久保存 `ref_queries`、`local_ref_queries`、`remote_ref_queries`；前者等于后两者之和，由 `preparation.max_ref_queries` 限制。进入一次本地探查或远程查询前分别扣 1，失败也计数；本地探查后回退远程会合计扣 2，memo 命中不再扣除，resume 不刷新。它们与对象获取的 `fetches`/`max_fetches` 独立。远程单次时间还受较小的 `fetch_timeout` 约束，所有操作均受剩余准备时间约束。超限输出不能用于固定项目；本地输出超限可回退远程，解析总量耗尽则属于共享准备阻塞。

`preparation.local_command_timeout` 是正整数秒，默认 `60`；大型源码树的独立构建配置可显式设为 `120`，仍执行完整的干净状态检查。它只适用于未指定独立超时的准备命令；本地 ref 的 3 秒、远程广告的 30 秒上限、`fetch_timeout` 和切换提交的 120 秒仍优先使用各自的显式限制。所有命令继续受剩余准备时间和已激活的整案时间预算约束；该配置随有效配置及其哈希保存，恢复时不能换值刷新额度。

准备层使用自己的局部 ToolIO；在整案账本已激活时，每次 Git 执行前也会扣一次工具操作，并继承现有 I/O 额度，但不计调查时长。因此完整 manifest 准备的对象清单读取可能显著增加消耗，不能将所有控制器读取都视为免扣。准备账本始终绑定原批次，即使冻结向量尚未写出就中断，resume 也不能重置 ref、fetch 或准备时间；原账本缺失时明确阻塞。恢复不能通过换轮次或扩仓重新获得候选次数。示例配置保留迁移默认 `2000` 次和 `67108864` 字节，并关闭编译；完整构建验证使用单独配置，不修改迁移对照配置。

## 启用模块编译

先完成迁移配置，再把 `build` 替换为经过核对的服务器构建配置。例如：

```json
{
  "enabled": true,
  "runner": "/opt/aosp-agent/scripts/module-build-r760.sh",
  "product": "sdk_phone_x86_64",
  "variant": "userdebug",
  "arch": "x86_64",
  "build_system": "build system from the fixed manifest vector",
  "toolchain": "compiler prebuilts from the fixed manifest vector",
  "host": {
    "kind": "host",
    "identity": "operator-maintained-build-host-profile-v1",
    "tools": {"bash": "/bin/bash", "git": "/usr/bin/git", "python": "/usr/bin/python3"}
  },
  "identity_files": {},
  "environment": {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
  "ninja": "/srv/aosp/source/prebuilts/build-tools/linux-x86/bin/ninja",
  "output_root": "/srv/aosp-build/output",
  "tmp_root": "/srv/aosp-build/tmp",
  "baseline_cache": "/srv/aosp-build/baseline-cache",
  "baseline_timeout": 1800,
  "graph_timeout": 120,
  "compatibility_mappings": []
}
```

这些目录必须与源码、缓存、隔离层、运行记录及彼此均不重叠。构建程序、工具、主机身份和额外配置输入必须由服务器管理员声明；外部脚本或配置文件用 `identity_files` 记录。容器配置使用 `kind: "container"` 并提供固定 `image_digest`。`HOME` 强制位于 `tmp_root/home`；不能改为真实用户主目录。受控环境不继承模型密钥或任意环境变量。

环境身份包含完整固定项目向量、manifest、受控覆盖项、产品、variant、架构、工具链、构建脚本、控制器源码和已声明主机工具身份。编译前物化完整清单；未声明的额外 checkout 或 ignored 输入会阻塞构建，不能静默参与基线缓存。

先构建未打补丁的同范围模块，再验证候选。只有相同环境下已成功的模块范围能复用基线；新增模块补验，失败不写入成功缓存。每个候选仍需新验证身份、补丁哈希、源码恢复凭据及实际构建动作证据。模块名存在、旧产物存在或退出码为零都不能单独证明当前修改参与编译。条件源码、生成源码或构建文件无法充分核实时继续记录 partial，不能提升为完整验证。

### 全 manifest 构建的工具预算

下列按 `N` 计算的是当前完整构建审计的实际成本，不是新的优化目标，也不是要求重新运行全量准备的指令。当前普通可写源码没有跨任务变化证据，因此这些检查尚未消除。不要通过提高预算或超时来冒充源码复用优化；先解决准备依据与失效范围，再验证一个真实案例。

默认 `max_git_operations=2000` 适用于迁移调查，不适合直接覆盖大型完整 AOSP 构建的源审计。设固定向量含 `N` 个项目，manifest 含 `D` 个目录 linkfile，计划验证 `K` 组模块，最多执行 `R` 次候选验证：

- 每次完整源码快照需 `7N + 2D` 次 Git 命令，检查 Git 实际路径绑定、索引标志、HEAD/tree、status、暂存区、工作区、ignored 输入和 manifest 目录 linkfile 的目标树；普通 root copyfile/linkfile 还检查字节或链接身份。
- 每组首次构建最多 4 次快照：无补丁基线前后、候选前后，即 `28N` 次命令。命中基线缓存时为 `21N`。
- 若静态归属不完整，需要生成无补丁实际构建图，每次验证再增加 `14N`。

有图发现时按 `R × (2 + 4K) × (7N + 2D)` 估算构建快照上界，再给准备、环境身份核对、已准入仓库的常规审计和调查留出明确余量。上面的 `28N/21N/14N` 是没有目录 linkfile 时的例子。启用编译前在独立 build profile 中显式配置 `max_git_operations` 并记录 `N/D/K/R` 依据；不要把这一变化混入迁移对照实验。无模型的专项构建若需要提高准备读取额度，必须另存有限额度配置并记录原因，不能改动 M2 的 64 MiB 基线。索引检查会读取该仓完整的有界路径列表，所有命令仍逐条计费。

以 `N=1048`、`D=3`、一组模块与一次候选验证的未启用底座流程为例：四次基线/候选快照加可选两次构建图快照为 `6 × (7N + 2D) = 44052` 次。再预留本地 ref 探查最多 `3N=3144` 条，以及对象已齐备、已有 checkout 时约 `7N=7336` 条物化命令，共约 `54532` 次。历史 M4 的 `max_git_operations=50000` 已不足以覆盖这个新估算，旧配置与结果仍保留；若另建 `60000` 的独立实验 profile，仅余约 `5468` 次，仍不是完成保证。专项 M4 从准备开始就激活整案账本，准备 Git 与快照均按实际发起计次；预留数值不代表已经消费，准备层仍受自己的时间、ref/fetch 次数及 ToolIO 字节限制。缺对象获取、额外模块、验证重试或兼容视图会增加成本，须记录实际消耗并在有限额度耗尽时停止，不能自动扩大预算。

必要完整性审计有固定的 `audit_grace`：从首次整案硬限耗尽开始，最多 120 秒和 20000 条获准只读审计命令，两者均需满足。这是持久的墙钟截止时间和累计次数，跨 resume 不刷新；不能配置成无限，也不能用于写入、模型调用、修补、新调查或编译。`BatchBudgetExceeded` 等整批阻塞仍然生效，不会被这项宽限捕获或绕过。

默认严格使用原完整 manifest。只有服务器预先配置 `compatibility_mappings`，才能派生保持被测仓库提交不变的验证向量；映射必须给出完整向量、原向量哈希、规则 ID 和可信依据。派生环境单独记录，不能写成原 manifest 通过。分析用过的依赖只有在旧、新 Git tree 完全相同时才直接重绑定证据；tree 改变会标记相关依赖待重验并阻塞，构建层不猜语义等价。

## 查看状态与恢复

使用启动器输出的实际路径查询批次或单案：

```sh
"$AOSP_AGENT_PYTHON" -m aosp_agent status --record /absolute/path/batch-status.json
"$AOSP_AGENT_PYTHON" -m aosp_agent status --record /absolute/path/row-0001/execution/run.json
```

状态同时给出保存的状态和实际 lease/process 状态。不要仅凭旧 `RUNNING` 字段判断任务仍在运行。原始模型事件、报告拒绝、工具读取、预算、候选历史和基线/候选构建记录都由批次与单案记录指向，不能用最终一行状态替代原始证据。

无人值守批次必须通过相同隔离入口恢复：

```sh
./run-patches --config /absolute/path/server.json --resume /absolute/path/batch-status.json
```

恢复先核对源状态、候选、配置、预算、固定对象、旧进程和 checkpoint 协议。代码哈希也必须与原记录一致；代码发生变化或旧记录缺少兼容元数据时明确阻塞，不篡改旧记录强行恢复。需要比较新代码或调整硬限时，用原四字段输入启动独立新批次，保留旧证据。独立新任务有新预算和新结果身份，不能将它称为原任务续跑。

单案输入、影响证据、补丁生成或已确认恢复的构建环境失败，会记录该案结果并继续后续案例。认证、余额、模型不可用、整批硬限、磁盘不足、活跃源 lease 或无法核实源码/子进程恢复属于共享故障，会暂停批次。先排除共享故障并检查恢复凭据，再显式恢复。

正常取消会请求停止当前工作并进入有时间上限的收尾；取消状态本身不是源码或子进程恢复成功的凭据。若恢复、旧进程或 lease 仍无法核实，后续 resume 继续阻塞；应检查记录中的具体原因，不能只因进程已退出就删除 lease 或强行续跑。

`PATCH_UNVERIFIED` 表示候选已保存但验证不足；`build_validation`、`review_status` 和 `delivery_status` 分开表达构建、复核与交付准备状态。即使 `VALIDATED`，也不表示完成设备运行时安全证明。
