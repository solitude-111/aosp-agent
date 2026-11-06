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

每次新任务使用新的运行目录。默认先分析补丁和项目目录，再按证据读取、扩展项目范围；旧全仓发现仅以 `--exhaustive-discovery` 显式启用。`--inspect-only`（run 的兼容名 `--no-codex`）不调用模型或创建迁移 worktree；元数据能确定初始范围时返回 `DISCOVERED`，否则返回 `INCONCLUSIVE / INSPECTION_REQUIRES_PROJECT_SCOPE`，可用重复的 `--repository` 指定初始项目。`--turn-timeout` 默认 900 秒，另有整个调查阶段的总预算。认证由运行账户的 Codex SDK 环境提供，不把凭据放入项目。JSONL、预算及取消恢复命令见根目录 README。

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

`dataset/cases/` 提供提交身份和目标基线，CLI 忽略其中历史 `files`/`validation`。文件范围来自核实映射，donor 新增行只生成调查提示，构建目标来自固定目标树配置；独立人工验收需用 `--validation` 显式覆盖。`dataset/oracles/` 和历史人工补丁只供离线评价。源码引用检查不能自动证明模型推理正确或所有产品可达性。

## 状态与证据

| 状态 | 含义 | CLI 退出码 |
| --- | --- | --- |
| DISCOVERED | 仅完成固定基线的候选发现，模型未运行 | 0 |
| NOT_AFFECTED | 模型给出不受影响判断且引用通过核实，未迁移 | 0 |
| INCONCLUSIVE | 证据不足，停止迁移 | 4 |
| PATCH_UNVERIFIED | 未配置完整检查、仅冒烟通过，或缺少多仓联合验证 | 3 |
| VALIDATED | 当前候选的生产构建/还原及全部配置检查通过，且当前组合复核完整、各仓均为低风险 | 0 |
| NEEDS_REVIEW | 构建证据合格，但复核未完成、已过期或有中高风险 | 7 |
| VALIDATION_FAILED | 验证重试耗尽，保留候选和失败证据 | 5 |
| MIGRATION_INCOMPLETE | 文本迁移的映射覆盖、逐 hunk 证据或新增文件接入未通过 | 6 |
| FAILED | SDK、证据、路径或执行错误 | 2 |

顶层产物包括 `run.json`、`mapping-plan.json`、`validation-plans/`、`patch-bundle.json` 和全任务 `hunk-ledger.json`。顶层 `causal_evidence` 保存共同因果规则的检查结果；project-first 和多来源输入的全部变更单元必须纳入有来源命名空间的证明组，辅助变更保留对核心修复的证据关联。各仓库的运行时 Case、后端判断、逐 hunk 账本、候选补丁和验证输出位于 `repositories/<key>/`。

新增生产文件的 `new-file-audit-N.json` 同时记录调用路径及 `activation.binding`：新增源码中的具体声明、调用处的导入/包名绑定、目标文件和未证明的运行条件。名字相同、仅导入、仅被构建通配收录都不够。恒不执行的 switch 分支和遮蔽 helper 的局部变量不会获得接入证据；改变导入而接入已有调用的合法情形仍支持。这里的 RESOLVED_LEXICALLY 是受支持语法内的静态连接，不等价于产品运行时可达性。

新增文件还记录 `classification`。Test 后缀或 tests 目录本身不再豁免接入；汇编、脚本和头文件按源码处理，未知类型、无法解码或超过解析上限的新增文件明确拒绝。辅助测试需有固定目标基线中可静态求值的测试构建消费者，或满足受支持的 Python 断言脚本/测试函数结构并绑定实际修改的已有实现。测试构建查询仅限祖先 Android.bp，候选自己写入的构建声明不能作为豁免依据，没有新增文件就不查询。

`supplementary_test`、配置和数据材料不提供生产源码修复信用，不能通过搬运 token 满足生产来源单元。上游完整新增测试的义务另按受支持断言/JUnit/kotlin.test 声明核实。测试消费者只证明已查询元数据中的测试用途，不证明产品全局没有其他消费者；`test_executed=false` 明确表示角色检查未运行测试。复杂测试框架、动态构建表达式和未适配类型需要补充证据或适配，不能退回按名称放行。

验证配置既可使用旧的 argv 列表，也可使用带 `stage` 和 `artifacts` 的 `checks` 对象。每个检查记录命令、退出码、日志、阶段和产物哈希；未配置的 JVM、模块构建、设备运行和 PoC 层明确保持 `NOT_CONFIGURED`/`NOT_RUN`。共享的 `production_build_v1` 策略要求 `android_module_build` 阶段具备当前补丁和本次调用对应的 apply/build/restore 成功凭据，并要求全部配置检查通过。`verification.policy` 列出缺少构建覆盖的仓库；仅普通命令、文本检查或 JVM 检查通过，保留 PASS，但总结果为 PATCH_UNVERIFIED。构建器由配置方负责选择，事务凭据证明它执行并恢复了源码，不独立证明任意脚本就是生产编译器，也不证明运行时安全。

## 多仓联合验收

自动推导编译目标时，测试模块不能代替生产模块覆盖。`validation-plans/*/plan.json` 的 `build` 同时保留 `production_uncovered` 和 `unresolved_consumers`；存在未解决的生产消费者时不自动生成声称完整覆盖的构建检查。未启用验证、没有构建器或已显式覆盖构建检查时，不进行自动 Android.bp 扫描；分析和候选生成仍可继续，缺少构建证据保持 PATCH_UNVERIFIED。

`blueprint_literals` 按 [Android 12 Blueprint 解析规则](https://android.googlesource.com/platform/build/blueprint/+/android-12.0.0_r1/parser/parser.go) 处理受支持的静态表达式。配置按父目录先于子目录的顺序读取，子文件继承父变量，兄弟目录不互相修改作用域。值只来自固定目标配置，求值不执行代码。支持 JSON 兼容字符串、列表、映射和有界整数运算；超出范围的语法仍明确拒绝。每文件有 4 MiB 输入上限、20 万 token/求值工作额度及 64 层表达式深度上限，不允许通过变量反复拼接无限膨胀。非法文件不导出部分模块或变量，后代不会借用不完整父作用域。

静态值求解只改善构建归属推导，不替代 Soong 的产品配置、模块类型和 namespace 求解。未知变量、include 指令、产品条件或未解析的生产消费者仍阻止自动生成完整构建检查；应使用经目标环境确认的构建配置。`metadata_inputs` 的文件摘要与计划的固定提交共同记录输入出处，实际编译/恢复凭据仍须由后续验证产生。

文件匹配使用 `blueprint_posix_bounded_v1`：支持字符集合、范围、`^` 取反、转义、`*`、`?` 及一个非末尾的完整 `**` 路径段，遵循 Android 12 Blueprint / POSIX Go 匹配行为。非法规则、越界路径或工作量超限产生未确定结果，不能作为“没有消费者”或“没有排除”的证据；该规则也适用于 filegroup 和辅助测试归属。模式与路径各限 4096 字符，匹配工作估算限 100 万，解析缓存最多 256 条。自动构建仍可能扫描所选仓库的全部构建元数据；真实产品构建图、按版本和配置复用的索引及源文件实际编译覆盖仍待目标环境验收。

默认项目优先流程会把已解析的静态构建元数据放入受管对象缓存。首次仍收集所选仓库的全部 `Android.bp`，保留兄弟目录消费者；相同固定提交的后续轮次/任务可复用索引，无需再次遍历文件树、读取或解析这些文件。索引身份包含仓库、提交、解析实现、运行时 Unicode 版本、解析额度和扫描上限。读取失败不持久化；缓存损坏、不可用或索引过大时重新读取固定源码，不将失败解释为文件缺失。索引与 Git 对象共享现有容量、条目数和单条大小上限。

索引仅保存静态事实，每次仍按实际待改文件判断归属、排除规则、条件消费者及测试角色。`metadata_index.scope=pinned_static_metadata_not_product_graph` 明确其边界：它不缓存验证结论，不解决 namespace 或产品配置，也不充当候选文件已被实际编译的凭据。

受控符号工具支持 `locate-symbol --language native` 等可重复参数。默认已包含 C/C++ 等源码；输出明确标记搜索范围，NOT_FOUND_IN_SCOPE 不表示功能不存在，READ_FAILED 也不能作为排除依据。

验证命令默认允许 stdout/stderr 合计 64 MiB，超额返回失败并执行进程组清理；清理宽限期继续排空输出，保留每路最多 1 MiB 原始字节的首尾诊断。这里不再写全量临时捕获文件。`run_check` API 的 `output_limit` 可显式调整单命令上限；它不限制构建程序自行生成的文件。

固定对象缓存默认最多 256 MiB 数据、1024 条、单条最多 16 MiB。大对象仍可正常读取，只是不缓存；缓存失败不会变成“源码不存在”。任务记录中的 `object_cache` 显示额度、淘汰、跳过及配额准入状态。API 可配置容量，共享目录采用最严格配额；需要扩大时换用新缓存目录。SDK 事件日志、控制器结果及整批受管输出另由 `--max-output-bytes` 限制，具体计数与排除范围见下文。

`run` 和 `diff` 均支持 `--joint-validation checks.json`。文件包含固定 argv 检查列表（格式同单仓 checks），命令工作目录为组合后的 `workspace/`；仓库路径仍以各自 key 为前缀。显式联合检查声明覆盖整组候选，因此应选择确实检查组合行为的回归脚本；普通联合检查成功不能替代整组生产构建凭据。不传 `--verify` 时不执行这些命令。

启用验证后，最终可保留的候选执行独立的修复后业务影响复核，包括多来源序列和文本补丁。复核读取整个最终补丁组合及实际验证状态，不预设编译成功；失败标记为 `post_fix_review.status=INCOMPLETE`。成功复核按完整组合摘要关联，任一仓库补丁变化都重新复核，失败记录不作为成功缓存。该模型复核与确定性构建结果分开记录，不能替代运行时安全证据。

交付策略 `build_and_review_v1` 分别保存 `build_validation`、`review_status` 和 `delivery_status`。`post_fix_review.status=COMPLETED` 仅表示复核调用完成；其中任一仓库为 medium/high，仍需审查。构建合格但复核缺失、失败、过期或中高风险时，总状态为 NEEDS_REVIEW，原构建 PASS 和恢复凭据保留。只有当前候选的构建与低风险复核均满足时，交付状态才为 READY_FOR_HANDOFF；它表示可交给后续流程审阅，不授权部署，也不证明安全修复正确。缺少构建证据仍为 PATCH_UNVERIFIED/UNVERIFIED。已失败、恢复阻断或发现范围不完整的任务不能被旧复核升级。

CLI 的 run/diff/resume 摘要包含这些独立字段，NEEDS_REVIEW 返回 7；batch 记录 delivery_counts，普通待审查案例不阻断下一行。NEEDS_REVIEW 是已完成候选的终态，resume 不会因此自动重跑；后续修复或复核应显式发起。status 命令保留 saved_status，并按当前策略给出 effective_status 和交付字段，不改写历史记录。

多仓的 `android_module_build` 自动延后到联合阶段。相同显式 `--build-runner` 的字面量模块名取并集后执行；其他命令独立执行。`--joint-validation` 按 stage 覆盖自动联合检查，显式空列表禁用自动联合检查。缺少完整联合覆盖时，多仓结果最多为 `PATCH_UNVERIFIED`。

联合构建传入 `AOSP_AGENT_PATCH_BUNDLE`、`AOSP_AGENT_BUNDLE_SHA256`、`AOSP_AGENT_WORKTREE`、`AOSP_AGENT_RUN_DIR` 和每次调用唯一的 `AOSP_AGENT_VALIDATION_ID`。runner 应调用 `aosp_agent.build_transaction`：在同一锁内预检每个补丁和只读依赖，再临时同时应用全部补丁、构建、逐仓恢复，输出本次 bundle 的恢复回执。返回 0 但缺少新鲜回执的构建不会通过。任一恢复状态异常会失败并保留意外改动。

联合构建产物写入 `AOSP_AGENT_ARTIFACT_DIR`，即运行目录的 `joint-artifacts/`；配置中的产物路径也使用这个前缀。每次检查前归档旧产物，防止上一轮文件充当本轮输出。固定计划、最终补丁集合及联合检查记录分别保存在 `joint-validation-plan.json`、`joint-patch-bundle.json`、`joint-verification.json`。验收记录绑定整组补丁哈希，每次新验证均重新执行检查；固定对象和静态元数据缓存不提供旧 PASS 的复用信用。

## 开发测试

输入准备可先运行离线清单检查（不启动模型、不 fetch、不构建）：

```sh
.venv-sdk/bin/python -m aosp_agent.input_audit --dataset aosp_agent/dataset/cases-new16 --donor-root /path/to/donor-git --output /path/to/new-input-audit.json
```

输出逐行区分缺 donor 仓库、缺提交、父提交不匹配、diff 不可读和重复编号；某行无效不会吞掉其他输入。`READY` 仅代表本地 donor 输入可读取，临时编号仍需权威映射，未出现在输入表中的行也无法纳入统计。工具拒绝覆盖已有输出。补齐对象仍须独立准备，不能把此清单当作回移或 CVE 身份验证成绩。

```sh
.venv-sdk/bin/python -m unittest discover -s aosp_agent/tests -v
```

测试包含临时真实 Git 仓库、补丁重新应用、验证失败修订、证据拒绝和 SDK 事件处理。多数模型回合使用替身，必须与真实模型运行证据分开。当前验收范围与缺口见 [架构说明](ARCHITECTURE.md#验收范围与尚未完成的资格验证)，逐轮本地验证见 [优化记录](OPTIMIZATION_PROGRESS.md)。此工作树不包含此前引用的历史人工实验目录和独立验收文档，不能以这些缺失路径作为本版本已通过真实 Android 验证的证据。

影响分析引用标准库行为时，`platform_semantics` 需包含 `api`、`behavior`、调用处索引 `relied_at_evidence` 和目标版本实现索引 `implementation_evidence`。仅 API 名称、调用处或 donor 版本实现不足以支撑确定结论。可在已准入依赖仓库只读引用实现，不必将实现加入补丁编辑范围；缺少关键证据应补充范围或返回 UNKNOWN。`platform_behavior_evidence` 表示源码出处已核对，始终明确不证明语义正确性或运行时分派。

模型现在通过控制器动态工具读取及编辑，生产回合不提供 shell 或 apply_patch。`aosp_source` 提供固定版本的 view/locate/search/paths/history/show；`aosp_read_file` 和 `aosp_list_files` 用于运行元数据与候选文件；`aosp_replace_text` 和 `aosp_write_file` 只允许编辑当前阶段授权的文件，并校验读取时的 SHA256。旧提示中的 wrapper 工具名映射到上述 source 操作，不需要执行脚本。控制器仍负责验证、编译及恢复。

操作次数、模型工具 I/O 字节额度及截止时间在执行前/读取过程中检查；达到上限会停止该回合，不将读取失败当作功能不存在。字节计数使用保守预留（包括每次结果容量），并非磁盘实际读取量；它不覆盖整个缓存/编译日志的磁盘总量。底层 SDK 无范围诊断模式不具备这一读取边界，不能用作 agent 生产入口。

`run`、`diff`、`batch` 和 `inherit` 另有 `--max-output-bytes`（默认 256 MiB，允许 128 KiB 至 1 TiB），限制控制器累计写出的输入副本、事件日志、分析记录、导出补丁及保存的验证输出。批次行、仓库和轮次共享根任务额度，不能各自重置。计数包含覆盖及失败写入的预留量，不等于目录当前大小；普通恢复尝试继续使用根任务的剩余额度。

额度耗尽后停止新的分析、模型请求和验证，保留小额空间写最小 BLOCKED/UNKNOWN 终态；证据不截成“成功”。`status` 和 `resume` 检查持久额度状态，旧成功文件或缺失终态文件不能绕过耗尽屏障。需要增加额度时显式创建新任务，不修改旧计数重跑。锁等待、额度文件损坏或输出 I/O 失败也会阻止继续工作；SDK 清理不依赖继续写日志。

此额度不含源码/候选工作树、单独限额的对象缓存、外部编译产物以及必须保留的源码恢复回执。它不能替代文件系统容量预留，也不保证其他进程写满磁盘后仍可落盘；恢复和进程清理不得被普通日志额度跳过。生产限额仍需在目标环境测量调整。

变更正文和行号由 `patches.text_hunks` 共用计数解析器读取，供定位、因果证据、账本、映射范围、新增文件接入及辅助提示使用。重命名或权限位变更携带的多个 hunk 保留各自旧/新行号；代码行首的 `++`/`--`、无结尾换行标记及下一份文件头不会混淆。纯文件操作没有可执行变更行信用。该解析器提供出处与位置，不证明语义等价；完整输入和不支持的 patch 类型仍在入口由 `split_hunks` 检查。

初步定位采用直接文件、邻近目录、仓库级回退的分阶段读取。直接路径命中后还检查完整 donor 旧侧或新侧文本；仅文件名命中不足以推迟后续检索。邻近目录通过固定提交的子树读取与限定路径搜索处理，不把已读取的子树标成全仓清单。文件内容和子树缓存绑定固定版本；成功候选仍需独立语义调查，未搜索的其他实现保留 `DEFERRED`，没有“全仓已确认不存在”的信用。读取故障保留在 issues，候选读取上限跨阶段共享；不能通过多次扩大范围重置上限。
