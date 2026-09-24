# AOSP Backport Agent

基于 GLM 的 AOSP 影响判断与补丁迁移原型。项目保留固定提交比较、hunk 分解、
代码定位、受控证据核实和验证反馈流程；所有模型请求都走 `glm_runtime.py`。

## 运行方式

```sh
python3 -m venv .venv-glm
.venv-glm/bin/python -m pip install -r aosp_agent/requirements-glm.txt
export GLM_API_KEY=<your-glm-api-key>
.venv-glm/bin/python -m aosp_agent run CVE-2025-48550 \
  --source-root /path/to/source \
  --donor-root /path/to/donor-git \
  --run-root /path/to/runs/<新的实验名> \
  --model glm-5.3 --verify --max-attempts 2
```

默认模型是 `glm-5.3`，默认 API base URL 是
`https://open.bigmodel.cn/api/paas/v4`。可用 `--model` 换用账户可用的其他 GLM
模型；可用 `--api-base-url` 或 `AOSP_AGENT_GLM_BASE_URL` 指向兼容环境，可用
`--api-key-env` 或 `AOSP_AGENT_GLM_API_KEY_ENV` 改凭据变量名。默认读取
`GLM_API_KEY`，并兼容回退 `ZHIPUAI_API_KEY`。

每次使用新的运行目录。`--inspect-only` / `--no-model` 只做 Git 准备与 hunk
检查，不调用模型。`--turn-timeout` 默认 900 秒，覆盖一次业务回合中的多轮 GLM
请求和工具调用。

## GLM 执行层

`glm_runtime.py` 使用 GLM Chat Completions 的 function calling 循环，向模型提供：

- `view_file`：当前 workspace 内最多 2000 行的有界文件读取；
- `list_dir`：当前 workspace 内的一层目录列表；
- `search_files`：仅 diff-only 评估流程启用的有界正则搜索；
- `run_controlled_command`：仅允许执行控制器生成的 `locate-symbol`、
  `view-code`、`hunk-history`、`show-commit`；
- `write_file`：仅迁移阶段可用，路径解析不能逃出独立 worktree。

运行时记录 `glm-events.jsonl`，包括请求、响应、工具调用、命令输出、用量、
结构化输出校验和错误；凭据值会被 redact。影响阶段拒绝写工具。控制器仍在每轮
后审计允许路径、HEAD、符号链接、原始 checkout 和候选补丁重放结果。

GLM API 本身不提供进程级 sandbox，因此本项目的安全边界是显式工具 allowlist、
路径 containment、只读阶段拒绝写入和控制器事后审计，不宣称操作系统级逐文件
权限隔离。验证命令仍由控制器持有，模型不能通过 GLM 工具自行运行验证或 PoC。

## 当前流程

1. 固定 donor 修复及其真实父提交，创建干净的 detached worktree。
2. 分解 donor hunk，用独立临时 Git index 检查文本可应用性，保留冲突信息。
3. GLM 通过只读工具分析目标源码与相关 API，返回影响状态和源码证据。
4. 控制器检查引用的 Git blob、文件、行范围和连续摘录；不一致时请求只读纠正。
5. 仅 AFFECTED 进入迁移。GLM 在独立工作树中通过 `write_file` 修改文件。
6. 控制器导出候选，在新的干净 detached worktree 中重放，执行分层验证并反馈修订。

`dataset/cases/` 是运行事实；离线评价材料不进入模型输入。引用检查证明证据真实，
不能自动证明模型推理、产品可达性或运行时安全。

## 状态与证据

| 状态 | 含义 | CLI 退出码 |
| --- | --- | ---: |
| PREPARED | 仅完成准备，模型未运行 | 0 |
| NOT_AFFECTED | 模型判断不受影响且引用通过核实 | 0 |
| INCONCLUSIVE | 证据不足，停止迁移 | 4 |
| PATCH_UNVERIFIED | 已生成候选，但未请求或未配置验证 | 3 |
| VALIDATED | 当前候选通过所配置检查，仅限其覆盖范围 | 0 |
| VALIDATION_FAILED | 验证重试耗尽，保留候选和失败证据 | 5 |
| FAILED | GLM、证据、路径或执行错误 | 2 |

主要产物：`run.json`、`glm-events.jsonl`、`inspection.json`、`impact.json`、
`diff-audit.json`、逐次 `candidate-N.patch`、最终 `backport.patch`、
`verification.json` 和验证原始输出。

## 开发测试

```sh
.venv-glm/bin/python -m unittest discover -s aosp_agent/tests -v
```

单元测试使用临时真实 Git 仓库和 GLM runtime 替身，不消耗模型额度。真实连通性
检查可手动运行 `aosp_agent/tests/smoke_glm_runtime.py`。
