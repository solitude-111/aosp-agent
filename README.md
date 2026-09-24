# aosp-agent

以 GLM 为唯一大模型执行层的 AOSP 漏洞影响判断与补丁回移 agent。控制器保留
RetroPatch 风格的机械 apply、符号预扫、受控只读工具、策略阶梯、诊断反馈、
hunk 级申报核对、证据逐字核实和隔离审计。

## 结构

```text
aosp_agent/            agent 本体
  engine.py            控制器：worktree/审计/机械迁移/验证/状态机
  glm_runtime.py       GLM Chat Completions 运行时（唯一模型通道）
  direct_api.py        GLM HTTP 客户端
  prompts.py           SYSTEM / impact / backport 提示词
  symbols.py           donor 补丁符号预扫（git grep + difflib）
  patch_repair.py      机械补丁修复
  diagnosis.py         apply/验证失败的结构化诊断
  ladder.py            T1..T6 策略阶梯
  agent_tools.py       受控只读工具 CLI
  case.py / patches.py 输入契约 / donor diff 分解
  dataset/cases/       案例（仅输入事实；无参考答案）
  tests/               单元测试（真实临时 Git 仓 + mock runtime）
scripts/
  deepen_donor.sh      donor 历史加深（用户手动执行；agent 永不联网）
  r760-build-module.sh android_module_build 验证阶段（r760 编译树）
```

## 运行

```sh
export GLM_API_KEY=<your-glm-api-key>
python -m aosp_agent run CVE-2025-48550 \
  --source-root <目标 AOSP 源码根> --donor-root <donor 裸仓根> \
  --run-root <输出目录> --model glm-5.3 --verify --max-attempts 6
```

默认模型为 `glm-5.3`，默认 endpoint 为智谱 GLM OpenAI-compatible API。可用
`AOSP_AGENT_GLM_BASE_URL` 与 `AOSP_AGENT_GLM_API_KEY_ENV` 覆盖。状态机保持
`UNKNOWN ≠ NOT_AFFECTED`；空补丁、未配置验证或验证失败均不算成功。
