# aosp-agent

以官方 Codex SDK 为唯一模型执行层的 AOSP 漏洞影响判断与补丁回移 agent，
工作流移植自 RetroPatch（先机械 apply、符号预扫、受控只读工具、六级策略阶梯、
诊断式反馈、hunk 级申报核对），并保留证据逐字核实与隔离审计。

## 结构

```
aosp_agent/            agent 本体
  engine.py            控制器：worktree/审计/机械迁移/验证/状态机
  sdk_runtime.py       官方 openai-codex SDK 运行时（唯一模型通道）
  prompts.py           SYSTEM / impact / backport 提示词
  symbols.py           donor 补丁符号预扫（git grep + difflib）
  patch_repair.py      机械补丁修复（RetroPatch revise_patch 移植）
  diagnosis.py         apply/验证失败的结构化诊断
  ladder.py            T1..T6 策略阶梯
  agent_tools.py       受控只读工具 CLI（locate-symbol / view-code /
                       hunk-history / show-commit）
  case.py / patches.py 输入契约 / donor diff 分解
  dataset/cases/       案例（仅输入事实；无参考答案）
  tests/               单元测试（真实临时 Git 仓 + mock runtime）
scripts/
  deepen_donor.sh      donor 历史加深（用户手动执行；agent 永不联网）
  r760-build-module.sh android_module_build 验证阶段（r760 编译树）
```

## 运行

```sh
python -m aosp_agent run CVE-2025-48550 \
  --source-root <目标 AOSP 源码根> --donor-root <donor 裸仓根> \
  --run-root <输出目录> --model <模型> --verify --max-attempts 6
```

状态机：UNKNOWN ≠ NOT_AFFECTED；空补丁/未配置验证/验证失败均不算成功；
`run.json` 记录每轮策略、工具留痕、hunk 申报、分层验证与产物哈希。

参考答案（oracle）只用于运行结束后的离线比对，绝不进入模型输入。
