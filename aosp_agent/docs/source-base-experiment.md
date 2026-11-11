# 已退出主流程的源码底座实验

本文件保存此前实现说明与接口，供核对历史代码及证据使用。当前服务器没有启用该方案；fs-verity、SquashFS、loop 不是四字段自动入口的前置条件。本轮不继续部署该方案，也不开发替代底座。以下原说明中的登记、制镜像和挂载步骤均不属于当前执行计划。

## 显式复用只读源码底座

本节给出源码底座接口和启用条件。代码部署、小型仓库测试和真实 overlay 挂载测试，都不代表服务器已有可复用底座或实际 AOSP 构建已经通过；必须另有该服务器的成功登记收据。启用前先确认实际存储支持 fs-verity，并具备只读 loop/SquashFS 挂载权限，不要仅依据内核支持就准备整套源码。未配置 `source_base` 时继续使用原隔离流程和完整源码审计；要求禁止重复全量准备的任务，在底座登记完成前应保持暂停。

复用需要先登记一次经过独立完整核验的只读底座。当前支持的 provider 是 `fsverity_squashfs`：镜像文件必须受 fs-verity 保护，通过只读 loop 设备挂载为只读 SquashFS。控制器读取实际内核证据并绑定镜像摘要、目录清单和登记收据；仅有 `chmod`、普通只读 bind、JSON 中的 `READY` 或上次成功日志都不足以授权复用。每次打开或使用视图仍核对内核身份，登记后的相同底座不再逐仓执行 Git 审计。

先对已有、离线对象齐备的 checkout 生成目录清单，输出必须位于源码树外且不能覆盖既有文件：

```sh
"$AOSP_AGENT_PYTHON" -m aosp_agent.source_base_cli create-catalog \
  --source-root /srv/aosp/input \
  --manifest-origin https://android.googlesource.com/platform/manifest \
  --output /srv/aosp-registration/catalog.json
```

该步骤核验完整项目及 Git 元数据、对象闭包、固定引用和 manifest 的 copy/link 文件。随后由运维在本流程之外制作镜像，将上述清单的原始字节包含在镜像内，并完成 fs-verity、只读 loop 和 SquashFS 挂载。CLI 不下载对象、不切换 checkout、不制作镜像、不启用 verity，也不执行挂载。没有 `.repo` 的小型 checkout 可显式提供 `--project-catalog`；已有 `.repo` 时不能用手写清单缩小项目范围。

登记 spec 必须恰好包含以下六项，摘要占位符须替换为实际值，`catalog_path` 是镜像内部相对路径：

```json
{
  "provider": "fsverity_squashfs",
  "image": "/srv/aosp-base/base.squashfs",
  "mount_root": "/srv/aosp-base/mount",
  "verity_digest": "0000000000000000000000000000000000000000000000000000000000000000",
  "catalog_path": ".source-base/catalog.json",
  "catalog_sha256": "0000000000000000000000000000000000000000000000000000000000000000"
}
```

```sh
"$AOSP_AGENT_PYTHON" -m aosp_agent.source_base_cli register \
  --spec /srv/aosp-registration/sealed-image-spec.json \
  --receipt /srv/aosp-registration/registration.json
```

登记先核实真实 provider，再独立审计镜像内的完整源码；结果必须与镜像内清单一致才发布收据。上述两个 CLI 的默认审计限额分别为：单条 Git 最多 60 秒、64 MiB 输出，整次最多 7200 秒、1 GiB 输出、50000 条 Git；可显式配置有限额度，超限不发布成功登记。该初始成本与每案准备预算分开记录。

首次登记也核验 Git 配置的实际来源：首版拒绝 `include`/`includeIf`，配置文件及其符号链接必须完全位于可重定位的源码闭包内。完整索引不得含 `assume-unchanged` 或 `skip-worktree` 标志；否则 status/diff 的干净结果不足以证明源码未变。登记不会自动清除这些标志或修改配置。

将 `register` 输出中的 `receipt` 和 `receipt_sha256` 两项加入服务器配置顶层：

```json
{
  "source_base": {
    "receipt": "/srv/aosp-registration/registration.json",
    "receipt_sha256": "0000000000000000000000000000000000000000000000000000000000000000"
  }
}
```

底座挂载目录必须与任务源码、缓存、隔离层、运行目录和构建目录互不覆盖，镜像和登记收据也不能被任务挂载遮住。配置声明了底座但摘要、seal、挂载或目录清单失效时明确阻塞；不会静默回退到扫描 1048 个仓库，也不会继续信任旧 `source_view` 收据。

完整目标向量中与登记底座相同的项目直接复用；选中的写入仓库获得自己的可写 upper，pin 改变只物化相应仓库。相同向量的派生验证视图不重新物化项目；不同向量仅处理差异项目，并保留父视图已有的可写仓库。每案及每个派生视图使用独立工作层和输出层，修改不得写入底座或宿主 checkout。源码恢复审计继承仍有效的只读项目证据，并实际检查可写仓库；失去底座或活动视图证据时阻塞，不能把“少做检查”当成恢复成功。

每次可写仓审计都会重新核对 Git 实际 worktree、gitdir 和 common-dir，防止构建期间配置被改向另一棵干净源码树；同时用有界 `ls-files -v -z` 检查整个该仓索引，拒绝可隐藏改动的索引标志。大仓的索引路径输出可能较大，仍受读取与输出额度限制，超限即阻断；只读底座仓继承首次已核验的索引证明，不重复逐仓 Git 查询。

runner 路径、脚本字节、输出目录或构建参数变化不改变源码底座身份，也不应触发全仓 Git 扫描；它们仍改变构建环境身份，旧基线成功缓存不能据此沿用。源码复用与构建验证是两份独立证据。登记清单中来源匹配的固定 ref 也可直接继承，不重复查询本地或远程；这代表明确选用已登记的源码快照，不承诺上游最新。需要更新时显式选择新目标 pin 或重新登记新的底座，不能改写旧登记。

首版要求项目集合和 manifest copy/link 声明与已封存清单一致：新增或删除项目、改变这些文件布局会明确阻塞。可写项目与清单中其他项目存在父子路径交叠、Git worktree 的 `commondir` 与 `git_dir` 不同，也不支持。恢复记录中的私有 Git 元数据尚未 `READY` 或原 upper 缺失时保留现场并阻塞，不能重建一个空层冒充原任务恢复。此类情况应先满足受支持的底座布局，再显式登记或启动独立新任务。

