# ix-control systemd 模板（仅供本地审阅）

`cmd/ix-control/systemd.go` 内嵌一组**只渲染到标准输出**的 systemd unit 模板。`ix-control --mode systemd-render` 是纯本地生成命令：不调用 `systemctl`、不连接网络、不写入任何目录，也不启用或部署服务。

## 模板集合

节点角色渲染以下 unit：

- `ix-control-restore.service`：恢复已授权的本地规则集，并以 `Before=ix-control-agent.service` 明确先于 Agent。
- `ix-control-agent.service`：只使用 `--token-file` 读取本地 token；模板不包含 token 值，也不使用 `--apply-hook`。
- `ix-control-collector.service` 与 `ix-control-collector.timer`：本地采集器及其每分钟调度器。

主控角色渲染以下 unit：

- `ix-control-server.service`：只监听 `127.0.0.1:8787`。
- `ix-control-reconcile.service` 与 `ix-control-reconcile.timer`：本地 SQLite 对账及其每分钟调度器。

两个 timer 都包含 `OnUnitActiveSec=1min` 与 `Persistent=true`。所有可变状态固定为 `/var/lib/ix-control`，并使用 `StateDirectory=ix-control`、`StateDirectoryMode=0700` 和 `UMask=0077`。

## 渲染输入与审阅边界

调用者通过 `SystemdRenderInput` 提供绝对二进制路径、节点 ID、WebSocket URL、token 文件、状态目录和 SQLite DSN。渲染器使用 `@PLACEHOLDER@` 形式的占位符，并在替换前严格校验：

- 节点 ID 仅允许字母、数字、`_`、`-`；
- 节点 URL 必须是无凭据、无查询参数的 `wss://` URL；模板和文档均不提供真实远端地址；
- token 文件必须位于 `/etc/ix-control/` 下，并由调用者明确声明其权限为 `0600`；渲染器从不读取该文件；
- 状态目录只能是 `/var/lib/ix-control`；
- 主控 SQLite DSN 必须是该目录下的 `file:` URL，且含 `_journal_mode=WAL` 与正数 `_busy_timeout`，例如概念形式 `file:/var/lib/ix-control/ix-control.db?_busy_timeout=5000&_journal_mode=WAL`。

每个 unit 都包含限制性 systemd 安全选项，例如 `NoNewPrivileges=true`、`ProtectSystem=strict`、私有临时目录与能力边界。渲染后的文本还会拒绝 `--apply-hook`、`sh -c`、`eval` 及直接 `--token` 参数。

本文件刻意只定义模板内容与本地审阅范围，不包含安装、启用、启动或部署说明。

## 本地生成命令

生成器保持现有 `--mode` 兼容，并新增 `--mode systemd-render`。模板始终按稳定的文件名顺序写到标准输出，每段以 `### <unit 文件名>` 分隔，适合本地审阅：

```text
ix-control --mode systemd-render --systemd-role node \
  --node-id node-01 \
  --server wss://control.invalid/v1/ws \
  --token-file /etc/ix-control/node-01.token
```

该示例中的 `.invalid` 是保留的非真实地址，token 文件仅为路径；命令不读取或输出 token。token 文件权限通过 `--systemd-token-file-mode` 明确声明，且只能是默认值 `0600`。

`--systemd-output-dir` 已被明确拒绝。生成器没有任何写入目录功能；如需保留审阅文本，请由本地操作者在命令外自行处理标准输出。本命令不提供任何复制、安装、启用、启动或部署操作。
