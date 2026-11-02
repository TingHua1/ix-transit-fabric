# ix-control 节点本地网络 CLI

`ix-control node-network` 是节点管理员在**本机**审阅和操作 EasyTier 本地声明的入口。它不连接主控、不输出或持久化网络密钥内容、不解析或访问 peer/listener 地址，也不执行 `systemctl`、`easytier`、`ip`、`nft` 或任何网络命令；本地 validator 仅为核对 EnvironmentFile 变量契约而读取该文件。

主控仅接收脱敏状态；不会读取节点网络密钥、配置中的密钥路径或 endpoint。

## 本地配置占位示例

以下是字段形状示例，所有值均为占位符，不能直接用于任何网络：

```json
{
  "schema_version": 1,
  "service_name": "SERVICE_NAME_PLACEHOLDER",
  "binary_path": "/usr/local/libexec/ix-control/easytier-core",
  "network_name": "NETWORK_NAME_PLACEHOLDER",
  "network_secret_file": "/etc/ix-control/NETWORK_SECRET_FILE_PLACEHOLDER",
  "hostname": "node-placeholder.invalid",
  "ipv4": "10.44.0.0/24",
  "transport": "tcp",
  "listeners": ["tcp://127.0.0.1:PORT_PLACEHOLDER"],
  "peers": [],
  "no_listener": false,
  "state_dir": "/var/lib/ix-control/easytier"
}
```

配置文件路径固定为 `/etc/ix-control/node-network.json`，必须是本地普通非符号链接文件、权限严格为 `0600`（Unix 上归属 root），并在使用前通过严格 JSON 解析。`network_secret_file` 必须位于 `/etc/ix-control/`、`binary_path` 必须位于 `/usr/local/libexec/ix-control/`、`state_dir` 必须位于 `/var/lib/ix-control/easytier/`；文件及所有已存在的父目录均须由 root 拥有、不得是符号链接、且不得对组或其他用户可写。密钥文件本身必须为 root 所有的 `0600` 文件。本地 validator 会读取该文件但绝不输出或保存其内容，并严格要求文件**恰好**为单行 `ET_NETWORK_SECRET=<非空值>`：不得有其他变量、空白、控制字符或换行。除上述 validator 契约核对外，CLI、渲染器和 agent 状态上报均不读取、输出或放入 argv。

## EasyTier unit 契约

渲染的 unit 不会把 ix-control JSON 交给 EasyTier，也不会使用 `--config-file`。受支持的是管理员已在本机审阅、其 CLI `--help` 明确提供以下参数的 EasyTier 官方 release 版本：`--network-name`、`--hostname`、`--ipv4`、重复的 `--listeners` 与 `--peers`、条件性的 `--no-listener`，以及 `--state-dir`。本模块不固定、探测或宣称未经该审阅的 EasyTier 版本；严格声明中的这些字段逐项渲染为固定结构 argv，`service_name` 仅用于 unit 描述，unit 文件名固定为 `ix-control-easytier.service`。本地质量检查不会执行 artifact 或启动/测试服务。

## 本地审阅顺序

1. 管理员从 EasyTier **官方 release** 在本机手动下载 artifact，并在本机核对其 SHA-256。安装器在 Unix 上以 no-follow 描述符打开源文件并从该描述符完成哈希和暂存；符号链接源会被拒绝。不要把下载 URL、密钥或 endpoint 写入主控或本文件。
2. 严格检查本地声明：
   ```text
   ix-control node-network validate --config /etc/ix-control/node-network.json --json
   ```
3. 只渲染 unit 到标准输出并进行本地审阅：
   ```text
   ix-control node-network render-systemd --config /etc/ix-control/node-network.json
   ```
4. 在本机将已核验 artifact 安装到固定位置：
   ```text
   ix-control node-network install-local --config /etc/ix-control/node-network.json --artifact /LOCAL/ARTIFACT_PLACEHOLDER --sha256 LOWERCASE_SHA256_PLACEHOLDER --json
   ```
5. 先查看 apply 计划；它仅输出 dry-run JSON，不写 unit、不会 reload 或 restart 服务：
   ```text
   ix-control node-network apply-local --config /etc/ix-control/node-network.json --json
   ```

兼容现有调用方式时，使用 `--mode node-network --node-network-action ... --node-network-config ...`；`--artifact`、`--sha256` 与 `--json` 含义相同。

## 隔离、状态与回滚

`status` 只输出脱敏 JSON，配置路径同样固定（未指定时状态为 `unknown`），状态为 `unknown`（未采集）或 `config_rejected`（本地声明未通过）；它不探测服务或接口。此模块不选择、附着或接管既有网络接口（包括 `tun0`）。`stop` 与 `uninstall` 也只生成 dry-run 计划，绝不会调用 systemd 或删除文件。

隔离时先停止采用任何经审阅 unit 的人工本地操作，再使用 `stop` 审阅预期动作。artifact 与 metadata **不是原子 pair 替换**：在任何 rename 前，安装会 fsync 持久事务 intention journal（包含目标、备份路径和原文件存在标记），随后逐项备份并记录 phase；只有 commit marker 持久化后新 pair 才生效。下一次安装会在操作前恢复未提交事务中实际存在的备份（包括第一次备份后崩溃的窗口），或完成已提交事务的清理；恢复失败会明确报告每个组件的实际状态。公开安装 API 仅为 `InstallNodeNetworkArtifact(config, source, sha256)`：它从固定 `binary_path + .metadata.json` 派生 metadata，并在写入前使用 OS inspector 验证配置、固定前缀和可信目录链。`uninstall` 仅用于查看可逆动作清单。该文档不提供远端部署或远程执行说明。
