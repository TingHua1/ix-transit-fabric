# OpenCode 本地开发交接

仓库：`TingHua1/ix-transit-fabric`  
分支：`feat/control-plane-go-sqlite-ws`

## 约束

OpenCode **只能进行本地代码开发、单元测试和本机隔离验证**：

- 不得 SSH、SCP、部署或修改 HK04、HK05、阿里深圳、SOY IX 或任何远端服务器。
- 不得假定拥有远端凭据、Token、私钥或服务连接信息。
- 不得修改现有生产网络、EasyTier、nftables、systemd 配置。
- 远端部署、真实链路验证和清理由具备远端执行权限的独立流程完成。

## 现有实现

代码在 `cmd/ix-control/`，当前已具备：

- Go 单二进制、SQLite、节点主动 WebSocket 通信；
- 节点 Token 认证、usage 增量幂等入账、命令回执；
- 结构化 `apply_ruleset`；禁止主控传递任意 shell；
- 专属 `table ip ix_control_plane_v1` 的 DNAT/MASQUERADE 和 TCP/UDP 双向 conntrack 计数；
- 计数增量采集、首采基线避免误计历史流量；
- 用户启用、到期、总配额、计费方向；
- 节点 ruleset 状态文件持久化与 restore 模式；
- reconcile：按用户状态重算并按节点下发完整 ruleset。

当前代码已经通过：

```bash
go test ./cmd/ix-control
go vet ./...
go build -trimpath -ldflags='-s -w' -o /tmp/ix-control ./cmd/ix-control
```

## 下一项：双节点 Link 编排

实现一个用户可见的 `Link` / `Forward` 模型，描述：

```text
客户端
→ ingress 节点（阿里深圳）
→ EasyTier 虚拟网
→ transit 节点（SOY IX）
→ landing 服务器
```

字段：

```text
id
user_id
enabled
protocol: tcp | udp | both
client_port
ingress_node_id
ingress_public_ip（可选）
transit_node_id
transit_easy_ip
transit_port
landing_ip
landing_port
description
```

规则展开必须按节点聚合：

```text
transit ruleset：
  transit_easy_ip:transit_port → landing_ip:landing_port

ingress ruleset：
  client_port → transit_easy_ip:transit_port
```

禁止每条 Link 独立覆盖节点完整 ruleset。必须汇总一个节点的全部活动 Link 后再生成一个完整 ruleset。

### 本地实现要求

1. 添加 SQLite schema、Go 数据模型和 CLI/admin 操作。
2. 添加纯内存 SQLite 单元测试：
   - 一个节点多个 Link 时完整 ruleset 包含全部活动规则；
   - 到期、禁用、配额耗尽的用户不生成规则；
   - transit 规则先于 ingress 规则排队；
   - 同协议端口冲突被拒绝；
   - Link 更新/删除后不会保留旧规则。
3. 不实现任何远端调用。
4. 不引入通用 exec、shell 字符串、`eval`、`sh -c`。

## 后续本地开发顺序

1. Link 双节点编排与聚合 ruleset。
2. ruleset version/hash：节点 hello 上报已应用版本，主控发现不一致后排队全量同步。
3. systemd unit 模板生成：仅写模板和文档，不在本地/远端启用服务。
4. 节点健康上报协议：EasyTier 状态、tun0、规则版本、collector 时间；只实现数据结构和解析测试。
5. 无 UI CLI：用户、节点、Link、流量、命令、健康、备份恢复。
6. TLS/WSS 部署文档和 Caddy 示例；不部署。
7. 备份/恢复脚本与测试。

## 安全约束

- 永远只渲染/操作 `table ip ix_control_plane_v1`。
- 禁止 `flush ruleset`。
- 禁止操作 `table ip ix_transit_fabric`、`/etc/nftables.d/ix-transit-fabric.nft` 或现有 Docker/x-ui/Caddy 规则。
- Token、密码、私钥、EasyTier secret 不得写入代码、fixture、文档示例或 Git。
- token 配置必须假定来自权限 `0600` 的文件。
- nftables 规则必须先 `nft -c` 验证；应用失败不得删除现有专属表。

## 完成门槛

每个功能完成前运行：

```bash
gofmt -w cmd/ix-control/*.go
go test ./...
go vet ./...
go build -trimpath -ldflags='-s -w' -o /tmp/ix-control ./cmd/ix-control
git diff --check
```

不要声称完成远端部署或真实转发验证。需要远端执行时，只输出明确、可审阅的部署计划和验证清单。
