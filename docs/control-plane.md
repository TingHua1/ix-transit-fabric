# 无 UI 控制面（实验性）

`ix-control` 是 `ix-transit-fabric` 的可选最小控制面：一个 Go 二进制，主控使用 SQLite，节点通过**主动发起**的 WebSocket 长连接上报规则流量并接收结构化命令。

它不替换当前 `ix` 脚本，也不会自动修改 EasyTier、nftables 或转发规则。先完成统计/控制面验证，再单独实现并审阅节点侧 nftables 适配器。

## 范围

- 节点身份校验：每节点独立 ID + token。
- 规则级双向流量增量上报：`rule_id`、上行字节、下行字节、单规则序号。
- SQLite 幂等账本：`(node_id, rule_id, sequence)` 唯一，断线重发不会重复累计。
- 命令队列与回执：命令仅按节点投递并记录 `pending/done/failed`。
- 本地执行边界：主控不能下发 shell。节点只会运行由节点管理员本地预配置的单一 `--apply-hook`，命令 JSON 通过标准输入交给该 hook。

尚未实现：用户/套餐 UI、配额判定器、nftables 双向计数采集器、`tc` 限速适配器、TLS/mTLS、自动注册。这些应分阶段加入，不能用通用远程执行代替。

## 构建

```bash
go build -trimpath -ldflags='-s -w' -o ix-control ./cmd/ix-control
```

本机验证：

```bash
go test -v ./cmd/ix-control
go vet ./...
```

## 主控启动

先只绑定回环地址；在反向代理或 VPN 后验证 TLS 和认证策略后再开放。

```bash
./ix-control --mode server \
  --listen 127.0.0.1:8787 \
  --db /var/lib/ix-control/ix-control.db
```

健康检查：

```bash
curl http://127.0.0.1:8787/healthz
```

首次使用时，在主控 SQLite 中预先创建每台节点记录。Token 必须从安全来源生成，且不得写入仓库、日志或 shell 历史。

```sql
INSERT INTO nodes(node_id, token, enabled) VALUES ('soy-ix', '[REDACTED]', 1);
INSERT INTO nodes(node_id, token, enabled) VALUES ('aliyun-sz', '[REDACTED]', 1);
```

## 节点启动

节点仅向主控发起连接，不需要开放额外管理端口：

```bash
./ix-control --mode agent \
  --server wss://control.example.invalid/v1/ws \
  --node-id soy-ix \
  --token-file /etc/ix-control/token \
  --usage-file /var/lib/ix-control/usage.ndjson
```

当前最小版本的 token 参数为 `--token`。生产部署应由 systemd `EnvironmentFile=` 提供 token，权限必须为 `0600`；避免把 token 写在 unit 的公开命令行中。`--token-file` 是后续改进项，暂不应假定可用。

`usage.ndjson` 中每行是一个尚未确认的增量：

```json
{"node_id":"soy-ix","rule_id":"rule-main","sequence":1,"up_bytes":1234,"down_bytes":5678,"at":1760000000}
```

主控确认后，Agent 会删除该条记录；连接中断时保留并重试。采集器应只追加增量，并为每个 `(node_id, rule_id)` 保持单调递增的 `sequence`。

## 命令安全模型

节点默认不执行收到的命令，而会回执失败：`no local apply hook configured`。

只有部署者显式配置一条绝对路径的本地 hook 后，Agent 才执行它：

```bash
--apply-hook /usr/local/libexec/ix-control/apply-command
```

该 hook 必须自行白名单命令类型（例如 `enable_rule`、`disable_rule`、`apply_ruleset`），严格验证 JSON schema、规则 ID 和端口范围；禁止调用 `eval`、`sh -c` 或执行主控提供的字符串。
