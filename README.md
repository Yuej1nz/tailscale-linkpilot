# Tailscale LinkPilot

适用于 Tailscale 的第三方跨平台直连优化工具，命令为 **`tslink`**。当前版本 `0.6.0-macos-agent`，处于早期测试阶段。

两端已经加入 Tailscale 后，安装一次后台程序、选择目标。后台在有通信需求且连续确认中继时，尝试恢复直连；已有直连时保持观察。失败会退避，原生 Tailscale 仍可使用中继。

```text
tslink install
tslink connect my-server
tslink status
```

这是一套与官方客户端配合的独立程序，没有修改官方 Tailscale。当前新会话优化支持 **macOS / Windows 客户端 → 具有公网物理 IPv4 的 Linux 协调端**，不保证所有 NAT 和网络都能直连。

## 平台支持

| 平台 | 角色 | 验证范围 |
| --- | --- | --- |
| macOS arm64 | 客户端、用户 LaunchAgent、受限采集助手 | 实机完成中继到新 IPv4 直连、三次业务校验、后台重启和续期 |
| Windows amd64 | 客户端、用户登录时启动的计划任务 | 实机完成自动中继恢复、业务校验和辅助会话保留 |
| Linux amd64 | 按授权设备隔离的协调响应端、用户 systemd 服务 | 实机与两种客户端配合 |
| macOS amd64、Linux arm64 | 对应平台角色 | 仅交叉构建验证 |

Windows ARM64、手机端、任意 NAT 之间的双桌面响应、原生 IPv6 新会话打洞尚未实现。Mac / Windows 需要用户保持登录，机器保持唤醒；Linux 用户服务依赖用户管理器。长时间运行、整机重启和睡眠唤醒仍需进一步验收。

## 使用

先确保 Tailscale 已登录，设备之间允许互访。选择自己的节点名称，不复制历史实验的地址。

```text
tslink status
tslink optimize my-server
tslink pause my-server
tslink resume my-server
tslink disconnect my-server
tslink doctor
```

`optimize` 请求后台立即执行；`resume` 恢复自动监测。日常无需重复输入完整优化参数。

对端已有程序时，需要明确授权本机：

```text
# 在 Linux 协调端执行；my-client 是客户端的真实节点名。
tslink install --allow my-client
# 在客户端执行。
tslink connect my-server
```

有自己的 SSH 管理权限时，可以尝试从客户端部署或授权 Linux 对端：

```text
tslink connect my-server --ssh user@my-server
```

SSH 引导需要完整平台包和已可用的登录权限。Windows 远端引导、安装邀请和远程 Mac 的首次交互式管理员授权尚未实现。普通 Tailnet 成员身份不会自动获得本程序的协调权限。

Mac 首次 install 请求管理员授权，安装 root 持有的固定采集助手，并仅授权其 `capture-helper` 命令。后台和 UDP 会话仍以普通用户运行，不保存密码。Windows 首次 install 需要管理员权限，使用当前登录用户的管理员令牌注册任务。具体权限和卸载方式见[产品指南](docs/tslink-product.md)。

## 怎样判断成功

后台先调用官方恢复能力，再在支持的组合上搜索最多三个新 UDP 会话。候选来自当前原生节点信息、网卡和同 socket 的新鲜 STUN 观测，不使用写死的公网地址或成功端口。

只有 UDP 往返预验证、两端原生身份及路径验证、三次 64 KiB 业务往返和两端承载计数全部通过，才记录新会话优化成功。UDP 可达、中继仍能传数据、已有直连被保留，都与新打洞成功分别记录。

- 默认每轮最多 180 秒；禁止后台重启原生 Tailscale 或重新绑定其 socket。
- 中继持续至少 20 秒并经三次确认后尝试，失败按 1 / 5 / 15 分钟退避。
- 有效辅助会话默认保留 30 分钟；有需求且双向路径匹配时才续期。
- 暂停、删除目标、身份或网络改变会取消或清理相应任务。

Tailscale 隧道内部访问成功，不代表原生公网 IPv6 SSH 已可达。

## 源码构建与检查

Go 模块依赖固定为 `tailscale.com v1.102.4`，工具链固定为 Go 1.26.6。在 Linux / macOS 构建环境中准备 Go 1.21 或更高版本及 Python 3：

```sh
./scripts/go mod download
./scripts/check
./scripts/build
python3 scripts/package.py
```

构建输出覆盖 Linux amd64 / arm64、Windows amd64、macOS amd64 / arm64，包含 `tslink`、兼容诊断工具 `ts-direct` 及 SHA256 清单；平台包放在 `dist/`。`scripts/go` 将固定工具链缓存放在项目的 `toolchains/`，不替换系统 Go。

Windows 原生开发环境可以使用 Go 1.26.6：

```powershell
go test ./...
go build -o tslink.exe ./cmd/tslink
```

GitHub Actions 执行竞态检查、静态检查和五个平台构建；构建成功与真实 NAT 的现场成功分别记录。

## 文档

- [产品操作、权限和卸载](docs/tslink-product.md)
- [实现架构与后续范围](docs/implementation-plan.md)
- [验收范围与已知限制](docs/validation.md)
- [对照实验规程](docs/experiment-protocol.md)

公开仓库中的测试使用合成身份及示例地址。实际部署配置、账号、密钥、原始报告与抓包保留在本机，不进入版本管理。`ts-direct` 保留诊断和手动兼容接口；新的后台产品入口使用 `tslink`。
