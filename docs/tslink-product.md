# Tailscale LinkPilot 产品指南

产品命令 `tslink`，当前版本 `0.8.0-service-controls`。这是与官方 Tailscale 配合的第三方测试程序。

## 安装与选择目标

先登录 Tailscale，并确认两端允许互访。将本机平台的程序放到长期保留的位置，不要从即将删除的临时目录注册服务。

```text
tslink install
tslink connect my-server
```

Linux 协调端可以在首次安装时授权已知客户端：

```text
tslink install --allow my-client
```

已安装的协调端增删授权无需重启：

```text
tslink authorize my-client
tslink revoke my-client
```

默认端口 45829，只绑定本机 Tailnet 地址。HTTP 协调忽略环境代理，每个请求使用官方 WhoIs 验证来源与稳定节点 ID。授权按设备隔离；属于同一个 Tailnet 不等于被本程序授权。

对端缺少部署或授权时，`connect` 会明确报告。拥有自己的 SSH 管理权限且使用完整平台包时，可执行 `tslink connect my-server --ssh user@my-server`。已安装的 Linux 助手优先动态授权；未安装时上传平台程序并登记服务。首次新机器 SSH 部署仍需独立验收。Windows 远端引导和安装邀请未实现；远端 Mac 的首次特权安装需要交互式管理员授权。

## 日常命令

```text
tslink start
tslink stop
tslink restart
tslink status
tslink status --json
tslink optimize my-server
tslink pause my-server
tslink resume my-server
tslink disconnect my-server
tslink doctor
```

`start / stop / restart` 在三个系统上保持相同用法。内部管理已登记的用户后台：Mac 为 LaunchAgent，Windows 为当前用户的计划任务，Linux 为用户 systemd 服务。无需输入系统服务名称。首次安装仍用 `install`，日常服务控制不重新登记、不增加权限；更新二进制位置后重新执行 `install`。

重复 `start` 不打断健康进程。`stop` 确认后台已经停止后才显示离线，保留目标、暂停、排除列表、全节点模式与协调授权；即使原生 Tailscale 离线也可以停止。`restart` 等待旧后台释放进程锁，再等待新版本、相同本机身份的新鲜心跳。旧心跳、仅向系统提交启动请求均不计为启动成功。带有其他配置目录的调用不能控制当前登记的服务。

停止只结束当前运行，安装时的登录自动启动设置保留；下次登录仍自动启动。希望仅暂停自动优化时用 `pause --all`，其选择会持久保留。停止或重启后台可能结束其持有的辅助会话，后续按需求重新确认路径；不会停止原生 Tailscale。

Windows 启停通过官方 Task Scheduler COM 接口，不依赖可能缺失的 ScheduledTasks CIM provider。退出错误保留在 `%APPDATA%\tslink\daemon.log`。Mac 日志在配置目录的 `daemon.log`；Linux 可用 `journalctl --user -u tslink.service` 查看。

`optimize` 请求后台立即执行并等待结果。`pause` 取消优化并清理本机辅助会话，尝试清理对端对应会话；`resume` 仅恢复监测。`disconnect` 删除本机目标和对应本地授权，不自动替对端撤销授权，也不停止原生 Tailscale。

用户配置保存在系统用户配置目录中的 `tslink`：Linux 为 `~/.config/tslink`，Mac 为 `~/Library/Application Support/tslink`，Windows 为 `%APPDATA%\tslink`。配置与状态不保存密码；报告包含实际网络信息，应保留在自己控制的目录。

## 本机全节点模式

```text
tslink connect --all
tslink status
tslink pause my-client
tslink resume my-client
tslink disconnect my-client
tslink pause --all
tslink resume --all
tslink disconnect --all
```

后台每轮同步官方客户端可见节点，以稳定 ID 管理关系；新节点自动纳入，离开可见列表的自动目标被移除，明确选定的目标保留为离线。名称变化不会丢失暂停选择，名称冲突时要求使用节点 ID。

新自动目标没有立即优化请求，也不获得本机入站协调授权。只有实际有需求且持续中继才尝试优化。未部署或未授权显示 `setup_required`，对端缺少配对响应能力显示 `unsupported`，本版 Linux 发起端显示 `responder_only`；已有原生直连仍正常监测。不支持任意两台桌面设备的新会话打洞。

单节点暂停保留在扫描结果中。断开单节点后加入排除列表，重复 `connect --all` 不覆盖；`connect <设备>` 明确重新选择并移出排除列表，沿用单节点命令的本地协调授权行为。全局暂停影响后来发现的节点，全局恢复不会取消单节点暂停。全局断开关闭发现、清空目标和排除列表，保留单独授予的入站协调权限；撤销这类权限仍使用 `revoke`。

`connect --all` 不接受 `--ssh`，不批量部署对端。`optimize --all` 不提供；强制测试请指定单个节点。`status` 分别显示最后检测路径和上次优化验收；当前直连不会覆盖某次优化的失败判据。手动 `optimize` 按对应请求的独立完成结果返回，不把后续一次原生直连探测当作本次成功。最后检测路径可能是空闲前的观测，不能当作实时业务或新打洞验收。

## 自动运行

后台循环每 10 秒启动检查；每轮最多主动探测八个已选择、在线且有近期通信的目标，轮转到其余目标；首次 connect 和立即 optimize 可以主动请求。原生最后通信时间陈旧时，以收发字节增量补充判断。自身探测结束后只更新对应节点的基线，排除自身产生的流量与时间戳，需求窗口为 30 秒。

中继持续至少 20 秒并经三次确认后尝试。先执行支持的原生恢复动作，再搜索最多三个新会话，单轮预算 180 秒。已有直连时保持观察；失败按 1、5、15 分钟退避。网卡地址快照变化清除旧网络需求、确认和退避。

双方原生路径、三次 64 KiB 数据往返和承载计数全部通过才记录成功。辅助会话默认保留 30 分钟；只有有通信需求、双方原生路径匹配各自辅助会话时才续期。失效会话不会被续活。身份改变时暂停，旧授权不会自动迁移。

健康心跳独立于长优化任务。客户端重打洞任务串行执行，其他目标继续监测与按需续期；待处理的手动请求只有实际被选中时才消费。暂停、断开或换网取消当前任务。每个节点的策略、报告和本地辅助会话独立，最多保留十六个本地会话；达到上限保留已有会话，不进行隐式驱逐。旧单会话 worker 可继续被识别，无需为升级停止。Linux 响应端按授权设备隔离多个会话。

## Mac 权限

首次 `install` 需要一次管理员授权。程序复制 root 持有的 `/Library/PrivilegedHelperTools/net.tslink.capture`，并写入当前用户专用 `/private/etc/sudoers.d/tslink-capture-<UID>`。持久授权只允许该助手的固定 `capture-helper` 命令，禁止附加参数和其他子命令。

助手只接受本机物理网卡地址、指定公开发现密钥与最多十二个候选。过滤器由程序固定生成，匹配探测包标记及双方发现密钥，排除业务包。不接受调用者自定义命令、文件路径或过滤器；一次最多 180 秒、4096 个包，同时最多一个采集任务。tcpdump 打开设备后降为调用用户，后台和 UDP 会话也由普通用户持有。

用户 LaunchAgent `net.tslink.agent` 在登录后运行；需要保持登录和唤醒，关闭终端不影响运行。入口为 `~/bin/tslink`，登录 shell 增加该目录，新开终端生效。更新程序后重新执行 install 会更新助手。

## Windows 与 Linux 权限

Windows install 需要管理员权限。计划任务 **Tailscale LinkPilot** 在当前用户登录时启动，使用其现有管理员令牌，不保存密码；后台任务要求用户保持登录。只为产品端口添加限定 Tailnet 来源的防火墙规则。短命令放到用户 bin 并加入 PATH，新开终端生效。

Linux 使用用户 systemd 服务 `tslink.service`。当前版本由桌面端发起新会话，Linux 承担响应端。如果该系统不允许普通用户执行官方 restun，需要管理员单独授予 `/usr/bin/tailscale debug restun` 固定权限，再使用 install 的 `--sudo-restun`；本程序不会替管理员创建这项 Linux 授权。无人登录时是否运行依赖当地用户管理器设置。

## 当前边界与卸载

新会话优化要求 Linux 响应端具有公网物理 IPv4。任意 NAT 响应端、双桌面角色选举、手机端、Windows ARM64、原生 IPv6 新会话及图形安装器未实现。长期运行、整机重启、实际睡眠唤醒和新网络自动恢复需要更多现场验收。

卸载前先 disconnect 已选择的目标。

- Linux：`systemctl --user disable --now tslink.service`，再删除本程序的用户 unit、二进制和配置目录。
- Windows：在管理员 PowerShell 停止并删除 **Tailscale LinkPilot** 计划任务及 **Tailscale LinkPilot coordination** 规则，再删除二进制、用户 bin 入口和配置目录。
- Mac：`launchctl bootout gui/$(id -u)/net.tslink.agent`，删除其 LaunchAgent、用户 bin 入口和配置目录；管理员删除当前 UID 的固定 sudoers 规则。最后一个用户卸载后删除 root 助手及其 `.lock`，仅移除 shell 配置中标注本程序的 PATH 行。

卸载本程序不会卸载原生 Tailscale。测试覆盖见[验收记录](validation.md)。
