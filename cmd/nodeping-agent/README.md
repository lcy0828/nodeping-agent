# NodePing Agent

NodePing Agent 是独立探针进程，负责注册节点、心跳、上报出口公网 IP，并通过 SSE 接收后端任务。当前支持 ICMP Ping、TCP Ping、长 Ping、长 TCP、UDP 探测、HTTP、HTTP/3 请求检测、DNS 解析、DNS 对比、TLS 证书、traceroute、MTR、节点状态和公网 IP 检测能力。

## 配置

必填：

- `NODEPING_SERVER_URL`：后端公网地址。
- `NODEPING_TOKEN`：创建探针时生成的绑定 token，仅用于首次绑定和心跳绑定校验。

常用可选项：

- `NODEPING_AGENT_ID`：稳定探针 ID，一台机器或一个容器使用一个 ID。默认自动生成 `agent-<uuid-v4>` 不透明 ID，并保存到状态目录；不要用 hostname 当 ID。旧版本留下的 hostname ID 会在本机已有长期 agent token 时自动迁移为 UUID，并在注册成功后写入状态目录。
- `NODEPING_AGENT_NAME`：展示名称，默认使用 hostname，可在页面上改成更容易识别的名称。
- `NODEPING_AGENT_TOKEN_FILE`：后端返回的 agent token 存储位置，默认是用户配置目录。
- `NODEPING_AGENT_RELEASE_PROXY_FILE`：后端下发的 GitHub Release 代理目录，Linux 默认 `/var/lib/nodeping-agent/release-proxies.tsv`。
- `NODEPING_AGENT_LATEST_VERSION_FILE`：后端缓存的最新版本号，Linux 默认 `/var/lib/nodeping-agent/latest-version`；自动更新优先读取它，缺失或非法时才访问 GitHub API。
- `NODEPING_CONCURRENCY`：连接旧版后端时使用的本地回退并发，默认 `10`。当前后端会在每个任务中下发探针管理页面的实时并发设置；旧安装遗留的 `1-9` 会迁移为 `10`，实际并发统一由后台控制。
- `NODEPING_AGENT_ALLOW_INSECURE_HTTP`：开发环境显式设为 `true` 后，允许 `NODEPING_SERVER_URL` 使用非回环 HTTP 地址。默认 `false`；只影响控制面地址，发布包和代理下载地址仍要求 HTTPS。

`NODEPING_AGENT_TOKEN` 是后端注册后返回的长期 agent token。生产环境推荐写入 `NODEPING_AGENT_TOKEN_FILE`，不要明文放进命令行历史。

## 本地运行

```bash
NODEPING_SERVER_URL='https://your-nodeping.example' \
NODEPING_TOKEN='np_xxx' \
go run ./cmd/nodeping-agent
```

局域网开发后端使用 HTTP 时：

```bash
NODEPING_SERVER_URL='http://192.168.2.28:8099' \
NODEPING_TOKEN='np_xxx' \
NODEPING_AGENT_ALLOW_INSECURE_HTTP=true \
go run ./cmd/nodeping-agent
```

查看版本：

```bash
nodeping-agent -version
```

自检：

```bash
NODEPING_SERVER_URL='https://your-nodeping.example' \
NODEPING_TOKEN='np_xxx' \
nodeping-agent doctor
```

`doctor` 会检查配置、token 文件读写、系统 `ping`、DNS、公网 IP 和后端 `/healthz` 可达性。

## 构建独立安装包

```bash
VERSION=0.1.0 ./scripts/build-nodeping-agent.sh
```

默认生成：

- `linux/amd64`
- `linux/arm64`
- `darwin/amd64`
- `darwin/arm64`

产物目录：

```text
dist/nodeping-agent/0.1.0/
```

发布到静态下载地址时，需要保留同一目录下的：

- `nodeping-agent_0.1.0_checksums.txt`
- `nodeping-agent_0.1.0_linux_amd64.tar.gz`
- `nodeping-agent_0.1.0_linux_arm64.tar.gz`

GitHub Releases 的 Assets 需要上传各平台 `tar.gz`、对应的 `.minisig` 和 `nodeping-agent_<version>_checksums.txt`。`install-release.sh`、`install-docker.sh`、`compose.yml` 和更新脚本默认由后端固定版本镜像内的只读下载路由提供，不再执行仓库浮动分支脚本。

## systemd 安装

默认安装到 `/opt/nodeping-agent/nodeping-agent`，配置保存在 `/etc/nodeping-agent`，运行状态和长期 agent token 保存在 `/var/lib/nodeping-agent`。

使用仓库最新安装脚本一键安装最新版：

```bash
curl -fsSL https://hub.ilatency.com/https://raw.githubusercontent.com/lcy0828/nodeping-agent/main/deploy/nodeping-agent/install-release.sh \
  | sudo env NODEPING_SERVER_URL='https://your-nodeping.example' NODEPING_TOKEN='np_xxx' NODEPING_AGENT_DISTRIBUTION_MODE='cn' bash
```

使用最新安装脚本安装指定 Agent 版本：

```bash
curl -fsSL https://hub.ilatency.com/https://raw.githubusercontent.com/lcy0828/nodeping-agent/main/deploy/nodeping-agent/install-release.sh \
  | sudo env NODEPING_SERVER_URL='https://your-nodeping.example' NODEPING_TOKEN='np_xxx' NODEPING_AGENT_DISTRIBUTION_MODE='cn' NODEPING_AGENT_VERSION='v0.0.1' bash
```

解压 Linux 包后执行：

```bash
tar -xzf nodeping-agent_0.1.0_linux_amd64.tar.gz
cd nodeping-agent
sudo ./install-systemd.sh
```

安装脚本会预检 `systemctl`、`ping`、`curl/wget`、`tar` 等依赖；重复安装会打印当前版本和将要安装的版本。`cn` 模式代理优先、GitHub 回退，`global` 模式 GitHub 优先、代理回退。配置完整时，启动服务后会自动执行一次 `nodeping-agent doctor`。

编辑配置：

```bash
sudo nano /etc/nodeping-agent/nodeping-agent.env
sudo systemctl restart nodeping-agent
```

日志：

```bash
journalctl -u nodeping-agent -f
```

卸载：

```bash
sudo /etc/nodeping-agent/uninstall-systemd.sh
```

默认保留 `/etc/nodeping-agent` 和 `/var/lib/nodeping-agent`。如需同时删除配置和 token 状态：

```bash
sudo REMOVE_CONFIG=1 REMOVE_STATE=1 /etc/nodeping-agent/uninstall-systemd.sh
```

## 自动升级

默认自动升级从 GitHub Releases 解析最新 tag，并下载对应的 checksums 和 tar.gz：

```text
https://github.com/lcy0828/nodeping-agent/releases/download/v0.1.0/nodeping-agent_v0.1.0_checksums.txt
https://github.com/lcy0828/nodeping-agent/releases/download/v0.1.0/nodeping-agent_v0.1.0_linux_amd64.tar.gz
```

自建下载源时，编辑：

```bash
sudo nano /etc/nodeping-agent/nodeping-agent-update.env
sudo systemctl enable --now nodeping-agent-update.timer
```

默认每天 10:00 检查一次，并带 30 分钟随机延迟。更新脚本会先解析 `latest` 对应的 GitHub Release tag，再校验 SHA256，安装新二进制，然后重启 `nodeping-agent.service`。

升级前会备份当前二进制到 `/opt/nodeping-agent/nodeping-agent.previous`。如果新版本安装后 systemd 服务没有在超时时间内恢复 active，脚本会自动回滚上一版并重启。

可选 minisign 签名校验：

```bash
NODEPING_AGENT_MINISIGN_PUBLIC_KEY='RWQ...' \
NODEPING_AGENT_REQUIRE_SIGNATURE=auto \
sudo -E nodeping-agent-update
```

启用后发布目录需要同时提供 tar 包、checksums 和 manifest 的签名：

```text
nodeping-agent_0.1.0_linux_amd64.tar.gz.minisig
nodeping-agent_0.1.0_checksums.txt.minisig
nodeping-agent_0.1.0_manifest.json.minisig
```

## Docker

国内节点使用脚本安装：

```bash
curl -fsSL https://hub.ilatency.com/https://raw.githubusercontent.com/lcy0828/nodeping-agent/main/deploy/nodeping-agent/install-docker.sh \
  | sudo env NODEPING_SERVER_URL='https://your-nodeping.example' NODEPING_TOKEN='np_xxx' NODEPING_AGENT_DISTRIBUTION_MODE='cn' bash
```

海外节点将分发模式改为 `global`。脚本会以 `0600` 创建 `.env`，主镜像拉取失败时自动尝试另一镜像源。

本地开发也可以手动启动：

```bash
IMAGE=ghcr.io/lcy0828/nodeping-agent VERSION=0.1.0 ./scripts/build-nodeping-agent-image.sh
cd deploy/nodeping-agent
cp docker.env.example .env
docker compose --env-file .env up -d
```

容器需要 `NET_RAW` 能力来执行 ICMP ping 和 MTR。Compose 以 root 启动 Agent，但会丢弃除 `NET_RAW` 外的全部 capability，并保留只读根文件系统和 `no-new-privileges`。Docker init 负责回收 MTR 超时或取消后退出的辅助进程；任务并发由 Agent 自身控制，不再叠加容易阻断探测的容器 PID、CPU 或内存硬限制。

发布镜像：

```bash
IMAGE=ghcr.io/lcy0828/nodeping-agent VERSION=0.1.0 PUSH=1 PLATFORMS=linux/amd64,linux/arm64 ./scripts/build-nodeping-agent-image.sh
```

Docker 日常升级在容器内部完成，不依赖宿主机的 systemd、procd 或其他 init 系统，也不会挂载 Docker Socket。Agent 下载并校验发布包后，把新二进制原子写入容器 `/opt/nodeping-agent/nodeping-agent`；该目录默认映射到宿主机 `/opt/nodeping-agent/runtime`。升级任务结果成功上报后 Agent 优雅退出，镜像内 supervisor 启动候选版本；候选版本未通过稳定窗口时自动恢复 `nodeping-agent.previous`，两者都不可用时回退到镜像内基础版本。

身份、长期 token 和 DNS 状态继续保存在宿主机 `/opt/nodeping-agent/data`，只在容器内映射为 `/var/lib/nodeping-agent`；安装器不会把宿主机数据迁回 `/var/lib/nodeping-agent`。宿主机 `/opt/nodeping-agent/update-docker.sh` 仅用于刷新基础镜像和默认 Compose，例如更新 Alpine、CA、ping、traceroute 或 MTR；它不再是控制台日常 Agent 升级链路。自定义 Compose 不会被覆盖。如果要在宿主机从源码重建，需要让 `COMPOSE_FILE` 指向带 `build:` 的自定义 Compose 文件，再设置 `NODEPING_AGENT_DOCKER_BUILD=1`。

远端部署只拉镜像时，使用 `compose.yml`：

```bash
mkdir -p /opt/nodeping-agent
cd /opt/nodeping-agent
docker compose --env-file .env up -d
```
