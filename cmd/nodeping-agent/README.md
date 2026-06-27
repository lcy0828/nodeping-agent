# NodePing Agent

NodePing Agent 是独立探针进程，负责注册节点、心跳、上报出口公网 IP，并通过 SSE 接收后端任务。当前支持 ICMP Ping、TCP Ping、长 Ping、长 TCP、UDP 探测、HTTP、HTTP/3 请求检测、DNS 解析、DNS 对比、TLS 证书、traceroute、MTR、节点状态和公网 IP 检测能力。

## 配置

必填：

- `NODEPING_SERVER_URL`：后端公网地址。
- `NODEPING_TOKEN`：创建探针时生成的绑定 token，仅用于首次绑定和心跳绑定校验。

常用可选项：

- `NODEPING_AGENT_ID`：稳定探针 ID，一台机器或一个容器使用一个 ID。
- `NODEPING_AGENT_NAME`：展示名称。
- `NODEPING_AGENT_TOKEN_FILE`：后端返回的 agent token 存储位置，默认是用户配置目录。
- `NODEPING_CONCURRENCY`：并发任务数，默认 `3`。

`NODEPING_AGENT_TOKEN` 是后端注册后返回的长期 agent token。生产环境推荐写入 `NODEPING_AGENT_TOKEN_FILE`，不要明文放进命令行历史。

## 本地运行

```bash
NODEPING_SERVER_URL='https://your-nodeping.example' \
NODEPING_TOKEN='np_xxx' \
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

GitHub Releases 的 Assets 只需要上传各平台 `tar.gz` 和 `nodeping-agent_<version>_checksums.txt`。安装脚本、`compose.yml`、`docker.env.example`、`update-docker.sh` 默认从仓库 `main` 分支的 `deploy/nodeping-agent` 目录下载。

## systemd 安装

默认安装到 `/opt/nodeping-agent/nodeping-agent`，配置保存在 `/etc/nodeping-agent`，运行状态和长期 agent token 保存在 `/var/lib/nodeping-agent`。

使用仓库最新安装脚本一键安装最新版：

```bash
curl -fsSL https://raw.githubusercontent.com/lcy0828/nodeping-agent/main/deploy/nodeping-agent/install-release.sh \
  | sudo env NODEPING_SERVER_URL='https://your-nodeping.example' NODEPING_TOKEN='np_xxx' bash
```

使用最新安装脚本安装指定 Agent 版本：

```bash
curl -fsSL https://raw.githubusercontent.com/lcy0828/nodeping-agent/main/deploy/nodeping-agent/install-release.sh \
  | sudo env NODEPING_SERVER_URL='https://your-nodeping.example' NODEPING_TOKEN='np_xxx' NODEPING_AGENT_VERSION='v0.0.1' bash
```

解压 Linux 包后执行：

```bash
tar -xzf nodeping-agent_0.1.0_linux_amd64.tar.gz
cd nodeping-agent
sudo ./install-systemd.sh
```

安装脚本会预检 `systemctl`、`ping`、`curl/wget`、`tar` 等依赖；重复安装会打印当前版本和将要安装的版本。配置完整时，启动服务后会自动执行一次 `nodeping-agent doctor`。

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

启用后发布目录需要同时提供：

```text
nodeping-agent_0.1.0_linux_amd64.tar.gz.minisig
```

## Docker

```bash
IMAGE=ghcr.io/lcy0828/nodeping-agent VERSION=0.1.0 ./scripts/build-nodeping-agent-image.sh
cd deploy/nodeping-agent
cp docker.env.example .env
docker compose --env-file .env up -d
```

容器需要 `NET_RAW` 能力来执行 ICMP ping；Compose 文件已包含 `cap_add: NET_RAW`。

发布镜像：

```bash
IMAGE=ghcr.io/lcy0828/nodeping-agent VERSION=0.1.0 PUSH=1 PLATFORMS=linux/amd64,linux/arm64 ./scripts/build-nodeping-agent-image.sh
```

Docker 部署自动升级可以把 `deploy/nodeping-agent/update-docker.sh` 放到宿主机定时执行。它默认 `docker compose pull && docker compose up -d`。如果要在宿主机从源码重建，需要让 `COMPOSE_FILE` 指向带 `build:` 的自定义 Compose 文件，再设置 `NODEPING_AGENT_DOCKER_BUILD=1`。

远端部署只拉镜像时，使用 `compose.yml`：

```bash
mkdir -p /opt/nodeping-agent
cd /opt/nodeping-agent
docker compose --env-file .env up -d
```
