# NodePing Agent

Standalone NodePing probe agent.

## Build

```bash
go test ./...
VERSION=0.1.0 ./scripts/build-nodeping-agent.sh
```

## Linux Install

The release installer installs the binary to:

```text
/opt/nodeping-agent/nodeping-agent
```

Configuration is stored in `/etc/nodeping-agent`, and runtime state is stored in
`/var/lib/nodeping-agent`.

Install from GitHub Releases:

```bash
curl -fsSL https://github.com/lcy0828/nodeping-agent/releases/latest/download/install-release.sh \
  | sudo env NODEPING_SERVER_URL='https://your-nodeping.example' NODEPING_TOKEN='np_xxx' bash
```

Install a pinned version:

```bash
curl -fsSL https://github.com/lcy0828/nodeping-agent/releases/download/v0.0.1/install-release.sh \
  | sudo env NODEPING_SERVER_URL='https://your-nodeping.example' NODEPING_TOKEN='np_xxx' NODEPING_AGENT_VERSION='v0.0.1' bash
```

## Docker

Release Docker deployments use the standard Docker Compose file name:

```text
/opt/nodeping-agent/compose.yml
```

Run with:

```bash
cd /opt/nodeping-agent
docker compose --env-file .env up -d
```
