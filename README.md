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
