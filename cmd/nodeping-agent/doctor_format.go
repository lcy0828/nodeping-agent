package main

import (
	"fmt"
	"strings"
)

func formatDoctorCheck(check doctorCheck) string {
	return fmt.Sprintf("%-32s %-12s %s", doctorCheckName(check.Name), doctorCheckStatus(check.Status), doctorCheckMessage(check))
}

func doctorCheckName(name string) string {
	switch name {
	case "config":
		return "配置 / config"
	case "ping command":
		return "Ping 命令 / ping command"
	case "traceroute command":
		return "Traceroute 命令 / traceroute command"
	case "mtr command":
		return "MTR 命令 / mtr command"
	case "dns lookup":
		return "DNS 解析 / dns lookup"
	case "public ip":
		return "公网 IP / public ip"
	case "token file":
		return "Token 文件 / token file"
	case "backend health":
		return "后端健康 / backend health"
	case "agent registration":
		return "Agent 注册 / agent registration"
	case "upgrade control":
		return "升级控制 / upgrade control"
	default:
		return name
	}
}

func doctorCheckStatus(status string) string {
	switch status {
	case "ok":
		return "正常 / ok"
	case "warn":
		return "警告 / warn"
	case "fail":
		return "失败 / fail"
	default:
		return status
	}
}

func doctorCheckMessage(check doctorCheck) string {
	message := check.Message
	switch {
	case message == "":
		return ""
	case strings.HasPrefix(message, "agent_id="):
		return "标识与版本 / identity and version: " + message
	case message == "NODEPING_SERVER_URL is not a valid URL":
		return "NODEPING_SERVER_URL 不是有效 URL / NODEPING_SERVER_URL is not a valid URL"
	case strings.HasPrefix(message, "missing "):
		return "缺少 " + strings.TrimPrefix(message, "missing ") + " / " + message
	case message == "remote upgrade is disabled":
		return "远程升级已禁用 / remote upgrade is disabled"
	case message == "NODEPING_AGENT_UPGRADE_REQUEST_FILE is empty":
		return "NODEPING_AGENT_UPGRADE_REQUEST_FILE 为空 / NODEPING_AGENT_UPGRADE_REQUEST_FILE is empty"
	case message == "NODEPING_AGENT_UPGRADE_UNIT is empty":
		return "NODEPING_AGENT_UPGRADE_UNIT 为空 / NODEPING_AGENT_UPGRADE_UNIT is empty"
	case message == "systemctl not found":
		return "未找到 systemctl / systemctl not found"
	case message == "upgrade script is not executable":
		return "升级脚本不可执行 / upgrade script is not executable"
	case strings.HasPrefix(message, "request file "):
		return "请求文件 / request file " + strings.TrimPrefix(message, "request file ")
	case strings.HasPrefix(message, "systemd unit "):
		return "systemd 单元 / systemd unit " + strings.TrimPrefix(message, "systemd unit ")
	case strings.HasPrefix(message, "auto request file "):
		return "自动请求文件 / auto request file " + strings.TrimPrefix(message, "auto request file ")
	case strings.HasPrefix(message, "auto systemd unit "):
		return "自动 systemd 单元 / auto systemd unit " + strings.TrimPrefix(message, "auto systemd unit ")
	case strings.HasPrefix(message, "auto script "):
		return "自动脚本 / auto script " + strings.TrimPrefix(message, "auto script ")
	case message == "remote upgrade is not configured; set NODEPING_AGENT_UPGRADE_MODE=request_file for systemd installs":
		return "远程升级未配置；systemd 安装请设置 NODEPING_AGENT_UPGRADE_MODE=request_file / remote upgrade is not configured; set NODEPING_AGENT_UPGRADE_MODE=request_file for systemd installs"
	case message == "ping command not found":
		return "未找到 ping 命令 / ping command not found"
	case strings.HasSuffix(message, " not found; related diagnostic task will fail until installed"):
		binary := strings.TrimSuffix(message, " not found; related diagnostic task will fail until installed")
		return "未找到 " + binary + "；安装前相关诊断任务会失败 / " + message
	case strings.HasSuffix(message, " answers"):
		count := strings.TrimSuffix(message, " answers")
		return count + " 个结果 / " + message
	case message == "public IP discovery failed":
		return "公网 IP 发现失败 / public IP discovery failed"
	case message == "NODEPING_AGENT_TOKEN_FILE is empty":
		return "NODEPING_AGENT_TOKEN_FILE 为空 / NODEPING_AGENT_TOKEN_FILE is empty"
	case message == "readable":
		return "可读 / readable"
	case message == "writable":
		return "可写 / writable"
	case message == "server URL is empty":
		return "后端地址为空 / server URL is empty"
	case strings.HasPrefix(message, "status "):
		if strings.Contains(message, "invalid binding token") {
			return "安装 token 已失效；请在用户页重新获取 Agent 安装命令 / binding token is invalid; get a fresh Agent install command from the user page"
		}
		return "HTTP 状态 " + strings.TrimPrefix(message, "status ") + " / " + message
	case strings.HasPrefix(message, "registered node "):
		return "已注册节点 / registered node " + strings.TrimPrefix(message, "registered node ")
	case message == "agent is not registered on this endpoint":
		return "Agent 尚未注册到当前 Endpoint / agent is not registered on this endpoint"
	default:
		return message
	}
}
