# Claude Model Armor Guardrails

A high-performance, dual-layer security guardrail system for Claude Code, written in Go for maximum execution speed and minimal latency overhead. It operates as both a deterministic local policy engine and a cloud-based content safety filter.

## Dual-Layer Security Architecture

This plugin protects your environment using two complementary security layers:

```
[Claude Code Tool Call]
          │
          ▼
┌──────────────────────────────────────────────┐
│  Layer 1: Deterministic CEL Rules (Local)   │
│  - Blocks sensitive path access (/etc, .ssh) │
│  - Prevents sandbox-disable configurations   │
│  - Intercepts destructive shell commands    │
│  - Restricts operations outside CWD          │
└──────────────────────┬───────────────────────┘
                       │ (if allowed)
                       ▼
┌──────────────────────────────────────────────┐
│   Layer 2: Cloud Model Armor (GCP Service)   │
│  - Screens command/file text via APIs        │
│  - Detects Prompt Injection & Jailbreaks     │
│  - Scans for PII / Sensitive Data (SDP)      │
│  - Blocks Malicious URIs & RAI violations    │
└──────────────────────┬───────────────────────┘
                       │ (if allowed)
                       ▼
             [Execute Tool Call]
```

### 1. Deterministic Local Rules (CEL Engine)
Powered by `google/cel-go`, this layer evaluates coding agent tool calls (Read, Write, Edit, Bash) against a structured local rule set before execution. 

By default, it includes **60+ rules** designed for local system safety and agent containment:
*   **Path Protection**: Prevents reads or writes to system files (`/etc`, `/var`, `/boot`), GPG, SSH keys, AWS/GCP cloud credentials, and browser databases.
*   **Sandbox Enforcement**: Intercepts requests to disable Claude Code's OS-level process sandboxing or to bypass approval dialogs.
*   **Destructive Shell Commands**: Denies highly destructive shell pipelines (e.g., `sudo su`, `mkfs`, `dd`, `rm -rf /`).
*   **WorkingDirectory Boundary**: Restricts the agent from writing files outside the active workspace directory unless confirmed by the user.

### 2. Cognitive Cloud Safety (Google Cloud Model Armor)
Integrates with Google Cloud Model Armor to check the inputs and outputs of commands and files.
*   **PII & Sensitive Data Protection (SDP)**: Redacts or flags exposure of sensitive data like social security numbers, credit cards, or API credentials.
*   **Prompt Injection Detection**: Blocks hidden instructions in files or downloaded materials trying to hijack the agent.
*   **Responsible AI (RAI)**: Filters hate speech, harassment, sexually explicit, and dangerous content.
*   **Phishing & Malicious URLs**: Screens URLs present in commands or file edits.

---

## Deployment Modes

The plugin can be integrated into Claude Code in two ways:

### A. PreToolUse Hook Mode (Recommended)
Intercepts tool execution *before* it happens, returning `allow`, `deny`, or `ask` (which prompts the user to confirm).

#### Registration
Add the hook to your Claude Code settings (e.g., in `~/.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/claude-model-armor/claude-model-armor",
            "args": [
              "--hook"
            ]
          }
        ]
      }
    ]
  }
}
```

### B. MCP Server Mode
Exposes a `scan_content` tool to Claude, allowing it to inspect text blocks on-demand.

#### Registration
Add the server to your Claude configuration (e.g., in `~/.claude/config.json`):

```json
{
  "mcpServers": {
    "model-armor": {
      "command": "/absolute/path/to/claude-model-armor/claude-model-armor",
      "args": [],
      "env": {
        "GOOGLE_CLOUD_PROJECT": "your-gcp-project-id",
        "MODEL_ARMOR_TEMPLATE": "projects/your-gcp-project-id/locations/us-central1/templates/your-template-id"
      }
    }
  }
}
```

---

## Prerequisites

1.  **GCP Project**: A Google Cloud project with the Model Armor API enabled.
2.  **Authentication**: Authenticated GCP environment (e.g., via `gcloud auth application-default login`).
3.  **Go Runtime**: Go 1.23+ is required to build the high-performance binary.

---

## Building from Source

```bash
# Build the binary
go build -o claude-model-armor main.go

# Run unit tests
go test -v ./...
```

---

## Customizing Local Rules (`rules.yaml`)

Rules are written in Common Expression Language (CEL) and structured with reusable `lists` and `macros`:

```yaml
lists:
  - name: sensitive_paths
    items:
      - /etc/
      - /private/etc/
      - /root/

macros:
  - name: is_write_tool
    expression: tool.name in ["Write", "Edit"]

rules:
  - name: deny_sensitive_paths
    description: "Prevent modification of system paths"
    expression: is_write_tool && sensitive_paths.exists(p, tool.real_file_path.startsWith(p))
    action: deny
    message: "Security blocked modification of system path: %tool.real_file_path%"
```

---

## Enterprise Orchestration & Deployment

For security teams looking to deploy and enforce `claude-model-armor` across all developer machines within a company, follow this orchestration guide:

### 1. Centralized Binary & Rules Distribution
Use an endpoint management platform or configuration manager (such as Jamf Pro, Microsoft Intune, Ansible, or Chef) to distribute the following assets to developer workstations:
*   **Production Binary**: Install `claude-model-armor` to a read-only system executable directory (e.g., `/usr/local/bin/claude-model-armor`).
*   **Local Rules file**: Deploy the company-approved `rules.yaml` to a centralized configuration directory (e.g., `/etc/claude-model-armor/rules.yaml`). Ensure this file is owned by root/system and read-only to prevent users from modifying or tampering with the rules locally.

### 2. Global Hook Configuration
Automate the injection of the `PreToolUse` hook configuration into each developer's `~/.claude/settings.json`. The following configuration enforces the security check and points to the read-only rules file using the `--rules` flag:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "/usr/local/bin/claude-model-armor",
            "args": [
              "--hook",
              "--rules",
              "/etc/claude-model-armor/rules.yaml"
            ]
          }
        ]
      }
    ]
  }
}
```

This can be pushed automatically via a logon/startup shell script or by orchestrating changes to the settings file using `jq`.

### 3. Environment Variable Enforcement
Model Armor requires the Google Cloud client environment variables for cognitive safety screening. Push the following environment variables globally (e.g., via `/etc/profile.d/model_armor.sh` on macOS/Linux, or registry key group policies on Windows):
*   `GOOGLE_CLOUD_PROJECT`: The ID of your centralized Google Cloud project.
*   `MODEL_ARMOR_TEMPLATE`: The resource path to your Model Armor safety template: `projects/<project-id>/locations/<region>/templates/<template-id>`

Ensure that developers are authenticated with the GCP project (e.g., via a shared service account key or dynamic credential exchange via `gcloud auth application-default login`).

### 4. Policy Limits Hardening (Tamper Prevention)
To prevent developers from disabling or unstaging the security hook configuration, deploy a read-only **Policy Limits** file to:
*   `~/.claude/policy-limits.json`

Ensure the limits file has permission rules restricting the modification of Claude's environment or bypassing approvals. The local rules engine itself also blocks attempts to write to settings or policy limits via the `Deny writes to Claude Code settings file` and `Deny writes to Claude Code policy limits file` rules.

