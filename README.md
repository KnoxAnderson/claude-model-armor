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

## Operating Modes

The plugin ships two ready-to-use coverage profiles, assembled from the hook modes below:

| Path through the system | Hook | Standard | Vertex Simulation |
|-------------------------|------|:--------:|:-----------------:|
| User message → model | UserPromptSubmit (`--prompt-hook`) | ✅ | ✅ |
| Model → tool call request (+ local rules) | PreToolUse (`--hook`) | ✅ | ✅ |
| Tool result → model | PostToolUse (`--post-hook`) | ✅ | ✅ |
| Model → user response | Stop (`--response-hook`) | — | ✅ |

**Standard** scans the agent's inputs and actions. **Vertex Simulation** adds the outbound model-response scan (`SanitizeModelResponse`), so every leg that would cross a Vertex API boundary is covered in both directions — approximating what Model Armor sees when integrated natively into Vertex AI.

## Deployment Modes

The plugin can be integrated into Claude Code via the following hook modes (and as an MCP server):

### A. PreToolUse Hook Mode (Recommended)
Intercepts tool execution *before* it happens, returning `allow`, `deny`, or `ask` (which prompts the user to confirm). Runs both Layer 1 (local CEL rules) and Layer 2 (Model Armor scan of Bash commands and file-write content).

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

### B. UserPromptSubmit Hook Mode
Scans each user message through Model Armor *before* it reaches Claude. On a flag it emits a `block` decision (honored by the Claude Code CLI) and also injects an `additionalContext` security alert so clients that do not hard-block on prompt submit (e.g. the desktop app) still warn the model. Register with `--prompt-hook`:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      { "hooks": [ { "type": "command", "command": "/absolute/path/to/claude-model-armor", "args": ["--prompt-hook"] } ] }
    ]
  }
}
```

### C. PostToolUse Hook Mode
Scans the *output* of read-like tools (`Read`, `Bash`, `WebFetch`, `Grep`) after they run — the primary defense against prompt-injection payloads hidden inside files or command output. The content is already in context and cannot be unread, so on a flag the hook injects an `additionalContext` alert instructing the model to treat the output as untrusted data. Register with `--post-hook`:

```json
{
  "hooks": {
    "PostToolUse": [
      { "hooks": [ { "type": "command", "command": "/absolute/path/to/claude-model-armor", "args": ["--post-hook"] } ] }
    ]
  }
}
```

### D. Stop Hook Mode (Vertex Simulation)
Scans the *assistant's own response* after each turn through Model Armor's model-response API (`SanitizeModelResponse` — RAI, PII leakage, and malicious URLs the model emitted). On a flag it blocks the Stop, forcing the model to revise — mirroring how Vertex-integrated Model Armor rejects an unsafe model response. A loop guard (`stop_hook_active`) prevents endless regeneration. Register with `--response-hook`:

```json
{
  "hooks": {
    "Stop": [
      { "hooks": [ { "type": "command", "command": "/absolute/path/to/claude-model-armor", "args": ["--response-hook"] } ] }
    ]
  }
}
```

### E. MCP Server Mode
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
3.  **Go Runtime** *(optional)*: Go 1.23+ is only required if you build from source. Most users can download a prebuilt binary from the [Releases](https://github.com/KnoxAnderson/claude-model-armor/releases) page instead.

---

## Installation

Download a prebuilt binary for your platform from the [latest release](https://github.com/KnoxAnderson/claude-model-armor/releases/latest) — no Go toolchain required.

| Platform | Asset |
|----------|-------|
| macOS Apple Silicon | `claude-model-armor-darwin-arm64` |
| macOS Intel | `claude-model-armor-darwin-amd64` |
| Linux x86_64 | `claude-model-armor-linux-amd64` |
| Linux ARM64 | `claude-model-armor-linux-arm64` |

```bash
# Pick the asset for your platform (this example: macOS Apple Silicon)
VERSION=v0.1.0
ASSET=claude-model-armor-darwin-arm64
BASE=https://github.com/KnoxAnderson/claude-model-armor/releases/download/$VERSION

# Download the binary and the checksums
curl -L -o claude-model-armor      "$BASE/$ASSET"
curl -L -o SHA256SUMS.txt          "$BASE/SHA256SUMS.txt"

# Verify integrity, then install
shasum -a 256 --ignore-missing -c SHA256SUMS.txt   # use `sha256sum` on Linux
chmod +x claude-model-armor
mkdir -p ~/.local/bin && mv claude-model-armor ~/.local/bin/

# Fetch the default rule set alongside the binary
curl -L -o ~/.local/bin/rules.yaml \
  https://raw.githubusercontent.com/KnoxAnderson/claude-model-armor/main/rules.yaml
```

> On macOS, Gatekeeper may quarantine a downloaded binary. If you see “cannot be opened,” run `xattr -d com.apple.quarantine ~/.local/bin/claude-model-armor`.

Then register the hooks (see [Deployment Modes](#deployment-modes)), pointing the `command` at `~/.local/bin/claude-model-armor`.

---

## Configuration (Environment Variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `GOOGLE_CLOUD_PROJECT` | — | GCP project ID hosting the Model Armor template. |
| `MODEL_ARMOR_TEMPLATE` | — | Full template resource path. The regional endpoint is derived from the `locations/<region>` segment automatically. |
| `MODEL_ARMOR_TIMEOUT` | `10` | Per-scan network timeout in seconds. Prevents a slow or unreachable Model Armor service from hanging tool execution. |
| `MODEL_ARMOR_FAIL_CLOSED` | `false` | When `true`, a Model Armor error or timeout on a PreToolUse scan results in `deny` instead of `allow`. Prompt and post hooks always fail open so the user is never locked out. |
| `MODEL_ARMOR_RULES_ASK_ONLY` | `false` | When `true`, every Layer 1 (local rule) `deny` is downgraded to `ask`, so Layer 1 prompts for confirmation instead of hard-blocking. Model Armor cloud findings are unaffected. |
| `MODEL_ARMOR_AUDIT_LOG` | — | When set to a file path, every decision (local rule, Model Armor, or error) is appended as a JSON line for auditing. |

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

