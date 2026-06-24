# Claude Model Armor Guardrails

A dual-layer security guardrail system for Claude Code, written in Go. It combines a local deterministic rule engine with Google Cloud Model Armor's content safety APIs to screen every prompt, tool call, and response.

---

## Prerequisites

- **Claude Code** installed and running
- **Google Cloud account** with the Model Armor API enabled — required for cloud scanning (prompt injection, PII, RAI filtering). The local rules layer works without GCP.
- **`gcloud` CLI** authenticated: `gcloud auth application-default login`

---

## Quick Start

### 1. Download the binary

Download the binary for your platform from the [latest release](https://github.com/KnoxAnderson/claude-model-armor/releases/latest):

| Platform | Asset |
|----------|-------|
| macOS Apple Silicon | `claude-model-armor-darwin-arm64` |
| macOS Intel | `claude-model-armor-darwin-amd64` |
| Linux x86_64 | `claude-model-armor-linux-amd64` |
| Linux ARM64 | `claude-model-armor-linux-arm64` |

```bash
VERSION=v0.1.0
ASSET=claude-model-armor-darwin-arm64   # change for your platform
BASE=https://github.com/KnoxAnderson/claude-model-armor/releases/download/$VERSION

curl -L -o claude-model-armor "$BASE/$ASSET"
curl -L -o SHA256SUMS.txt "$BASE/SHA256SUMS.txt"
shasum -a 256 --ignore-missing -c SHA256SUMS.txt   # use sha256sum on Linux
chmod +x claude-model-armor
mkdir -p ~/.local/bin && mv claude-model-armor ~/.local/bin/
```

### 2. macOS only: clear the Gatekeeper quarantine

macOS blocks unsigned binaries downloaded from the internet. Run this before anything else, or the plugin will silently fail:

```bash
xattr -d com.apple.quarantine ~/.local/bin/claude-model-armor
```

### 3. Download the default rule set

```bash
curl -L -o ~/.local/bin/rules.yaml \
  https://raw.githubusercontent.com/KnoxAnderson/claude-model-armor/main/rules.yaml
```

### 4. Add hooks to Claude Code settings

Open (or create) `~/.claude/settings.json` and add the `hooks` block below. Use the **absolute path** to the binary — tilde expansion is not guaranteed in hook commands.

If `settings.json` already exists, merge the `hooks` key into it rather than replacing the whole file.

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/Users/YOUR_USERNAME/.local/bin/claude-model-armor",
            "args": [
              "--prompt-hook",
              "--template",
              "projects/YOUR_PROJECT/locations/us-central1/templates/YOUR_TEMPLATE"
            ]
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "/Users/YOUR_USERNAME/.local/bin/claude-model-armor",
            "args": [
              "--hook",
              "--rules",
              "/Users/YOUR_USERNAME/.local/bin/rules.yaml"
            ]
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "/Users/YOUR_USERNAME/.local/bin/claude-model-armor",
            "args": ["--post-hook"]
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/Users/YOUR_USERNAME/.local/bin/claude-model-armor",
            "args": ["--response-hook"]
          }
        ]
      }
    ]
  }
}
```

> **No GCP yet?** Remove the `--template` arg from `UserPromptSubmit`. The local rules layer runs independently — cloud scanning simply won't be active until you set up a template.

Restart Claude Code. The guardrails are active.

---

## Cloud Scanning Setup

The cloud layer requires a Google Cloud project with Model Armor enabled.

1. Enable the [Model Armor API](https://console.cloud.google.com/model-armor) in your GCP project
2. Create a template in the Model Armor console
3. Run `gcloud auth application-default login`
4. Set these environment variables (add to your shell profile to make them permanent):

```bash
export GOOGLE_CLOUD_PROJECT=your-project-id
export MODEL_ARMOR_TEMPLATE=projects/your-project-id/locations/us-central1/templates/your-template-id
```

5. Add the `--template` arg to the `UserPromptSubmit` hook as shown in step 4 above

---

## How It Works

Every Claude Code action passes through two layers:

```
[User prompt / Tool call / Tool output / Model response]
          │
          ▼
┌──────────────────────────────────────────────────┐
│  Layer 1: Local Rule Engine                      │
│  Runs before every tool call (PreToolUse).       │
│  Evaluates 60+ CEL rules from rules.yaml.        │
│  Flags: sensitive path access, credential reads, │
│  sandbox escapes, destructive commands, supply   │
│  chain attacks, and more.                        │
│  Works offline — no GCP required.                │
└──────────────────────┬───────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────┐
│  Layer 2: Cloud Content Scanning (Model Armor)   │
│  Runs on all hooks. Requires GCP.                │
│  - Prompt injection & jailbreak detection        │
│  - PII / sensitive data exposure (SDP)           │
│  - Responsible AI (RAI) content filtering        │
│  - Malicious URL detection                       │
└──────────────────────┬───────────────────────────┘
                       │
                       ▼
        [Action proceeds or user is prompted]
```

### Hook coverage

| What's being scanned | Hook | Layer 1 | Layer 2 |
|----------------------|------|:-------:|:-------:|
| User messages | UserPromptSubmit | — | ✅ |
| Tool calls + behavioral rules | PreToolUse | ✅ | ✅ |
| Tool output (injection in files/command output) | PostToolUse | — | ✅ |
| Claude's responses | Stop | — | ✅ |

---

## Customizing Rules

Rules live in `rules.yaml` and are written in [Common Expression Language (CEL)](https://github.com/google/cel-spec). By default, every flagged action uses `ask` — Claude pauses and you choose whether to allow or cancel.

```yaml
rules:
  - name: Ask before writing outside working directory
    description: "Flags writes outside the current project directory."
    expression: is_write_tool && tool.real_file_path != "" && is_outside_cwd
    action: ask
    message: "CONFIRMATION REQUIRED: Claude wants to write to %tool.real_file_path%, which is outside your working directory (%agent.real_cwd%). Approve to allow or deny to cancel."
```

> **Want a hard block instead of a prompt?** Change `action: ask` to `action: deny` on any rule and the hook will block that action outright without asking.

Rules support three actions: `allow` (log and pass through), `ask` (pause and prompt the user), `deny` (block immediately).

The rule set ships with reusable `lists` (path groups, file name sets) and `macros` (CEL sub-expressions) you can compose into new rules. See `rules.yaml` for the full set.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GOOGLE_CLOUD_PROJECT` | — | GCP project ID hosting your Model Armor template. |
| `MODEL_ARMOR_TEMPLATE` | — | Full template resource path (`projects/.../locations/.../templates/...`). |
| `MODEL_ARMOR_TIMEOUT` | `10` | Per-scan network timeout in seconds. Prevents a slow Model Armor service from hanging tool execution. |
| `MODEL_ARMOR_FAIL_CLOSED` | `false` | When `true`, a Model Armor error or timeout on PreToolUse blocks the action instead of allowing it through. Prompt and post hooks always fail open. |
| `MODEL_ARMOR_RULES_ASK_ONLY` | `false` | Downgrades any `deny` rule to `ask` at runtime without editing the yaml. Not needed if your rules already use `ask` — the default rule set does. |
| `MODEL_ARMOR_AUDIT_LOG` | — | File path to append a JSON audit log of every decision. |

---

## Building from Source

Requires Go 1.23+.

```bash
go build -o claude-model-armor main.go
go test -v ./...
```

---

## Enterprise Deployment

### Distribute the binary and rules centrally

Use your endpoint management platform (Jamf, Intune, Ansible, Chef) to:
- Install `claude-model-armor` to a read-only system path (e.g., `/usr/local/bin/claude-model-armor`)
- Deploy a company-approved `rules.yaml` to a protected location (e.g., `/etc/claude-model-armor/rules.yaml`, owned by root, not writable by users)

### Enforce hooks globally

Push the hook configuration to each developer's `~/.claude/settings.json` via logon script or configuration management, pointing `--rules` at the protected rules file and `command` at the system binary path.

### Set environment variables system-wide

Push `GOOGLE_CLOUD_PROJECT` and `MODEL_ARMOR_TEMPLATE` via `/etc/profile.d/model_armor.sh` (macOS/Linux) or Group Policy (Windows). Ensure developers are authenticated to the GCP project via `gcloud auth application-default login` or a service account.

### Tamper prevention

Deploy `~/.claude/policy-limits.json` as a read-only file to prevent users from disabling hooks. The local rules engine also blocks any attempt by Claude to write to Claude Code settings or policy-limits files.
