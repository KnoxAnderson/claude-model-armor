# claude-model-armor

Security guardrails for [Claude Code](https://claude.ai/code). Screens every prompt, tool call, and response through two layers: a local CEL rule engine that catches dangerous patterns instantly, and Google Cloud [Model Armor](https://cloud.google.com/security/products/model-armor) for cloud-based prompt injection, PII, and RAI filtering.

Works without a GCP account — the local rule engine runs entirely offline.

## Prerequisites

- **Claude Code** installed
- **macOS or Linux** (x86_64 or ARM64)
- **GCP account** _(optional)_ — required for cloud scanning (prompt injection, PII, RAI). The local rule layer works without it.
- **`gcloud` CLI** _(if using cloud scanning)_: `gcloud auth application-default login`

## Install

**1. Download the binary**

```bash
# Auto-detect your platform
case "$(uname -sm)" in
  "Darwin arm64")  ASSET="claude-model-armor-darwin-arm64" ;;
  "Darwin x86_64") ASSET="claude-model-armor-darwin-amd64" ;;
  "Linux x86_64")  ASSET="claude-model-armor-linux-amd64"  ;;
  "Linux aarch64") ASSET="claude-model-armor-linux-arm64"  ;;
esac

VERSION=v0.1.0
BASE=https://github.com/KnoxAnderson/claude-model-armor/releases/download/$VERSION

curl -fL -o claude-model-armor "$BASE/$ASSET"
curl -fL -o SHA256SUMS.txt "$BASE/SHA256SUMS.txt"
shasum -a 256 --ignore-missing -c SHA256SUMS.txt   # sha256sum on Linux
chmod +x claude-model-armor
mkdir -p ~/.local/bin && mv claude-model-armor ~/.local/bin/
```

**2. macOS: clear the Gatekeeper quarantine**

macOS blocks unsigned binaries from the internet. Clear the quarantine flag or the plugin silently fails:

```bash
xattr -d com.apple.quarantine ~/.local/bin/claude-model-armor
```

**3. Download the default rule set**

Place `rules.yaml` in the same directory as the binary. The plugin looks there by default, so no `--rules` flag is needed:

```bash
curl -fL -o ~/.local/bin/rules.yaml \
  https://raw.githubusercontent.com/KnoxAnderson/claude-model-armor/main/rules.yaml
```

**4. Wire up the Claude Code hooks**

Add the `hooks` block to `~/.claude/settings.json`. Replace `YOUR_USERNAME` with your actual username, or run this to do it automatically:

```bash
BINARY="$HOME/.local/bin/claude-model-armor"
TEMPLATE="projects/YOUR_PROJECT/locations/us-central1/templates/YOUR_TEMPLATE"

cat > /tmp/model-armor-hooks.json << EOF
{
  "hooks": {
    "UserPromptSubmit": [{"hooks": [{"type": "command", "command": "$BINARY", "args": ["--prompt-hook", "--template", "$TEMPLATE"]}]}],
    "PreToolUse":       [{"matcher": "", "hooks": [{"type": "command", "command": "$BINARY", "args": ["--hook"]}]}],
    "PostToolUse":      [{"matcher": "", "hooks": [{"type": "command", "command": "$BINARY", "args": ["--post-hook"]}]}],
    "Stop":             [{"hooks": [{"type": "command", "command": "$BINARY", "args": ["--response-hook"]}]}]
  }
}
EOF
```

Merge `model-armor-hooks.json` into your `~/.claude/settings.json`, then restart Claude Code. The guardrails are active.

> **No GCP yet?** Remove `--template $TEMPLATE` from `UserPromptSubmit`. The local rule engine works immediately; cloud scanning can be added later.

---

## How it works

```
User prompt / Tool call / Tool output / Model response
          │
          ▼
┌──────────────────────────────────────────────────┐
│  Layer 1: Local CEL Rule Engine                  │
│  Runs on PreToolUse. Offline, zero latency.      │
│  40+ rules covering: credential access,          │
│  sandbox escapes, reverse shells, exfiltration,  │
│  MCP server attacks, agent self-modification.    │
│  Action per rule: ask (default) | deny | allow   │
└──────────────────────┬───────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────┐
│  Layer 2: Model Armor Cloud Scan (optional)      │
│  Runs on all four hooks. Requires GCP.           │
│  · Prompt injection & jailbreak detection        │
│  · PII / sensitive data exposure (SDP)           │
│  · Responsible AI (RAI) content filtering        │
│  · Malicious URL detection                       │
└──────────────────────┬───────────────────────────┘
                       │
                       ▼
        [Tool call proceeds or user is prompted]
```

### Hook coverage

| Hook | What's scanned | Layer 1 | Layer 2 |
|------|----------------|:-------:|:-------:|
| `UserPromptSubmit` | User messages | — | ✅ |
| `PreToolUse` | Tool calls + behavioral rules | ✅ | ✅ |
| `PostToolUse` | Tool output (injection in files/command output) | — | ✅ |
| `Stop` | Claude's final response | — | ✅ |

---

## Built-in rules

The default `rules.yaml` ships with 40+ rules organized into categories. Every rule defaults to `ask` — Claude pauses and you approve or cancel — not a hard block.

| Category | What it catches |
|---|---|
| **File system** | Reads/writes to sensitive paths (`~/.ssh/`, `/etc/`, cloud credential dirs), writes outside the working directory |
| **Credentials** | Access to `.env`, `credentials.json`, `.netrc`, AWS/GCP credential files via Bash or Read tool |
| **Sandbox escape** | `dangerouslyDisableSandbox`, Codex CLI bypass flags, Gemini sandbox env vars, agent settings tampering via `sed`/`cp`/`mv` |
| **Shell attacks** | Pipe-to-shell (`\| bash`), encoded exec (`base64 -d`), reverse shells (`/dev/tcp/`, `nc -e`), IMDS access, archive of credential dirs |
| **Exfiltration** | `curl`/`wget` POST/upload, temp-path staging, SSH reverse tunnels, SOCKS proxy |
| **Persistence** | Crontab writes, shell startup file edits (`.bashrc`, `.zshrc`), audit trail destruction (`history -c`) |
| **Supply chain** | `npm publish`, `twine upload`, `cargo publish` |
| **MCP attacks** | MCP server install from malicious domains, MCP config with IOC domains/temp-dir commands/base64, self-registered MCP servers, execution from temp paths |
| **Agent self-modification** | Writes to `.claude/commands/`, `CLAUDE.md` outside CWD, skill files with IOC domains or pipe-to-shell content, cross-agent OAuth file reads |

---

## Customizing rules

Rules are [CEL](https://github.com/google/cel-spec) expressions evaluated against tool context. `ask` is the default — it pauses Claude and prompts you to approve or cancel:

```yaml
rules:
  - name: Ask before writing outside working directory
    description: "Requires confirmation when writing outside the project directory."
    expression: is_write_tool && tool.real_file_path != "" && is_outside_cwd
    action: ask
    message: "CONFIRMATION REQUIRED: Claude wants to write to %tool.real_file_path%,
      which is outside your working directory (%agent.real_cwd%). Approve to allow or deny to cancel."
```

**Change `ask` to `deny`** on any rule to hard-block without prompting.

Rules support three actions: `allow` (log and pass through), `ask` (pause and prompt), `deny` (block immediately).

The rule set ships with reusable `lists` (path groups, file sets) and `macros` (CEL sub-expressions) you can reference in new rules. See [`rules.yaml`](rules.yaml) for the full set.

---

## MCP server mode

When called with no flags, the binary runs as an MCP server exposing a `scan_content` tool. Add it to your Claude Code MCP config to let Claude scan arbitrary text on demand:

```json
{
  "mcpServers": {
    "model-armor": {
      "command": "/Users/YOUR_USERNAME/.local/bin/claude-model-armor",
      "env": {
        "MODEL_ARMOR_TEMPLATE": "projects/YOUR_PROJECT/locations/us-central1/templates/YOUR_TEMPLATE"
      }
    }
  }
}
```

The `scan_content` tool accepts a `text` argument and returns `CLEAN: ...` or `BLOCKED: <finding>`.

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `MODEL_ARMOR_TEMPLATE` | — | Full template resource path. Falls back to this if `--template` is not passed. |
| `GOOGLE_CLOUD_PROJECT` | — | GCP project ID. |
| `MODEL_ARMOR_TIMEOUT` | `10` | Per-scan timeout in seconds. |
| `MODEL_ARMOR_FAIL_CLOSED` | `false` | When `true`, a Model Armor error on PreToolUse blocks the action instead of allowing it through. Prompt and post hooks always fail open. |
| `MODEL_ARMOR_RULES_ASK_ONLY` | `false` | Downgrades any `deny` rule to `ask` at runtime — lets you test rules without hard blocks. |
| `MODEL_ARMOR_AUDIT_LOG` | — | Path to append a JSON audit log of every decision. |

---

## Cloud scanning setup

1. Enable the [Model Armor API](https://console.cloud.google.com/model-armor) in your GCP project
2. Create a template in the Model Armor console
3. Authenticate: `gcloud auth application-default login`
4. Pass `--template projects/PROJECT/locations/LOCATION/templates/TEMPLATE` to the `UserPromptSubmit` hook (or set `MODEL_ARMOR_TEMPLATE`)

---

## Enterprise deployment

**Distribute centrally.** Use Jamf, Intune, Ansible, or Chef to:
- Install `claude-model-armor` to a read-only path (`/usr/local/bin/`)
- Deploy a company-approved `rules.yaml` to a protected location (`/etc/claude-model-armor/rules.yaml`, root-owned)

**Enforce hooks.** Push the hook configuration to `~/.claude/settings.json` via login script or config management, pointing `--rules` at the protected rules file.

**Set env vars system-wide.** Push `MODEL_ARMOR_TEMPLATE` via `/etc/profile.d/model_armor.sh` (macOS/Linux) or Group Policy (Windows).

**Tamper prevention.** Deploy `~/.claude/policy-limits.json` as a read-only file. The rule set also blocks any attempt by Claude to write to Claude Code settings or policy-limits files directly.

---

## Build from source

Requires Go 1.23+.

```bash
go build -o claude-model-armor main.go
go test -v ./...
```
