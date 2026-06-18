# Model Armor MCP Server for Claude Code

This project implements a Model Context Protocol (MCP) server that allows Claude Code to use Google Cloud Model Armor to scan content for safety risks, including prompt injection, jailbreak attempts, and sensitive data exposure.

## Features

Model Armor provides four primary pillars of protection, which this server can leverage:

1.  **Prompt Injection & Jailbreak Detection**: Detects attempts to manipulate the model's behavior or bypass safety guardrails.
2.  **Sensitive Data Protection (SDP)**: Scans for and identifies Personally Identifiable Information (PII).
    *   *Basic Configuration*: Screens for a fixed set of common infoTypes (e.g., Credit card numbers, US SSNs, credentials).
    *   *Advanced Configuration*: Supports de-identification (masking/redacting) using custom templates.
3.  **Responsible AI (RAI) Safety Filters**: Screens content for categories like `HATE_SPEECH`, `HARASSMENT`, `SEXUALLY_EXPLICIT`, and `DANGEROUS` content.
4.  **Malicious URL Detection**: Identifies phishing links and known web threats (scans the first 40 URLs in the text).

*Note: The default implementation in this server enables **Prompt Injection Detection** and **Basic SDP**.*

## Prerequisites

1.  **Google Cloud Project**: You need a Google Cloud project with the Model Armor API enabled.
2.  **Authentication**: You must be authenticated with Google Cloud (e.g., via `gcloud auth application-default login` or by setting `GOOGLE_APPLICATION_CREDENTIALS`).
3.  **Environment Variable**: You must set the `GOOGLE_CLOUD_PROJECT` environment variable.

## Installation

1.  Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```

## Configuration for Claude Code

Add the following to your Claude Code configuration (e.g., in `~/.claude/config.json`):

```json
{
  "mcpServers": {
    "model-armor": {
      "command": "python",
      "args": ["/Users/knoxanderson/.gemini/jetski/scratch/claude-model-armor/model_armor_server.py"],
      "env": {
        "GOOGLE_CLOUD_PROJECT": "your-project-id"
      }
    }
  }
}
```

Replace `"your-project-id"` with your actual Google Cloud project ID.

## Customization

You can customize the filters by editing the `get_or_create_template` function in `model_armor_server.py`. For example, to enable Malicious URL detection, you can add:

```python
malicious_uri_filter_settings=modelarmor_v1.MaliciousUriFilterSettings(
    filter_enforcement=modelarmor_v1.MaliciousUriFilterSettings.MaliciousUriFilterEnforcement.ENABLED
)
```

## Usage

Once configured, Claude will have access to the `scan_content` tool. You can ask it to scan text:

*"Check this text for prompt injection and PII: [your text here]"*

## PreToolUse Hook Mode (CEL Rules Engine)

This plugin can also act as a Claude Code `PreToolUse` hook to evaluate coding agent actions against local security rules (defined in CEL) and Google Cloud Model Armor.

### Registration in Claude Code

Add the hook command to your Claude Code settings (e.g., in `~/.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "/Users/knoxanderson/.gemini/jetski/scratch/claude-model-armor/venv/bin/python",
            "args": [
              "/Users/knoxanderson/.gemini/jetski/scratch/claude-model-armor/model_armor_server.py",
              "--hook"
            ]
          }
        ]
      }
    ]
  }
}
```

### Custom Rules

Rules are loaded from `rules.yaml` in the same directory. Each rule consists of a CEL expression, an action (`allow` | `deny` | `ask`), and a formatting message.

Example rule in `rules.yaml`:
```yaml
rules:
  - name: deny_sensitive_paths
    description: "Prevent reading or writing to sensitive system or credential paths"
    expression: |
      tool.name in ["Write", "Edit", "Read"] && (
        tool.real_file_path.startsWith("/etc/") ||
        tool.real_file_path.contains("/.ssh/")
      )
    action: deny
    message: "Falco CEL blocked access to sensitive path: %tool.real_file_path%"
```

