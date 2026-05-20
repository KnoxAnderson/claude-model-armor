# Model Armor MCP Server for Claude Code

This project implements a Model Context Protocol (MCP) server that allows Claude Code to use Google Cloud Model Armor to scan content for prompt injection and PII (Personally Identifiable Information).

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

## Usage

Once configured, Claude will have access to the `scan_content` tool. You can ask it to scan text:

*"Check this text for prompt injection and PII: [your text here]"*
