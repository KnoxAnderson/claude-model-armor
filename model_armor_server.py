import os
import sys
import logging
import json
import yaml
import celpy
from google.cloud import modelarmor_v1

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT")
LOCATION = "us-central1" # Model Armor is regional
TEMPLATE_ID = "claude-code-protection-template"

if not PROJECT_ID:
    logger.error("GOOGLE_CLOUD_PROJECT environment variable is not set.")
    sys.exit(1)

client = modelarmor_v1.ModelArmorClient()

def get_or_create_template():
    parent = f"projects/{PROJECT_ID}/locations/{LOCATION}"
    name = f"{parent}/templates/{TEMPLATE_ID}"
    
    try:
        template = client.get_template(name=name)
        logger.info(f"Using existing template: {name}")
        return template
    except Exception as e:
        logger.info(f"Template not found or error occurred: {e}. Creating new template.")
        # Create a template if it doesn't exist
        template = modelarmor_v1.Template(
            filter_config=modelarmor_v1.FilterConfig(
                # Enable Prompt Injection & Jailbreak filtering
                pi_and_jailbreak_filter_settings=modelarmor_v1.PiAndJailbreakFilterSettings(
                    filter_enforcement=modelarmor_v1.PiAndJailbreakFilterSettings.PiAndJailbreakFilterEnforcement.ENABLED
                ),
                # Enable Basic PII Detection (SDP)
                sdp_settings=modelarmor_v1.SdpFilterSettings(
                    basic_config=modelarmor_v1.SdpBasicConfig(
                        filter_enforcement=modelarmor_v1.SdpBasicConfig.SdpBasicConfigEnforcement.ENABLED
                    )
                )
            )
        )
        try:
            created_template = client.create_template(parent=parent, template_id=TEMPLATE_ID, template=template)
            logger.info(f"Created new template: {name}")
            return created_template
        except Exception as create_err:
            logger.error(f"Failed to create template: {create_err}")
            raise create_err

def scan_content_logic(text: str) -> str:
    try:
        get_or_create_template()
        name = f"projects/{PROJECT_ID}/locations/{LOCATION}/templates/{TEMPLATE_ID}"
        
        request = modelarmor_v1.SanitizeUserPromptRequest(
            name=name,
            user_prompt_data=modelarmor_v1.DataItem(text=text)
        )
        
        response = client.sanitize_user_prompt(request=request)
        result = response.sanitization_result
        
        if result.filter_match_state == modelarmor_v1.SanitizationResult.FilterMatchState.MATCH_FOUND:
            findings = []
            for filter_name, filter_res in result.filter_results.items():
                 findings.append(f"- {filter_name}: Flagged")
            
            if not findings:
                findings.append("- Content flagged (details unavailable)")
                
            return f"⚠️ SECURITY ALERT: Content flagged by Model Armor.\nFindings:\n" + "\n".join(findings)
        
        return "✅ Content is clean."
        
    except Exception as e:
        logger.error(f"Error during sanitization: {e}")
        return f"❌ Error calling Model Armor: {str(e)}"

def run_mcp_server():
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP("Model Armor Protection")

    @mcp.tool()
    def scan_content(text: str) -> str:
        """
        Scans text using Google Cloud Model Armor to detect prompt injection and PII.
        
        Args:
            text: The content to scan.
            
        Returns:
            A report indicating whether the content is clean or flagged.
        """
        return scan_content_logic(text)

    mcp.run()

# ---------------------------------------------------------------------------
# PreToolUse Hook Integration with CEL Engine
# ---------------------------------------------------------------------------

def extract_raw_file_path(tool_name: str, tool_input: dict) -> str:
    if tool_name in ("Write", "Edit", "Read"):
        return tool_input.get("file_path", "")
    return ""

def extract_command(tool_name: str, tool_input: dict) -> str:
    if tool_name == "Bash":
        return tool_input.get("command", "")
    return ""

def resolve_path(p: str) -> str:
    if not p:
        return ""
    return os.path.realpath(os.path.expanduser(p))

def resolve_file_path(file_path: str, real_cwd: str) -> str:
    if not file_path:
        return ""
    if os.path.isabs(file_path):
        return resolve_path(file_path)
    return resolve_path(os.path.join(real_cwd, file_path))

def format_message(message: str, context: dict) -> str:
    res = message
    placeholders = {
        "%agent.cwd%": context.get("agent", {}).get("cwd", ""),
        "%agent.real_cwd%": context.get("agent", {}).get("real_cwd", ""),
        "%tool.name%": context.get("tool", {}).get("name", ""),
        "%tool.file_path%": context.get("tool", {}).get("file_path", ""),
        "%tool.real_file_path%": context.get("tool", {}).get("real_file_path", ""),
        "%tool.file_name%": context.get("tool", {}).get("file_name", ""),
        "%tool.input_command%": context.get("tool", {}).get("input_command", ""),
    }
    for k, v in placeholders.items():
        res = res.replace(k, str(v))
    return res

def scan_text_with_model_armor(text: str) -> str:
    if not text:
        return None
    try:
        get_or_create_template()
        name = f"projects/{PROJECT_ID}/locations/{LOCATION}/templates/{TEMPLATE_ID}"
        request = modelarmor_v1.SanitizeUserPromptRequest(
            name=name,
            user_prompt_data=modelarmor_v1.DataItem(text=text)
        )
        response = client.sanitize_user_prompt(request=request)
        result = response.sanitization_result
        if result.filter_match_state == modelarmor_v1.SanitizationResult.FilterMatchState.MATCH_FOUND:
            findings = []
            for filter_name in result.filter_results.keys():
                 findings.append(filter_name)
            return "Model Armor flagged: " + ", ".join(findings)
    except Exception as e:
        logger.error(f"Error calling Model Armor: {e}")
    return None

def expand_expression(expr: str, macros: dict) -> str:
    import re
    current = expr
    changed = True
    iterations = 0
    max_iterations = 20
    while changed and iterations < max_iterations:
        changed = False
        iterations += 1
        for name, value in macros.items():
            pattern = r'\b' + re.escape(name) + r'\b'
            new_expr, count = re.subn(pattern, f"({value})", current)
            if count > 0:
                current = new_expr
                changed = True
    return current

def run_hook():
    try:
        # Read stdin
        input_data = sys.stdin.read()
        if not input_data.strip():
            logger.error("Empty stdin input")
            sys.exit(2)
        
        payload = json.loads(input_data)
        
        # Build context
        cwd = payload.get("cwd", "")
        real_cwd = resolve_path(cwd)
        tool_name = payload.get("tool_name", "")
        tool_input = payload.get("tool_input", {})
        file_path = extract_raw_file_path(tool_name, tool_input)
        real_file_path = resolve_file_path(file_path, real_cwd)
        file_name = os.path.basename(file_path) if file_path else ""
        input_command = extract_command(tool_name, tool_input)
        
        context = {
            "agent": {
                "name": payload.get("agent_name", "claude_code"),
                "os": "macos",
                "pid": payload.get("agent_pid", 0),
                "session_id": payload.get("session_id", ""),
                "permission_mode": payload.get("permission_mode", ""),
                "transcript_path": payload.get("transcript_path", ""),
                "cwd": cwd,
                "real_cwd": real_cwd,
            },
            "tool": {
                "use_id": payload.get("tool_use_id", ""),
                "name": tool_name,
                "input": tool_input,
                "input_command": input_command,
                "file_path": file_path,
                "real_file_path": real_file_path,
                "file_name": file_name,
            }
        }
        
        # Load rules, lists and macros from rules.yaml
        rules_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.yaml")
        rules = []
        lists = {}
        macros = {}
        if os.path.exists(rules_path):
            with open(rules_path, "r") as f:
                rules_config = yaml.safe_load(f) or {}
                for item in rules_config.get("lists", []):
                    lists[item["name"]] = item.get("items", [])
                for item in rules_config.get("macros", []):
                    macros[item["name"]] = item.get("expression", "")
                rules = rules_config.get("rules", [])
        
        # Inject lists into CEL evaluation context
        cel_context_dict = {**context}
        for list_name, list_items in lists.items():
            cel_context_dict[list_name] = list_items
            
        # Evaluate CEL rules
        env = celpy.Environment()
        decision = "allow"
        reason = ""
        
        cel_context = celpy.json_to_cel(cel_context_dict)
        
        for rule in rules:
            expr_raw = rule.get("expression", "")
            expr = expand_expression(expr_raw, macros)
            action = rule.get("action", "allow")
            rule_name = rule.get("name", "")
            msg_tmpl = rule.get("message", "")
            
            try:
                ast = env.compile(expr)
                prgm = env.program(ast)
                matched = prgm.evaluate(cel_context)
                
                if matched:
                    rule_reason = format_message(msg_tmpl, context)
                    # Escalation rules: deny overrides ask
                    if action == "deny":
                        decision = "deny"
                        reason = f"Rule '{rule_name}': {rule_reason}"
                        break  # deny is final, no need to check further
                    elif action == "ask":
                        if decision != "deny":
                            decision = "ask"
                            reason = f"Rule '{rule_name}': {rule_reason}"
            except Exception as eval_err:
                logger.error(f"Error evaluating rule '{rule_name}': {eval_err}")
        
        # If still allowed, run Model Armor check on inputs
        if decision == "allow":
            armor_finding = None
            if tool_name == "Bash":
                armor_finding = scan_text_with_model_armor(input_command)
            elif tool_name in ("Write", "Edit"):
                file_content = tool_input.get("content", "")
                armor_finding = scan_text_with_model_armor(file_content)
            
            if armor_finding:
                decision = "deny"
                reason = f"Model Armor check failed: {armor_finding}"
        
        # Output result
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": reason
            }
        }
        print(json.dumps(output))
        sys.exit(0)
        
    except Exception as e:
        logger.error(f"Hook error: {e}")
        # Fail safe/closed: output deny on exception
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": f"Hook execution error: {e}"
            }
        }
        print(json.dumps(output))
        sys.exit(2)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--hook":
        run_hook()
    else:
        run_mcp_server()
