import os
import sys
import logging
from mcp.server.fastmcp import FastMCP
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

mcp = FastMCP("Model Armor Protection")
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
                    basic_config=modelarmor_v1.SdpFilterSettings.SdpBasicConfig(
                        filter_enforcement=modelarmor_v1.SdpFilterSettings.SdpBasicConfig.SdpBasicConfigEnforcement.ENABLED
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

@mcp.tool()
def scan_content(text: str) -> str:
    """
    Scans text using Google Cloud Model Armor to detect prompt injection and PII.
    
    Args:
        text: The content to scan.
        
    Returns:
        A report indicating whether the content is clean or flagged.
    """
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

if __name__ == "__main__":
    mcp.run()
