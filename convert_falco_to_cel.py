import yaml
import re
import os
import json

def translate_condition(cond: str) -> str:
    res = " ".join(cond.split())
    # Replace boolean operators
    res = re.sub(r'\band\b', '&&', res, flags=re.IGNORECASE)
    res = re.sub(r'\bor\b', '||', res, flags=re.IGNORECASE)
    res = re.sub(r'\bnot\b', '!', res, flags=re.IGNORECASE)
    
    # Replace comparison operators (except inside existing ==)
    res = re.sub(r'(?<![<>!=])=(?!=)', '==', res)
    
    # Translate methods
    res = re.sub(r'\bstartswith\s+val\(([^)]+)\)', r'.startsWith(\1)', res)
    res = re.sub(r'\bstartswith\s+("[^"]*"|\'[^\']*\')', r'.startsWith(\1)', res)
    res = re.sub(r'\bendswith\s+val\(([^)]+)\)', r'.endsWith(\1)', res)
    res = re.sub(r'\bendswith\s+("[^"]*"|\'[^\']*\')', r'.endsWith(\1)', res)
    res = re.sub(r'\bcontains\s+("[^"]*"|\'[^\']*\')', r'.contains(\1)', res)
    res = re.sub(r'\bcontains\s+val\(([^)]+)\)', r'.contains(\1)', res)
    
    # Translate icontains
    def repl_icontains(match):
        val = match.group(2)[1:-1]
        return f'{match.group(1)}.matches("(?i){val}")'
    res = re.sub(r'(\S+)\s+icontains\s+("[^"]*"|\'[^\']*\')', repl_icontains, res)
    
    # Translate basename
    res = res.replace("basename(tool.file_path)", "tool.file_name")
    
    # Translate pmatch
    res = re.sub(
        r'(\S+)\s+pmatch\s+\(([^)]+)\)',
        r'\2.exists(p, \1.startsWith(p))',
        res
    )
    
    # Translate in lists
    def repl_in(match):
        inner = match.group(1).strip()
        if "," in inner or '"' in inner or "'" in inner:
            return f"in [{inner}]"
        else:
            return f"in {inner}"
    res = re.sub(r'\bin\s+\(([^)]+)\)', repl_in, res)
    
    # Clean up any leftover val(...)
    res = re.sub(r'\bval\(([^)]+)\)', r'\1', res)
    
    return res

# Load coding_agents_rules.yaml
falco_rules_path = "/Users/knoxanderson/.gemini/jetski/scratch/prempti/rules/default/coding_agents_rules.yaml"

if not os.path.exists(falco_rules_path):
    print(f"Error: {falco_rules_path} does not exist.")
    exit(1)

with open(falco_rules_path, "r") as f:
    items = yaml.safe_load(f)

lists = []
macros = []
rules = []

for item in items:
    if "list" in item:
        items_list = item["items"]
        if item["list"] == "sensitive_paths":
            new_items = []
            for p in items_list:
                new_items.append(p)
                if p == "/etc/":
                    new_items.append("/private/etc/")
                elif p == "/var/":
                    new_items.append("/private/var/")
            items_list = new_items
        lists.append({
            "name": item["list"],
            "items": items_list
        })
    elif "macro" in item:
        macros.append({
            "name": item["macro"],
            "expression": translate_condition(item["condition"])
        })
    elif "rule" in item:
        tags = item.get("tags", [])
        action = "allow"
        if "coding_agent_deny" in tags:
            action = "deny"
        elif "coding_agent_ask" in tags:
            action = "ask"
            
        # Format output message placeholders to CEL style (%...% -> %...%)
        # Falco output uses: %tool.real_file_path, %agent.real_cwd etc.
        # We can normalize them to %name% format
        msg = item.get("output", "").strip()
        msg_normalized = msg
        # Replace %field with %field%
        # Match word characters and dots after %
        msg_normalized = re.sub(r'%([a-zA-Z0-9._]+)', r'%\1%', msg_normalized)
        
        rules.append({
            "name": item["rule"],
            "description": item.get("desc", "").strip(),
            "expression": translate_condition(item["condition"]),
            "action": action,
            "message": msg_normalized
        })

# Output rules to cel_rules.yaml
cel_rules_config = {
    "lists": lists,
    "macros": macros,
    "rules": rules
}

output_path = "/Users/knoxanderson/.gemini/jetski/scratch/claude-model-armor/cel_rules.yaml"
with open(output_path, "w") as f:
    yaml.dump(cel_rules_config, f, default_flow_style=False, sort_keys=False)

print(f"Converted {len(lists)} lists, {len(macros)} macros, and {len(rules)} rules to {output_path}.")
