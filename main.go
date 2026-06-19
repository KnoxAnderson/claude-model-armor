// Package main implements the Google Cloud Model Armor plugin for Claude Code.
// It supports running both as an MCP server and as a PreToolUse hook.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	modelarmor "cloud.google.com/go/modelarmor/apiv1"
	modelarmorpb "cloud.google.com/go/modelarmor/apiv1/modelarmorpb"
	"github.com/google/cel-go/cel"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"google.golang.org/api/option"
	"gopkg.in/yaml.v3"
)

// Global logger configuration
var logger = log.New(os.Stderr, "[model_armor] ", log.LstdFlags)

// YAML Config Structs
type ListConfig struct {
	Name  string   `yaml:"name"`
	Items []string `yaml:"items"`
}

type MacroConfig struct {
	Name       string `yaml:"name"`
	Expression string `yaml:"expression"`
}

type RuleConfig struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Expression  string `yaml:"expression"`
	Action      string `yaml:"action"`
	Message     string `yaml:"message"`
}

type RulesConfig struct {
	Lists  []ListConfig  `yaml:"lists"`
	Macros []MacroConfig `yaml:"macros"`
	Rules  []RuleConfig  `yaml:"rules"`
}

// Hook Input Structs
type HookAgentContext struct {
	Name           string `json:"agent_name"`
	OS             string `json:"agent_os"`
	PID            int    `json:"agent_pid"`
	SessionID      string `json:"session_id"`
	PermissionMode string `json:"permission_mode"`
	TranscriptPath string `json:"transcript_path"`
	CWD            string `json:"cwd"`
}

type PromptHookInput struct {
	SessionID      string `json:"session_id"`
	TranscriptPath string `json:"transcript_path"`
	CWD            string `json:"cwd"`
	HookEventName  string `json:"hook_event_name"`
	Prompt         string `json:"prompt"`
}

type HookToolUse struct {
	UseID       string                 `json:"tool_use_id"`
	Name        string                 `json:"tool_name"`
	Input       map[string]interface{} `json:"tool_input"`
	AgentName   string                 `json:"agent_name"`
	AgentPID    int                    `json:"agent_pid"`
	SessionID   string                 `json:"session_id"`
	Permission  string                 `json:"permission_mode"`
	Transcript  string                 `json:"transcript_path"`
	CWD         string                 `json:"cwd"`
}

type HookResponse struct {
	HookSpecificOutput HookSpecificOutput `json:"hookSpecificOutput"`
}

type HookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

// resolvePath returns the canonical absolute path of p
func resolvePath(p string) string {
	if p == "" {
		return ""
	}
	if strings.HasPrefix(p, "~") {
		home, err := os.UserHomeDir()
		if err == nil {
			p = filepath.Join(home, p[1:])
		}
	}
	abs, err := filepath.Abs(p)
	if err == nil {
		p = abs
	}
	realPath, err := filepath.EvalSymlinks(p)
	if err == nil {
		return realPath
	}
	return p
}

// resolveFilePath resolves p relative to cwd and returns canonical path
func resolveFilePath(p string, cwd string) string {
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return resolvePath(p)
	}
	return resolvePath(filepath.Join(cwd, p))
}

// extractRawFilePath pulls filePath from tool call inputs
func extractRawFilePath(toolName string, toolInput map[string]interface{}) string {
	if toolName == "Read" || toolName == "Write" || toolName == "Edit" {
		if val, ok := toolInput["filePath"].(string); ok {
			return val
		}
	} else if toolName == "apply_patch" {
		if val, ok := toolInput["file_path"].(string); ok {
			return val
		}
	}
	return ""
}

// extractCommand pulls command from Bash tool inputs
func extractCommand(toolName string, toolInput map[string]interface{}) string {
	if toolName == "Bash" {
		if val, ok := toolInput["command"].(string); ok {
			return val
		}
	}
	return ""
}

// expandExpression replaces macro calls inside a CEL expression recursively
func expandExpression(expr string, macros map[string]string) string {
	current := expr
	changed := true
	iterations := 0
	maxIterations := 20
	for changed && iterations < maxIterations {
		changed = false
		iterations++
		for name, value := range macros {
			pattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
			if pattern.MatchString(current) {
				current = pattern.ReplaceAllString(current, "("+value+")")
				changed = true
			}
		}
	}
	return current
}

// truncateStr shortens s to max runes, appending "…" if truncated.
func truncateStr(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "…"
}

// formatMessage replaces placeholders in message template using context fields.
// Values longer than 120 chars are truncated to keep Claude Code output readable.
func formatMessage(msgTmpl string, context map[string]interface{}) string {
	res := msgTmpl
	re := regexp.MustCompile(`%([a-zA-Z0-9._]+)%`)
	matches := re.FindAllStringSubmatch(msgTmpl, -1)
	for _, match := range matches {
		path := match[1]
		parts := strings.Split(path, ".")
		var val interface{} = context
		for _, part := range parts {
			if m, ok := val.(map[string]interface{}); ok {
				val = m[part]
			} else {
				val = ""
				break
			}
		}
		res = strings.ReplaceAll(res, "%"+path+"%", truncateStr(fmt.Sprintf("%v", val), 120))
	}
	return res
}

// isFilterMatch checks if a specific Model Armor filter was triggered
func isFilterMatch(res *modelarmorpb.FilterResult) bool {
	if res == nil {
		return false
	}
	switch f := res.FilterResult.(type) {
	case *modelarmorpb.FilterResult_RaiFilterResult:
		return f.RaiFilterResult.MatchState == modelarmorpb.FilterMatchState_MATCH_FOUND
	case *modelarmorpb.FilterResult_SdpFilterResult:
		if inspect, ok := f.SdpFilterResult.Result.(*modelarmorpb.SdpFilterResult_InspectResult); ok {
			return inspect.InspectResult != nil && len(inspect.InspectResult.Findings) > 0
		}
	case *modelarmorpb.FilterResult_PiAndJailbreakFilterResult:
		return f.PiAndJailbreakFilterResult.MatchState == modelarmorpb.FilterMatchState_MATCH_FOUND
	case *modelarmorpb.FilterResult_MaliciousUriFilterResult:
		return f.MaliciousUriFilterResult.MatchState == modelarmorpb.FilterMatchState_MATCH_FOUND
	case *modelarmorpb.FilterResult_CsamFilterFilterResult:
		return f.CsamFilterFilterResult.MatchState == modelarmorpb.FilterMatchState_MATCH_FOUND
	case *modelarmorpb.FilterResult_VirusScanFilterResult:
		return f.VirusScanFilterResult.MatchState == modelarmorpb.FilterMatchState_MATCH_FOUND
	}
	return false
}

// regionalEndpoint derives the Model Armor regional endpoint from a template resource path.
// Template paths have the form: projects/<proj>/locations/<loc>/templates/<name>
func regionalEndpoint(templateName string) string {
	parts := strings.Split(templateName, "/")
	if len(parts) >= 4 && parts[2] == "locations" {
		return fmt.Sprintf("modelarmor.%s.rep.googleapis.com:443", parts[3])
	}
	return "modelarmor.googleapis.com:443"
}

// newModelArmorClient creates a client pointed at the correct regional endpoint.
func newModelArmorClient(ctx context.Context, templateName string) (*modelarmor.Client, error) {
	endpoint := regionalEndpoint(templateName)
	return modelarmor.NewClient(ctx, option.WithEndpoint(endpoint))
}

// scanTextWithModelArmor sends content to Google Cloud Model Armor for scanning
func scanTextWithModelArmor(ctx context.Context, client *modelarmor.Client, templateName string, text string) (string, error) {
	if text == "" {
		return "", nil
	}
	req := &modelarmorpb.SanitizeUserPromptRequest{
		Name: templateName,
		UserPromptData: &modelarmorpb.DataItem{
			DataItem: &modelarmorpb.DataItem_Text{
				Text: text,
			},
		},
	}
	resp, err := client.SanitizeUserPrompt(ctx, req)
	if err != nil {
		return "", err
	}

	result := resp.GetSanitizationResult()
	if result == nil {
		return "", nil
	}

	if result.FilterMatchState == modelarmorpb.FilterMatchState_MATCH_FOUND {
		var findings []string
		for name, filterRes := range result.FilterResults {
			if isFilterMatch(filterRes) {
				findings = append(findings, name)
			}
		}
		if len(findings) > 0 {
			return "Model Armor flagged: " + strings.Join(findings, ", "), nil
		}
	}
	return "", nil
}

func main() {
	hookMode := flag.Bool("hook", false, "Run in PreToolUse hook mode")
	promptHookMode := flag.Bool("prompt-hook", false, "Run in UserPromptSubmit hook mode")
	templateFlag := flag.String("template", "", "Google Cloud Model Armor template resource path")
	rulesFlag := flag.String("rules", "", "Path to local rules.yaml definition")
	flag.Parse()

	// Load template from environment if flag is empty
	templateName := *templateFlag
	if templateName == "" {
		templateName = os.Getenv("MODEL_ARMOR_TEMPLATE")
	}

	// Resolve rules.yaml path
	rulesPath := *rulesFlag
	if rulesPath == "" {
		executablePath, err := os.Executable()
		if err == nil {
			rulesPath = filepath.Join(filepath.Dir(executablePath), "rules.yaml")
		} else {
			rulesPath = "rules.yaml"
		}
	}

	// 1. UserPromptSubmit hook path
	if *promptHookMode {
		runPromptHook(templateName)
		return
	}

	// 2. PreToolUse hook path
	if *hookMode {
		runHook(templateName, rulesPath)
		return
	}

	// 3. MCP Server execution path
	runMcpServer(templateName)
}

func runPromptHook(templateName string) {
	ctx := context.Background()

	inputBytes, err := io.ReadAll(os.Stdin)
	if err != nil || len(inputBytes) == 0 {
		logger.Printf("Empty stdin or read error: %v", err)
		os.Exit(2)
	}

	var payload PromptHookInput
	if err := json.Unmarshal(inputBytes, &payload); err != nil {
		logger.Printf("Failed to parse prompt hook input: %v", err)
		os.Exit(2)
	}

	if payload.Prompt == "" || templateName == "" {
		os.Exit(0)
	}

	client, err := newModelArmorClient(ctx, templateName)
	if err != nil {
		logger.Printf("Warning: Failed to create Model Armor client: %v", err)
		os.Exit(0)
	}
	defer client.Close()

	finding, err := scanTextWithModelArmor(ctx, client, templateName, payload.Prompt)
	if err != nil {
		logger.Printf("Error scanning user prompt: %v", err)
		os.Exit(0)
	}

	if finding != "" {
		resp := HookResponse{
			HookSpecificOutput: HookSpecificOutput{
				HookEventName:            "UserPromptSubmit",
				PermissionDecision:       "deny",
				PermissionDecisionReason: "Model Armor blocked your message: " + finding,
			},
		}
		json.NewEncoder(os.Stdout).Encode(resp)
	}

	os.Exit(0)
}

func runHook(templateName string, rulesPath string) {
	ctx := context.Background()

	// Fail safe/closed helper on exit/errors
	failClosed := func(reason string) {
		resp := HookResponse{
			HookSpecificOutput: HookSpecificOutput{
				HookEventName:            "PreToolUse",
				PermissionDecision:       "deny",
				PermissionDecisionReason: reason,
			},
		}
		json.NewEncoder(os.Stdout).Encode(resp)
		os.Exit(0) // hook framework expects 0 exit code even for blocks, using stdout to convey decision
	}

	// Read stdin
	inputBytes, err := io.ReadAll(os.Stdin)
	if err != nil || len(inputBytes) == 0 {
		logger.Printf("Empty stdin or read error: %v", err)
		os.Exit(2)
	}

	var payload HookToolUse
	if err := json.Unmarshal(inputBytes, &payload); err != nil {
		logger.Printf("Failed to parse input JSON: %v", err)
		os.Exit(2)
	}

	// Build context matching exact python hook schema
	cwd := payload.CWD
	realCwd := resolvePath(cwd)
	toolName := payload.Name
	toolInput := payload.Input
	filePath := extractRawFilePath(toolName, toolInput)
	realFilePath := resolveFilePath(filePath, realCwd)
	fileName := filepath.Base(filePath)
	if filePath == "" {
		fileName = ""
	}
	inputCommand := extractCommand(toolName, toolInput)

	celContextMap := map[string]interface{}{
		"agent": map[string]interface{}{
			"name":            payload.AgentName,
			"os":              "macos",
			"pid":             payload.AgentPID,
			"session_id":      payload.SessionID,
			"permission_mode": payload.Permission,
			"transcript_path": payload.Transcript,
			"cwd":             cwd,
			"real_cwd":        realCwd,
		},
		"tool": map[string]interface{}{
			"use_id":         payload.UseID,
			"name":           toolName,
			"input":          toolInput,
			"input_command":  inputCommand,
			"file_path":      filePath,
			"real_file_path": realFilePath,
			"file_name":      fileName,
		},
	}

	var rulesConfig RulesConfig
	if yamlFile, err := os.ReadFile(rulesPath); err == nil {
		yaml.Unmarshal(yamlFile, &rulesConfig)
	}

	// Populating lists & macros
	lists := make(map[string][]string)
	for _, l := range rulesConfig.Lists {
		lists[l.Name] = l.Items
		celContextMap[l.Name] = l.Items
	}

	macros := make(map[string]string)
	for _, m := range rulesConfig.Macros {
		macros[m.Name] = m.Expression
	}

	// Create CEL environment
	var opts []cel.EnvOption
	opts = append(opts, cel.Variable("agent", cel.MapType(cel.StringType, cel.AnyType)))
	opts = append(opts, cel.Variable("tool", cel.MapType(cel.StringType, cel.AnyType)))
	for name := range lists {
		opts = append(opts, cel.Variable(name, cel.ListType(cel.StringType)))
	}

	env, err := cel.NewEnv(opts...)
	if err != nil {
		failClosed(fmt.Sprintf("Failed to initialize CEL env: %v", err))
		return
	}

	decision := "allow"
	reason := ""

	// Evaluate CEL Rules
	for _, rule := range rulesConfig.Rules {
		expr := expandExpression(rule.Expression, macros)
		ast, iss := env.Compile(expr)
		if iss.Err() != nil {
			logger.Printf("Rule compile error: %v", iss.Err())
			continue
		}
		prg, err := env.Program(ast)
		if err != nil {
			logger.Printf("Rule program error: %v", err)
			continue
		}

		out, _, err := prg.Eval(celContextMap)
		if err != nil {
			logger.Printf("Rule eval error on '%s': %v", rule.Name, err)
			continue
		}

		if matched, ok := out.Value().(bool); ok && matched {
			ruleReason := formatMessage(rule.Message, celContextMap)
			if rule.Action == "deny" {
				decision = "deny"
				reason = ruleReason
				break // Deny immediately overrides other matches
			} else if rule.Action == "ask" {
				if decision != "deny" {
					decision = "ask"
					reason = ruleReason
				}
			}
		}
	}

	// Model Armor verification if allowed by rules
	if decision == "allow" && templateName != "" {
		client, err := newModelArmorClient(ctx, templateName)
		if err != nil {
			logger.Printf("Warning: Failed to create Model Armor client: %v", err)
		} else {
			defer client.Close()
			var scanText string
			if toolName == "Bash" {
				scanText = inputCommand
			} else if toolName == "Write" || toolName == "Edit" {
				if content, ok := toolInput["content"].(string); ok {
					scanText = content
				}
			}

			if scanText != "" {
				finding, err := scanTextWithModelArmor(ctx, client, templateName, scanText)
				if err != nil {
					logger.Printf("Error calling Model Armor: %v", err)
				} else if finding != "" {
					decision = "deny"
					reason = fmt.Sprintf("Model Armor check failed: %s", finding)
				}
			}
		}
	}

	// Output standard hook response
	resp := HookResponse{
		HookSpecificOutput: HookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       decision,
			PermissionDecisionReason: reason,
		},
	}
	json.NewEncoder(os.Stdout).Encode(resp)
}

func runMcpServer(templateName string) {
	s := server.NewMCPServer("claude-model-armor", "1.0.0")

	// Register scan_content tool
	tool := mcp.NewTool("scan_content",
		mcp.WithDescription("Scans user input or system command for security risks"),
		mcp.WithString("text", mcp.Required(), mcp.Description("Content to scan")),
	)

	s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		text, _ := request.GetArguments()["text"].(string)
		if text == "" {
			return mcp.NewToolResultText("Empty content provided"), nil
		}

		if templateName == "" {
			return mcp.NewToolResultText("Warning: Model Armor template not configured. Content check skipped."), nil
		}

		client, err := newModelArmorClient(ctx, templateName)
		if err != nil {
			return nil, fmt.Errorf("failed to create Model Armor client: %w", err)
		}
		defer client.Close()

		finding, err := scanTextWithModelArmor(ctx, client, templateName, text)
		if err != nil {
			return nil, fmt.Errorf("error during Model Armor scan: %w", err)
		}

		if finding != "" {
			return mcp.NewToolResultText("BLOCKED: " + finding), nil
		}
		return mcp.NewToolResultText("CLEAN: Content passed security checks"), nil
	})

	if err := server.ServeStdio(s); err != nil {
		logger.Fatalf("Server error: %v", err)
	}
}
