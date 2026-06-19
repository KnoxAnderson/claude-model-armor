package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestResolvePath(t *testing.T) {
	// Test empty path
	if resolvePath("") != "" {
		t.Error("Empty path should resolve to empty string")
	}

	// Test normal path resolution (should return absolute path)
	cwd := resolvePath(".")
	if cwd == "" {
		t.Error("Current directory should resolve to absolute path")
	}
}

func TestResolveFilePath(t *testing.T) {
	if resolveFilePath("", "/tmp") != "" {
		t.Error("Empty file path should resolve to empty string")
	}

	// Test absolute path bypasses CWD. The path is canonicalized (symlinks
	// resolved), so on macOS /etc -> /private/etc; assert the CWD is not
	// prepended rather than an exact platform-specific string.
	got := resolveFilePath("/etc/hosts", "/tmp")
	if strings.HasPrefix(got, "/tmp") {
		t.Errorf("Absolute path should not prepend CWD, got: %s", got)
	}
	if !strings.HasSuffix(got, "/etc/hosts") {
		t.Errorf("Absolute path should resolve to a canonical /etc/hosts, got: %s", got)
	}
}

func TestExtractRawFilePath(t *testing.T) {
	inputs := map[string]interface{}{
		"filePath": "/some/path.txt",
	}
	if extractRawFilePath("Write", inputs) != "/some/path.txt" {
		t.Errorf("Expected /some/path.txt, got %s", extractRawFilePath("Write", inputs))
	}

	patchInputs := map[string]interface{}{
		"file_path": "/patch/path.txt",
	}
	if extractRawFilePath("apply_patch", patchInputs) != "/patch/path.txt" {
		t.Errorf("Expected /patch/path.txt, got %s", extractRawFilePath("apply_patch", patchInputs))
	}

	if extractRawFilePath("Bash", inputs) != "" {
		t.Errorf("Expected empty string for Bash, got %s", extractRawFilePath("Bash", inputs))
	}
}

func TestExtractCommand(t *testing.T) {
	inputs := map[string]interface{}{
		"command": "ls -la",
	}
	if extractCommand("Bash", inputs) != "ls -la" {
		t.Errorf("Expected ls -la, got %s", extractCommand("Bash", inputs))
	}

	if extractCommand("Write", inputs) != "" {
		t.Errorf("Expected empty string for Write, got %s", extractCommand("Write", inputs))
	}
}

func TestExpandExpression(t *testing.T) {
	macros := map[string]string{
		"is_claude_write_tool": "tool.name in ['Write', 'Edit']",
		"is_write_tool":        "is_claude_write_tool || tool.name == 'apply_patch'",
	}

	// Simple replacement
	res := expandExpression("is_claude_write_tool && is_sensitive_path", macros)
	expected := "(tool.name in ['Write', 'Edit']) && is_sensitive_path"
	if res != expected {
		t.Errorf("Expected '%s', got '%s'", expected, res)
	}

	// Nested macro replacement
	res2 := expandExpression("is_write_tool && is_sensitive_path", macros)
	expected2 := "((tool.name in ['Write', 'Edit']) || tool.name == 'apply_patch') && is_sensitive_path"
	if res2 != expected2 {
		t.Errorf("Expected '%s', got '%s'", expected2, res2)
	}
}

func TestFormatMessage(t *testing.T) {
	context := map[string]interface{}{
		"tool": map[string]interface{}{
			"real_file_path": "/etc/hosts",
		},
		"agent": map[string]interface{}{
			"name": "claude_code",
		},
	}

	tmpl := "Blocked: %tool.real_file_path% accessed by %agent.name%"
	expected := "Blocked: /etc/hosts accessed by claude_code"
	res := formatMessage(tmpl, context)
	if res != expected {
		t.Errorf("Expected '%s', got '%s'", expected, res)
	}
}

func TestTruncateStr(t *testing.T) {
	if got := truncateStr("short", 120); got != "short" {
		t.Errorf("short string should be unchanged, got %q", got)
	}
	long := strings.Repeat("a", 200)
	got := truncateStr(long, 120)
	if len([]rune(got)) != 121 { // 120 runes + ellipsis
		t.Errorf("expected 121 runes, got %d", len([]rune(got)))
	}
	if !strings.HasSuffix(got, "…") {
		t.Error("truncated string should end with ellipsis")
	}
	// Multibyte safety: must not split a rune.
	multi := strings.Repeat("é", 200)
	if !strings.HasSuffix(truncateStr(multi, 10), "…") {
		t.Error("multibyte truncation should still append ellipsis")
	}
}

func TestRegionalEndpoint(t *testing.T) {
	cases := map[string]string{
		"projects/p/locations/us-central1/templates/t": "modelarmor.us-central1.rep.googleapis.com:443",
		"projects/p/locations/us/templates/t":          "modelarmor.us.rep.googleapis.com:443",
		"garbage":                                       "modelarmor.googleapis.com:443",
		"":                                              "modelarmor.googleapis.com:443",
	}
	for in, want := range cases {
		if got := regionalEndpoint(in); got != want {
			t.Errorf("regionalEndpoint(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtractToolOutput(t *testing.T) {
	// String response (Read) is unquoted.
	p := PostToolUseInput{ToolName: "Read", ToolResponse: json.RawMessage(`"hello world"`)}
	if got := extractToolOutput(p); got != "hello world" {
		t.Errorf("expected unquoted string, got %q", got)
	}

	// Object response (Bash) is serialized.
	p = PostToolUseInput{ToolName: "Bash", ToolResponse: json.RawMessage(`{"stdout":"x"}`)}
	if got := extractToolOutput(p); !strings.Contains(got, "stdout") {
		t.Errorf("expected serialized object, got %q", got)
	}

	// Non-scanned tool returns empty.
	p = PostToolUseInput{ToolName: "Write", ToolResponse: json.RawMessage(`"content"`)}
	if got := extractToolOutput(p); got != "" {
		t.Errorf("Write output should not be scanned, got %q", got)
	}

	// Oversized output is truncated.
	big, _ := json.Marshal(strings.Repeat("a", maxScanBytes+5000))
	p = PostToolUseInput{ToolName: "Read", ToolResponse: big}
	if got := extractToolOutput(p); len(got) > maxScanBytes {
		t.Errorf("output should be truncated to %d, got %d", maxScanBytes, len(got))
	}
}

func TestLoadRuntimeConfig(t *testing.T) {
	// Defaults.
	os.Unsetenv("MODEL_ARMOR_TIMEOUT")
	os.Unsetenv("MODEL_ARMOR_FAIL_CLOSED")
	os.Unsetenv("MODEL_ARMOR_AUDIT_LOG")
	cfg := loadRuntimeConfig()
	if cfg.scanTimeout != 10*time.Second {
		t.Errorf("default timeout should be 10s, got %v", cfg.scanTimeout)
	}
	if cfg.failClosed {
		t.Error("default should be fail-open")
	}

	// Overrides.
	os.Setenv("MODEL_ARMOR_TIMEOUT", "3")
	os.Setenv("MODEL_ARMOR_FAIL_CLOSED", "true")
	defer os.Unsetenv("MODEL_ARMOR_TIMEOUT")
	defer os.Unsetenv("MODEL_ARMOR_FAIL_CLOSED")
	cfg = loadRuntimeConfig()
	if cfg.scanTimeout != 3*time.Second {
		t.Errorf("timeout override failed, got %v", cfg.scanTimeout)
	}
	if !cfg.failClosed {
		t.Error("fail-closed override failed")
	}
}

func TestExtractContentText(t *testing.T) {
	// Bare string.
	if got := extractContentText(json.RawMessage(`"hello"`)); got != "hello" {
		t.Errorf("string content: got %q", got)
	}
	// Array of blocks: only text blocks, joined.
	blocks := json.RawMessage(`[{"type":"text","text":"a"},{"type":"tool_use","name":"Bash"},{"type":"text","text":"b"}]`)
	if got := extractContentText(blocks); got != "a\nb" {
		t.Errorf("block content: got %q", got)
	}
	// Empty.
	if got := extractContentText(json.RawMessage(``)); got != "" {
		t.Errorf("empty content should be empty, got %q", got)
	}
}

func TestLastAssistantText(t *testing.T) {
	tmp, err := os.CreateTemp("", "transcript-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	tmp.WriteString(`{"type":"user","message":{"role":"user","content":"hi"}}` + "\n")
	tmp.WriteString(`{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"first"}]}}` + "\n")
	tmp.WriteString(`{"type":"user","message":{"role":"user","content":"again"}}` + "\n")
	tmp.WriteString(`{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"latest answer"}]}}` + "\n")
	tmp.Close()

	if got := lastAssistantText(tmp.Name()); got != "latest answer" {
		t.Errorf("expected most recent assistant text, got %q", got)
	}

	// Missing file is a safe no-op.
	if got := lastAssistantText("/nonexistent/path.jsonl"); got != "" {
		t.Errorf("missing transcript should yield empty, got %q", got)
	}
}

func TestRulesAskOnlyConfig(t *testing.T) {
	os.Setenv("MODEL_ARMOR_RULES_ASK_ONLY", "true")
	defer os.Unsetenv("MODEL_ARMOR_RULES_ASK_ONLY")
	if !loadRuntimeConfig().rulesAskOnly {
		t.Error("MODEL_ARMOR_RULES_ASK_ONLY=true should set rulesAskOnly")
	}
	os.Unsetenv("MODEL_ARMOR_RULES_ASK_ONLY")
	if loadRuntimeConfig().rulesAskOnly {
		t.Error("rulesAskOnly should default false")
	}
}

func TestWriteAudit(t *testing.T) {
	tmp, err := os.CreateTemp("", "audit-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	tmp.Close()

	cfg := runtimeConfig{auditPath: tmp.Name()}
	cfg.writeAudit(auditEntry{Event: "PreToolUse", Tool: "Bash", Decision: "deny", Source: "local_rule"})

	data, _ := os.ReadFile(tmp.Name())
	var e auditEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &e); err != nil {
		t.Fatalf("audit line not valid JSON: %v", err)
	}
	if e.Decision != "deny" || e.Timestamp == "" {
		t.Errorf("audit entry missing fields: %+v", e)
	}

	// No path configured = no-op (no panic).
	runtimeConfig{}.writeAudit(auditEntry{Decision: "allow"})
}
