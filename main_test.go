package main

import (
	"testing"
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

	// Test absolute path bypasses CWD
	if resolveFilePath("/etc/hosts", "/tmp") != "/etc/hosts" {
		t.Errorf("Absolute path should not prepend CWD, got: %s", resolveFilePath("/etc/hosts", "/tmp"))
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
