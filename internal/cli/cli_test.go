package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
)

func TestSavedPlanWorksWithoutClientAndDoesNotOverwriteEvidence(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.json")
	output := filepath.Join(dir, "plan.json")
	r := &model.Report{SchemaVersion: 1, CollectedAt: time.Now(), BackendState: "Running", Peers: []model.Peer{{Node: model.Node{ID: "test-peer", Name: "example"}, Path: model.UnknownPath(time.Now(), "status_only")}}}
	if err := saveReport(input, r); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	args := []string{"plan", "--peer", "test-peer", "--from-report", input, "--json", "--output", output}
	if code := Run(context.Background(), args, &out, &errOut); code != 0 {
		t.Fatalf("%d %s", code, &errOut)
	}
	var result model.Report
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.ActiveProbes || result.ConfigurationChanges || result.Plan == nil {
		t.Fatal("unexpected side effects")
	}
	before, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if Run(context.Background(), args, &out, &errOut) == 0 {
		t.Fatal("overwrote existing evidence")
	}
	after, _ := os.ReadFile(output)
	if !bytes.Equal(before, after) {
		t.Fatal("evidence changed")
	}
}

func TestUnimplementedCommandsAndInvalidBudgetDoNotReachClient(t *testing.T) {
	for _, args := range [][]string{{"optimize"}, {"diagnose", "--peer", "example", "--budget", "0s"}, {"status", "--from-report", "something"}} {
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), args, &out, &errOut); code != 2 {
			t.Fatalf("%v returned %d", args, code)
		}
	}
}

func TestFailedCommandPreservesFailureReport(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "failed.json")
	var out, errOut bytes.Buffer
	args := []string{"plan", "--peer", "example", "--from-report", filepath.Join(dir, "missing.json"), "--output", output, "--json"}
	if Run(context.Background(), args, &out, &errOut) != 1 {
		t.Fatal("expected a failure")
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal("failure evidence was lost:", err)
	}
	var r model.Report
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	if r.Error == nil || r.Error.Code != "command_failed" {
		t.Fatal("failure report lacks cause")
	}
}
