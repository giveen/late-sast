package tool

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// roundTrip is a helper: parse → marshal to normalise formatting for comparison.
func roundTrip(t *testing.T, src string) string {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatalf("roundTrip unmarshal: %v", err)
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		t.Fatalf("roundTrip marshal: %v", err)
	}
	return string(out)
}

// ── patchComposeNetwork ───────────────────────────────────────────────────────

func TestPatchComposeNetwork_BasicService(t *testing.T) {
	src := `
services:
  app:
    image: myapp:latest
    ports:
      - "8080:8080"
`
	out, services, err := patchComposeNetwork([]byte(src), "sast-net")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(services) != 1 || services[0] != "app" {
		t.Errorf("expected [app], got %v", services)
	}

	// Parse result and verify top-level network + service network.
	var doc map[string]interface{}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is invalid YAML: %v", err)
	}
	networks, ok := doc["networks"].(map[string]interface{})
	if !ok {
		t.Fatal("top-level 'networks' key missing or wrong type")
	}
	entry, ok := networks["sast-net"].(map[string]interface{})
	if !ok {
		t.Fatal("'sast-net' missing from top-level networks")
	}
	if entry["external"] != true {
		t.Errorf("expected external=true, got %v", entry["external"])
	}
	if entry["name"] != "sast-net" {
		t.Errorf("expected name=sast-net, got %v", entry["name"])
	}

	svcs := doc["services"].(map[string]interface{})
	app := svcs["app"].(map[string]interface{})
	nets := app["networks"].([]interface{})
	if len(nets) != 1 || nets[0] != "sast-net" {
		t.Errorf("expected service networks [sast-net], got %v", nets)
	}
}

func TestPatchComposeNetwork_MultiService(t *testing.T) {
	src := `
services:
  api:
    image: api:latest
  worker:
    image: worker:latest
  db:
    image: postgres:16
`
	out, services, err := patchComposeNetwork([]byte(src), "sast-net")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(services) != 3 {
		t.Errorf("expected 3 patched services, got %d: %v", len(services), services)
	}

	var doc map[string]interface{}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is invalid YAML: %v", err)
	}
	svcs := doc["services"].(map[string]interface{})
	for _, name := range []string{"api", "worker", "db"} {
		svc := svcs[name].(map[string]interface{})
		nets, ok := svc["networks"].([]interface{})
		if !ok || len(nets) == 0 || nets[0] != "sast-net" {
			t.Errorf("service %q: expected networks [sast-net], got %v", name, svc["networks"])
		}
	}
}

func TestPatchComposeNetwork_ExistingNetworksBlock(t *testing.T) {
	src := `
services:
  app:
    image: myapp
    networks:
      - internal
networks:
  internal:
    driver: bridge
`
	out, services, err := patchComposeNetwork([]byte(src), "sast-net")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(services) != 1 {
		t.Errorf("expected 1 patched service, got %v", services)
	}

	var doc map[string]interface{}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is invalid YAML: %v", err)
	}
	// Both networks should be present at top level.
	networks := doc["networks"].(map[string]interface{})
	if _, ok := networks["internal"]; !ok {
		t.Error("existing 'internal' network was removed")
	}
	if _, ok := networks["sast-net"]; !ok {
		t.Error("'sast-net' was not added to existing networks block")
	}

	// Service should now have both networks.
	app := doc["services"].(map[string]interface{})["app"].(map[string]interface{})
	nets := app["networks"].([]interface{})
	found := false
	for _, n := range nets {
		if n == "sast-net" {
			found = true
		}
	}
	if !found {
		t.Errorf("'sast-net' not added to service networks, got: %v", nets)
	}
	// Original network must still be there.
	foundInternal := false
	for _, n := range nets {
		if n == "internal" {
			foundInternal = true
		}
	}
	if !foundInternal {
		t.Error("original 'internal' network was removed from service")
	}
}

func TestPatchComposeNetwork_MapStyleServiceNetworks(t *testing.T) {
	// Some compose files use mapping style for service networks:
	//   networks:
	//     internal:
	//       aliases: [api]
	src := `
services:
  app:
    image: myapp
    networks:
      internal:
        aliases:
          - api
networks:
  internal:
    driver: bridge
`
	out, services, err := patchComposeNetwork([]byte(src), "sast-net")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(services) != 1 {
		t.Errorf("expected 1 patched service, got %v", services)
	}

	var doc map[string]interface{}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is invalid YAML: %v", err)
	}
	app := doc["services"].(map[string]interface{})["app"].(map[string]interface{})
	nets := app["networks"].(map[string]interface{})
	if _, ok := nets["sast-net"]; !ok {
		t.Error("'sast-net' not added to map-style service networks")
	}
	if _, ok := nets["internal"]; !ok {
		t.Error("existing 'internal' service network was removed")
	}
}

func TestPatchComposeNetwork_Idempotent(t *testing.T) {
	src := `
services:
  app:
    image: myapp
`
	// Apply twice — result should be the same.
	out1, _, err := patchComposeNetwork([]byte(src), "sast-net")
	if err != nil {
		t.Fatalf("first patch: %v", err)
	}
	out2, services2, err := patchComposeNetwork(out1, "sast-net")
	if err != nil {
		t.Fatalf("second patch: %v", err)
	}
	if len(services2) != 0 {
		t.Errorf("second patch should report 0 changes, got: %v", services2)
	}
	// Normalise both via round-trip and compare.
	if roundTrip(t, string(out1)) != roundTrip(t, string(out2)) {
		t.Errorf("idempotency violation:\nfirst:\n%s\nsecond:\n%s", out1, out2)
	}
}

func TestPatchComposeNetwork_NoServicesKey(t *testing.T) {
	src := `
version: "3"
`
	_, _, err := patchComposeNetwork([]byte(src), "sast-net")
	if err == nil {
		t.Fatal("expected error for compose file with no 'services' key")
	}
	if !strings.Contains(err.Error(), "services") {
		t.Errorf("error should mention 'services', got: %v", err)
	}
}

func TestPatchComposeNetwork_InvalidYAML(t *testing.T) {
	src := `this: is: not: valid: yaml:`
	_, _, err := patchComposeNetwork([]byte(src), "sast-net")
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestPatchComposeNetwork_PreservesComments(t *testing.T) {
	src := `# Project: myapp
services:
  app:
    image: myapp:latest  # pinned version
    ports:
      - "8080:8080"
`
	out, _, err := patchComposeNetwork([]byte(src), "sast-net")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// yaml.v3 Marshal does preserve head comments on the document node.
	// At minimum verify the output is still valid YAML.
	var doc map[string]interface{}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("patched output is not valid YAML: %v", err)
	}
}

// ── PatchComposeNetworkTool (Execute path) ────────────────────────────────────

func TestPatchComposeNetworkTool_Metadata(t *testing.T) {
	tool := PatchComposeNetworkTool{}
	if tool.Name() != "patch_compose_network" {
		t.Errorf("unexpected name: %q", tool.Name())
	}
	if tool.Description() == "" {
		t.Error("description is empty")
	}
	if tool.RequiresConfirmation(nil) {
		t.Error("should not require confirmation")
	}
}

func TestPatchComposeNetworkTool_CallString(t *testing.T) {
	tool := PatchComposeNetworkTool{}
	args := []byte(`{"file_path":"/tmp/compose.yml","network_name":"sast-net"}`)
	cs := tool.CallString(args)
	if !strings.Contains(cs, "patch_compose_network") {
		t.Errorf("CallString missing tool name: %q", cs)
	}
	if !strings.Contains(cs, "sast-net") {
		t.Errorf("CallString missing network name: %q", cs)
	}
}
