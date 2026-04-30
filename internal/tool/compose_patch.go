package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// PatchComposeNetworkTool injects an external Docker network into a compose file
// using the yaml.Node AST so comments and formatting are preserved. It is
// idempotent — calling it twice with the same network produces the same output.
type PatchComposeNetworkTool struct{}

func (PatchComposeNetworkTool) Name() string { return "patch_compose_network" }
func (PatchComposeNetworkTool) Description() string {
	return "Patch a docker-compose file to join an existing external Docker network. " +
		"Adds the network declaration at the top level and adds it to every service. " +
		"Uses the yaml.Node AST so comments and formatting are preserved. Idempotent. " +
		"Returns a summary of which services were patched."
}
func (PatchComposeNetworkTool) Parameters() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"file_path":    {"type": "string", "description": "Absolute path to the docker-compose file to patch"},
			"network_name": {"type": "string", "description": "Name of the existing external Docker network to add"}
		},
		"required": ["file_path", "network_name"]
	}`)
}
func (PatchComposeNetworkTool) RequiresConfirmation(_ json.RawMessage) bool { return false }
func (PatchComposeNetworkTool) CallString(args json.RawMessage) string {
	var p struct {
		FilePath    string `json:"file_path"`
		NetworkName string `json:"network_name"`
	}
	json.Unmarshal(args, &p) //nolint:errcheck
	return fmt.Sprintf("patch_compose_network(file_path=%q, network_name=%q)", p.FilePath, p.NetworkName)
}

func (PatchComposeNetworkTool) Execute(_ context.Context, args json.RawMessage) (string, error) {
	var p struct {
		FilePath    string `json:"file_path"`
		NetworkName string `json:"network_name"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", err
	}
	if p.FilePath == "" || p.NetworkName == "" {
		return "", fmt.Errorf("file_path and network_name are required")
	}

	raw, err := os.ReadFile(p.FilePath)
	if err != nil {
		return "", fmt.Errorf("cannot read compose file %q: %w", p.FilePath, err)
	}

	patched, services, err := patchComposeNetwork(raw, p.NetworkName)
	if err != nil {
		return "", fmt.Errorf("patch failed: %w", err)
	}

	if err := os.WriteFile(p.FilePath, patched, 0644); err != nil {
		return "", fmt.Errorf("cannot write patched compose file: %w", err)
	}

	return fmt.Sprintf("Patched %q: added network %q to %d service(s): %v",
		p.FilePath, p.NetworkName, len(services), services), nil
}

// patchComposeNetwork is the pure logic — separated for testability.
// It returns the patched YAML bytes and the names of services that were updated.
func patchComposeNetwork(src []byte, networkName string) ([]byte, []string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, nil, fmt.Errorf("invalid YAML: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, nil, fmt.Errorf("unexpected YAML structure (not a document node)")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, nil, fmt.Errorf("compose file root must be a mapping")
	}

	// ── 1. Patch top-level networks block ────────────────────────────────────
	if err := ensureTopLevelNetwork(root, networkName); err != nil {
		return nil, nil, err
	}

	// ── 2. Patch every service ───────────────────────────────────────────────
	services, err := patchServicesNetworks(root, networkName)
	if err != nil {
		return nil, nil, err
	}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, nil, err
	}
	return out, services, nil
}

// ensureTopLevelNetwork adds or amends the top-level `networks:` mapping so
// that `networkName` is declared as an external network.
//
//	networks:
//	  <networkName>:
//	    external: true
//	    name: <networkName>
func ensureTopLevelNetwork(root *yaml.Node, networkName string) error {
	networksVal := mappingValue(root, "networks")
	if networksVal == nil {
		// Append a brand-new top-level networks key+value pair.
		root.Content = append(root.Content,
			scalarNode("networks"),
			buildNetworksBlock(networkName),
		)
		return nil
	}
	// networks key already exists — make sure our network entry is in it.
	if networksVal.Kind != yaml.MappingNode {
		return fmt.Errorf("top-level 'networks' is not a mapping")
	}
	if mappingValue(networksVal, networkName) != nil {
		// Already present — idempotent, nothing to do.
		return nil
	}
	// Append the new network entry to the existing mapping.
	networksVal.Content = append(networksVal.Content,
		scalarNode(networkName),
		buildNetworkEntry(networkName),
	)
	return nil
}

// patchServicesNetworks iterates every service in `services:` and ensures
// `networkName` appears in its networks list.
func patchServicesNetworks(root *yaml.Node, networkName string) ([]string, error) {
	servicesVal := mappingValue(root, "services")
	if servicesVal == nil {
		return nil, fmt.Errorf("compose file has no 'services' key")
	}
	if servicesVal.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("'services' is not a mapping")
	}

	var patched []string
	// Mapping nodes interleave key-value pairs: [k0, v0, k1, v1, ...]
	for i := 0; i+1 < len(servicesVal.Content); i += 2 {
		serviceNameNode := servicesVal.Content[i]
		serviceNode := servicesVal.Content[i+1]
		if serviceNode.Kind != yaml.MappingNode {
			continue
		}
		if addNetworkToService(serviceNode, networkName) {
			patched = append(patched, serviceNameNode.Value)
		}
	}
	return patched, nil
}

// addNetworkToService ensures networkName appears in the service's `networks:`
// sequence. Returns true if a change was made.
func addNetworkToService(serviceNode *yaml.Node, networkName string) bool {
	networksVal := mappingValue(serviceNode, "networks")

	if networksVal == nil {
		// No networks key — append one with just our network.
		serviceNode.Content = append(serviceNode.Content,
			scalarNode("networks"),
			buildNetworksList(networkName),
		)
		return true
	}

	switch networksVal.Kind {
	case yaml.SequenceNode:
		// networks: [net1, net2] — check membership then append if absent.
		for _, item := range networksVal.Content {
			if item.Value == networkName {
				return false // already present
			}
		}
		networksVal.Content = append(networksVal.Content, scalarNode(networkName))
		return true

	case yaml.MappingNode:
		// networks:
		//   net1:
		//     aliases: [...]
		if mappingValue(networksVal, networkName) != nil {
			return false // already present
		}
		// Add the network with an empty mapping value (i.e. just the key).
		networksVal.Content = append(networksVal.Content,
			scalarNode(networkName),
			&yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"},
		)
		return true
	}
	return false
}

// ── helpers ──────────────────────────────────────────────────────────────────

// mappingValue returns the value node for `key` inside a MappingNode, or nil.
func mappingValue(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func scalarNode(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}

// buildNetworksBlock builds:
//
//	<networkName>:
//	  external: true
//	  name: <networkName>
func buildNetworksBlock(networkName string) *yaml.Node {
	return &yaml.Node{
		Kind: yaml.MappingNode,
		Tag:  "!!map",
		Content: []*yaml.Node{
			scalarNode(networkName),
			buildNetworkEntry(networkName),
		},
	}
}

// buildNetworkEntry builds:
//
//	external: true
//	name: <networkName>
func buildNetworkEntry(networkName string) *yaml.Node {
	return &yaml.Node{
		Kind: yaml.MappingNode,
		Tag:  "!!map",
		Content: []*yaml.Node{
			scalarNode("external"),
			{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"},
			scalarNode("name"),
			scalarNode(networkName),
		},
	}
}

// buildNetworksList builds a sequence node: [networkName]
func buildNetworksList(networkName string) *yaml.Node {
	return &yaml.Node{
		Kind:    yaml.SequenceNode,
		Tag:     "!!seq",
		Content: []*yaml.Node{scalarNode(networkName)},
	}
}
