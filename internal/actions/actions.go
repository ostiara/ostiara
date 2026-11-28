// Package actions is the catalog of predefined, shell-free commands people can run in pods,
// each with its own approval rule and optional redaction of what it prints.
package actions

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"

	"sigs.k8s.io/yaml"
)

// Approval rules.
const (
	Auto     = "auto"     // runs straight away, still audited, recorded and announced
	Required = "required" // a teammate approves, like any exec
)

// Redaction modes.
const RedactEnv = "env" // hide the values of KEY=VALUE lines that look secret

// Action is one predefined command.
type Action struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Command     []string `json:"command"`
	Approval    string   `json:"approval,omitempty"`   // auto or required (default)
	Redact      string   `json:"redact,omitempty"`     // "" or env
	Namespaces  []string `json:"namespaces,omitempty"` // empty means every namespace ostiara serves
}

// Catalog is the set of actions on offer.
type Catalog struct {
	Actions []Action `json:"actions"`
}

// Defaults are offered when no catalog file is configured.
var Defaults = Catalog{Actions: []Action{
	{Name: "ps", Description: "List running processes", Command: []string{"ps"}, Approval: Auto},
	{Name: "df", Description: "Disk usage", Command: []string{"df", "-h"}, Approval: Auto},
	{Name: "env", Description: "Environment variables, with secret-looking values hidden", Command: []string{"env"}, Approval: Required, Redact: RedactEnv},
}}

var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Load reads a YAML or JSON catalog; a missing file means the defaults.
func Load(path string) (Catalog, error) {
	if path == "" {
		return Defaults, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Defaults, nil
	}
	if err != nil {
		return Catalog{}, err
	}
	var c Catalog
	if err := yaml.UnmarshalStrict(data, &c); err != nil {
		return Catalog{}, fmt.Errorf("actions catalog %s: %w", path, err)
	}
	return c, c.Validate()
}

// Validate rejects a catalog with unclear or unsafe entries.
func (c Catalog) Validate() error {
	seen := map[string]bool{}
	for i, a := range c.Actions {
		switch {
		case !validName.MatchString(a.Name):
			return fmt.Errorf("action %d: name %q must be lowercase letters, digits and dashes", i, a.Name)
		case seen[a.Name]:
			return fmt.Errorf("action %q is defined twice", a.Name)
		case len(a.Command) == 0 || a.Command[0] == "":
			return fmt.Errorf("action %q has no command", a.Name)
		case a.Approval != "" && a.Approval != Auto && a.Approval != Required:
			return fmt.Errorf("action %q: approval must be auto or required", a.Name)
		case a.Redact != "" && a.Redact != RedactEnv:
			return fmt.Errorf("action %q: redact must be empty or env", a.Name)
		}
		seen[a.Name] = true
	}
	return nil
}

// Find returns the named action if it's offered in namespace.
func (c Catalog) Find(name, namespace string) (Action, bool) {
	for _, a := range c.Actions {
		if a.Name == name && (len(a.Namespaces) == 0 || slices.Contains(a.Namespaces, namespace)) {
			if a.Approval == "" {
				a.Approval = Required
			}
			return a, true
		}
	}
	return Action{}, false
}
