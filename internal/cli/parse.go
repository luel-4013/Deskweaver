// Package cli implements the Deskweaver command-line interface.
//
// The CLI is advisor-only: it never installs software, elevates privileges,
// writes into the scanned project, or executes project code. The only write it
// performs is the generated review kit, which is committed atomically after the
// plan is complete.
package cli

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type invocation struct {
	command string
	args    []string
	values  map[string][]string
	set     map[string]bool
}

func (inv *invocation) has(name string) bool { return inv.set[name] }

func (inv *invocation) one(name string) string {
	if vs := inv.values[name]; len(vs) > 0 {
		return vs[len(vs)-1]
	}
	return ""
}

func (inv *invocation) bool(name string) (bool, error) {
	if !inv.set[name] {
		return false, nil
	}
	v := inv.one(name)
	if v == "" {
		return true, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("--%s expects true or false, got %q", name, v)
	}
	return b, nil
}

func (inv *invocation) int(name string) (int, error) {
	if !inv.set[name] {
		return 0, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(inv.one(name)))
	if err != nil {
		return 0, fmt.Errorf("--%s expects an integer, got %q", name, inv.one(name))
	}
	return n, nil
}

var boolFlags = map[string]bool{
	"json":            true,
	"offline":         true,
	"no-exec":         true,
	"no-input":        true,
	"untrusted-input": true,
	"redact":          true,
	"no-color":        true,
	"force":           true,
	"no-kit":          true,
	"help":            true,
	"version":         true,
}

var valueFlags = map[string]bool{
	"answers":     true,
	"target":      true,
	"format":      true,
	"profile":     true,
	"sensitivity": true,
	"network":     true,
	"privilege":   true,
	"out":         true,
	"weight":      true,
	"max-files":   true,
	"candidate":   true,
	"workspace":   true,
	"distro":      true,
}

var commands = map[string]bool{
	"plan":       true,
	"scan":       true,
	"bundle":     true,
	"doctor":     true,
	"targets":    true,
	"explain":    true,
	"rules":      true,
	"self-check": true,
	"version":    true,
	"help":       true,
}

func parse(args []string) (*invocation, error) {
	inv := &invocation{values: make(map[string][]string), set: make(map[string]bool)}
	endFlags := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if endFlags {
			inv.args = append(inv.args, a)
			continue
		}
		if a == "--" {
			endFlags = true
			continue
		}
		if a == "-h" || a == "--help" {
			inv.set["help"] = true
			inv.values["help"] = append(inv.values["help"], "true")
			continue
		}
		if a == "-v" || a == "-V" || a == "--version" {
			inv.set["version"] = true
			inv.values["version"] = append(inv.values["version"], "true")
			continue
		}
		if strings.HasPrefix(a, "--") {
			name, raw, hasValue := strings.Cut(a[2:], "=")
			if name == "" {
				return nil, errors.New("empty flag name")
			}
			if boolFlags[name] {
				value := "true"
				if hasValue {
					value = raw
					if _, err := strconv.ParseBool(value); err != nil {
						return nil, fmt.Errorf("--%s expects true or false, got %q", name, raw)
					}
				}
				inv.set[name] = true
				inv.values[name] = append(inv.values[name], value)
				continue
			}
			if !valueFlags[name] {
				return nil, fmt.Errorf("unknown flag --%s", name)
			}
			if !hasValue {
				if i+1 >= len(args) {
					return nil, fmt.Errorf("--%s requires a value", name)
				}
				i++
				raw = args[i]
			}
			if strings.TrimSpace(raw) == "" {
				return nil, fmt.Errorf("--%s requires a non-empty value", name)
			}
			inv.set[name] = true
			inv.values[name] = append(inv.values[name], raw)
			continue
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			return nil, fmt.Errorf("unknown flag %s", a)
		}
		inv.args = append(inv.args, a)
	}

	if len(inv.args) > 0 {
		first := inv.args[0]
		if commands[first] {
			inv.command = first
			inv.args = inv.args[1:]
			return inv, nil
		}
		// Convenience: `deskweaver <project-dir>` behaves like `plan <dir>`.
		// Only a single existing path is accepted; a typo must not silently
		// become a project scan.
		if len(inv.args) == 1 && looksLikeDir(first) {
			inv.command = "plan"
			return inv, nil
		}
		return nil, fmt.Errorf("unknown command %q (run deskweaver --help)", first)
	}
	return inv, nil
}

func looksLikeDir(path string) bool {
	// This is a single stat; keep it in a tiny helper so tests can reason
	// about the convenience behavior.
	return dirExists(path)
}

func dirExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}
