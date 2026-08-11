// Command groundwork is the operator CLI for Groundwork deployments.
//
// Subcommands:
//
//	groundwork init [--dir <path>] [--template <name>] [--force]
//	    Scaffold a sovereign deployment directory: groundwork.env with
//	    generated key material, an RSA delegation key pair, a validated
//	    starter policy (policy.json), and a short README.
//
//	groundwork doctor [--env-file <path>] [--json] [--timeout-ms <ms>]
//	    Check a deployment's configuration and live dependencies
//	    (signing keys, deployment rules, tenancy, database, SpiceDB,
//	    Qdrant, Elasticsearch, outbox webhook). Exits non-zero when any
//	    check fails, so it can run in CI or a release gate.
//
//	groundwork templates
//	    List the embedded starter policy templates.
//
// Examples:
//
//	groundwork init --template finance-agent --dir ./deploy/uk
//	groundwork doctor --env-file ./deploy/uk/groundwork.env
package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

//go:embed templates/*.json
var templateFS embed.FS

const (
	exitOK    = 0
	exitCheck = 1
	exitUsage = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "init":
		return runInit(args[1:], stdout, stderr)
	case "doctor":
		return runDoctor(args[1:], stdout, stderr)
	case "templates":
		return runTemplates(stdout)
	case "-h", "--help", "help":
		usage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		usage(stderr)
		return exitUsage
	}
}

func usage(out io.Writer) {
	fmt.Fprint(out, `groundwork — operator CLI for sovereign Groundwork deployments

Usage:
  groundwork init [--dir <path>] [--template <name>] [--force]
      Scaffold a deployment directory (env, keys, starter policy).
  groundwork doctor [--env-file <path>] [--json] [--timeout-ms <ms>]
      Validate configuration and live dependencies. Exit 1 on failure.
  groundwork templates
      List embedded starter policy templates.
  groundwork -h | help
      Show this help.
`)
}

func runTemplates(stdout io.Writer) int {
	templates, err := loadTemplates()
	if err != nil {
		fmt.Fprintf(stdout, "error: %v\n", err)
		return exitCheck
	}
	names := make([]string, 0, len(templates))
	for name := range templates {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t := templates[name]
		ro := ""
		if t.ReadOnly {
			ro = " read-only"
		}
		fmt.Fprintf(stdout, "%-22s [%s%s] %s\n", t.Name, t.Region, ro, t.Description)
	}
	return exitOK
}

func loadTemplates() (map[string]PolicyTemplate, error) {
	entries, err := templateFS.ReadDir("templates")
	if err != nil {
		return nil, fmt.Errorf("read embedded templates: %w", err)
	}
	out := map[string]PolicyTemplate{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := templateFS.ReadFile("templates/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("read template %s: %w", e.Name(), err)
		}
		var t PolicyTemplate
		if err := json.Unmarshal(data, &t); err != nil {
			return nil, fmt.Errorf("parse template %s: %w", e.Name(), err)
		}
		if problems := t.Validate(); len(problems) > 0 {
			return nil, fmt.Errorf("template %s invalid: %s", e.Name(), strings.Join(problems, "; "))
		}
		out[t.Name] = t
	}
	return out, nil
}
