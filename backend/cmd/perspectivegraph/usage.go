package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
)

// commands is what the binary answers to, in the order `help` prints it: what someone
// trying the engine reaches for first, then what an operator runs, then the development
// tools. A test keeps it in step with the dispatch in main, because a list that silently
// drifts is worse than no list: it tells someone their spelling was wrong when the
// command actually exists.
var commands = []struct{ name, does string }{
	{"redteam", "ask AWS's own policy evaluator which roles reach administrator (read-only)"},
	{"gate", "judge a change before the merge: exit 0 clean, 1 blocked, 2 not analysed"},
	{"ingest", "send one scanner report to a running engine, signed"},
	{"mcp", "serve the engine's read-only tools to an AI agent, over stdio"},
	{"awscollect", "read an AWS account once and show what the engine finds exposed"},
	{"verify-audit", "verify the audit log's hash chain"},
	{"healthz", "probe the local API and exit 0 or 1 (the container's healthcheck)"},
	{"importverdicts", "record a red-team or BAS report's outcomes against the engine's paths"},
	{"ingestreal", "scan a real vulnerable image with Trivy and place it on a path"},
	{"andprobe", "count the hops on critical paths that need several prerequisites at once"},
	{"genload", "post a large synthetic estate, to measure how the engine scales"},
	{"genverdicts", "post synthetic verdicts from a known scenario, to exercise calibration"},
	{"version", "print which release this binary is"},
	{"help", "print this, or `help <command>` for that command's flags"},
}

// subcommands is the names alone, for the "unknown subcommand" message at the bottom of
// main.
var subcommands = func() []string {
	names := make([]string, len(commands))
	for i, c := range commands {
		names[i] = c.name
	}
	return names
}()

// helpFlag and versionFlag are the spellings people try before reading anything. They are
// answered as the subcommands are, not refused as unknown ones: `--help` printing "unknown
// subcommand" is the first thing a downloaded binary said to whoever tried it.
func helpFlag(arg string) bool {
	return arg == "-h" || arg == "-help" || arg == "--help"
}

func versionFlag(arg string) bool {
	return arg == "-v" || arg == "-version" || arg == "--version"
}

// versionLine is what `version` prints and what the server logs as it starts: the release,
// then the toolchain and the platform it was built for - what a bug report needs first.
func versionLine() string {
	return fmt.Sprintf("perspectivegraph %s (%s, %s/%s)", buildVersion(), runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, versionLine())
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  perspectivegraph                     start the server; its configuration is the environment")
	fmt.Fprintln(w, "  perspectivegraph <command> [flags]   run one command and exit")
	fmt.Fprintln(w, "  perspectivegraph <command> -h        that command's flags")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-15s %s\n", c.name, c.does)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Documentation: https://github.com/luiacuaniello/perspectivegraph#documentation")
}

// fail ends a subcommand that returned an error. Being asked for its flags is not one:
// the flag package has printed them by then, so -h exits 0 and adds nothing.
//
// gate does not come through here, and keeps exiting non-zero on -h: its exit code is a
// verdict, and a gate that printed its flags has analysed nothing.
func fail(name string, err error) {
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	}
	fmt.Fprintln(os.Stderr, name+":", err)
	os.Exit(1)
}
