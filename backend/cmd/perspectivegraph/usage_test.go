package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// What a downloaded binary says to the first things people type at it. Each case runs the
// real main() in a child process, because what is being checked - the exit code, and which
// stream the answer goes to - exists only there.
func TestFirstContactWithTheBinary(t *testing.T) {
	if args, ok := os.LookupEnv("PG_TEST_MAIN_ARGS"); ok {
		os.Args = append([]string{"perspectivegraph"}, strings.Fields(args)...)
		main()
		return
	}

	for _, tc := range []struct {
		args    string
		exit    int
		stdout  string // must appear on stdout
		stderr  string // must appear on stderr
		refused string // must appear on neither
	}{
		{args: "--help", stdout: "Commands:", refused: "unknown subcommand"},
		{args: "-h", stdout: "Commands:"},
		{args: "help", stdout: "perspectivegraph <command> -h"},
		{args: "help help", stdout: "Commands:"},
		{args: "version", stdout: "perspectivegraph "},
		{args: "--version", stdout: "perspectivegraph ", refused: "unknown subcommand"},

		// A command's flags, asked for either way, are an answer and not a failure.
		{args: "help redteam", stderr: "Usage of redteam", refused: "help requested"},
		{args: "redteam -h", stderr: "Usage of redteam", refused: "help requested"},
		{args: "mcp -h", stderr: "Usage of mcp", refused: "help requested"},
		{args: "ingest -h", stderr: "usage: perspectivegraph ingest", refused: "help requested"},
		{args: "verify-audit -h", stderr: "Usage of verify-audit", refused: "help requested"},
		// healthz takes no flags; -h must describe it, not go and probe a server.
		{args: "healthz -h", stdout: "usage: perspectivegraph healthz", refused: "connection refused"},

		// The gate's exit code is a verdict, so printing its flags is not a clean one.
		{args: "gate -h", exit: gateExitError, stderr: "Usage of gate"},
		// And a name nobody answers to is still refused, also when asked for its help.
		{args: "frobnicate", exit: gateExitError, stderr: `unknown subcommand "frobnicate"`},
		{args: "help frobnicate", exit: gateExitError, stderr: `unknown subcommand "frobnicate"`},
	} {
		t.Run(tc.args, func(t *testing.T) {
			// A case that fell through to the server would wait on NATS; do not wait with it.
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFirstContactWithTheBinary$")
			cmd.Env = append(os.Environ(), "PG_TEST_MAIN_ARGS="+tc.args)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()

			exit := 0
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				exit = ee.ExitCode()
			} else if err != nil {
				t.Fatalf("could not run it: %v", err)
			}
			if exit != tc.exit {
				t.Errorf("exit %d, want %d\nstdout: %s\nstderr: %s", exit, tc.exit, &stdout, &stderr)
			}
			if tc.stdout != "" && !strings.Contains(stdout.String(), tc.stdout) {
				t.Errorf("stdout lacks %q:\n%s", tc.stdout, &stdout)
			}
			if tc.stderr != "" && !strings.Contains(stderr.String(), tc.stderr) {
				t.Errorf("stderr lacks %q:\n%s", tc.stderr, &stderr)
			}
			if tc.refused != "" && strings.Contains(stdout.String()+stderr.String(), tc.refused) {
				t.Errorf("it said %q:\nstdout: %s\nstderr: %s", tc.refused, &stdout, &stderr)
			}
		})
	}
}

// `help` is only as good as its list: a command missing from it does not exist for
// whoever reads it, and one without a description might as well be missing.
func TestHelpDescribesEveryCommand(t *testing.T) {
	var out bytes.Buffer
	printUsage(&out)

	seen := map[string]bool{}
	for _, c := range commands {
		if seen[c.name] {
			t.Errorf("%q is listed twice", c.name)
		}
		seen[c.name] = true
		if strings.TrimSpace(c.does) == "" {
			t.Errorf("%q has no description", c.name)
		}
		if !strings.Contains(out.String(), "  "+c.name+" ") {
			t.Errorf("help does not list %q:\n%s", c.name, &out)
		}
	}
	if !strings.HasPrefix(out.String(), versionLine()) {
		t.Errorf("help does not open with the version:\n%s", &out)
	}
}

// A release build is stamped with its tag; whatever the build, the answer is never empty,
// because "which version?" is the first question of every report.
func TestVersionLineNamesTheBuild(t *testing.T) {
	if got := versionLine(); !strings.HasPrefix(got, "perspectivegraph "+buildVersion()+" (go") {
		t.Errorf("versionLine() = %q", got)
	}
	if buildVersion() == "" {
		t.Error("buildVersion() is empty")
	}

	old := releaseVersion
	t.Cleanup(func() { releaseVersion = old })
	releaseVersion = "v9.9.9"
	if got := versionLine(); !strings.HasPrefix(got, "perspectivegraph v9.9.9 (") {
		t.Errorf("a stamped build answers %q", got)
	}
}

// docs/API-STABILITY.md promises what will not break without a major version, and it
// names the scanner endpoints and the subcommands one by one. It had fallen four
// collectors and five subcommands behind the binary - the gate among them, whose exit
// code is the most depended-on interface the project has. A promise that does not list
// what ships covers nothing, so the list is held to the code here.
func TestAPIStabilityNamesWhatTheBinaryAnswersTo(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/API-STABILITY.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)

	for _, c := range ingestCollectors() {
		if !strings.Contains(doc, "`"+c.Source()+"`") {
			t.Errorf("POST /ingest/%s is served and docs/API-STABILITY.md does not name it", c.Source())
		}
	}
	for _, c := range commands {
		if !strings.Contains(doc, "`"+c.name+"`") {
			t.Errorf("`perspectivegraph %s` exists and docs/API-STABILITY.md does not name it", c.name)
		}
	}
	// The change report the gate reads and the ingest webhook does not.
	if !strings.Contains(doc, "`terraform`") {
		t.Error("the gate reads Terraform plans and docs/API-STABILITY.md does not name the source")
	}
}
