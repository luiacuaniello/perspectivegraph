package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/luiacuaniello/perspectivegraph/internal/mcp"
)

// runMCP serves the attack-path engine as MCP tools on stdio, so an AI agent can
// query it the way it queries a filesystem or a browser.
//
//	perspectivegraph mcp --api http://localhost:8080
//
// It is a client of the running engine, not a second copy of it: every answer goes
// through the same GraphQL API the dashboard uses, so tenancy, auth and scoring
// cannot drift between what a human sees and what an agent is told.
//
// Wiring it into an agent (Claude Desktop, Claude Code, any MCP client) is a stanza
// like:
//
//	{"mcpServers": {"perspectivegraph": {
//	   "command": "perspectivegraph",
//	   "args": ["mcp", "--api", "http://localhost:8080"],
//	   "env": {"API_TOKEN": "…"}}}}
//
// stdout is the protocol channel and must stay clean: every diagnostic goes to
// stderr, and a stray Println here corrupts the session.
func runMCP(args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	api := fs.String("api", envOr("PG_API_URL", "http://localhost:8080"), "PerspectiveGraph API base URL")
	token := fs.String("token", os.Getenv("API_TOKEN"), "bearer token, if the API requires auth")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Ctrl-C and SIGTERM end the session cleanly; agents start and stop these
	// processes constantly, and a server that ignores the signal gets killed mid-write.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client := mcp.NewAPI(*api, *token)
	srv := mcp.NewServer("perspectivegraph", buildVersion(), mcp.Tools(client))

	fmt.Fprintf(os.Stderr, "perspectivegraph mcp: serving %d tools against %s\n", len(mcp.Tools(client)), *api)
	if err := srv.Serve(ctx, os.Stdin, os.Stdout); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

// buildVersion reports the version stamped into the binary by the Go toolchain
// (module version, or the VCS revision for a local build). Nothing injects a
// version at link time here, so reading build info keeps this honest rather than
// hardcoding a number that drifts from reality.
func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && len(s.Value) >= 7 {
			return s.Value[:7]
		}
	}
	return "dev"
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
