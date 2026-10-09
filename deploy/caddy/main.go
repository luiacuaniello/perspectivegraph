// Command caddy is Caddy's standard distribution - the same main package as Caddy's own
// cmd/caddy - built from this module so that go.mod, not Caddy's release, decides the
// versions of its dependencies: a fix in one of them ships the day it is published, not the
// day Caddy next releases. See the Dockerfile beside it.
package main

import (
	_ "time/tzdata"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

func main() {
	caddycmd.Main()
}
