#!/usr/bin/env bash
# Print the official MCP Registry entry (server.json) for one release.
#
#   scripts/mcp-server-json.sh 1.13.3 > server.json
#
# The entry is generated, not committed, because two of its fields ARE the release: the
# version and the image tag the registry hands to a client. A server.json checked into the
# tree is right for exactly one release and wrong from the next merge on - the same reason
# the chart's appVersion is bumped by release-please rather than edited by hand. The
# publish-images workflow renders it from the tag being published; TestMCPRegistryEntry
# holds its fields to the code: the name to the backend image's
# io.modelcontextprotocol.server.name label (the registry refuses an image whose label
# differs), `--api` to the flag `perspectivegraph mcp` defines, API_TOKEN to the variable
# it reads.
#
# The image is the backend image, which is also the MCP server: `mcp` is a subcommand of
# the same binary. It is a client of a running engine, and the description says so.
set -euo pipefail

version="${1:-}"
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: $0 X.Y.Z   (a stable release version, without the leading v)" >&2
  exit 2
fi

cat <<JSON
{
  "\$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
  "name": "io.github.luiacuaniello/perspectivegraph",
  "title": "PerspectiveGraph",
  "description": "Read-only attack-path tools: reachable routes to sensitive assets, and what a fix would cut.",
  "repository": {
    "url": "https://github.com/luiacuaniello/perspectivegraph",
    "source": "github"
  },
  "version": "${version}",
  "packages": [
    {
      "registryType": "oci",
      "identifier": "ghcr.io/luiacuaniello/perspectivegraph:v${version}",
      "transport": { "type": "stdio" },
      "packageArguments": [
        { "type": "positional", "value": "mcp" },
        {
          "type": "named",
          "name": "--api",
          "value": "{api_url}",
          "description": "Base URL of a running PerspectiveGraph API; the MCP server is a client of it.",
          "isRequired": true,
          "variables": {
            "api_url": {
              "description": "e.g. http://host.docker.internal:8080 for an engine on the same machine",
              "isRequired": true,
              "default": "http://host.docker.internal:8080"
            }
          }
        }
      ],
      "environmentVariables": [
        {
          "name": "API_TOKEN",
          "description": "Bearer token, when the PerspectiveGraph API requires authentication.",
          "isRequired": false,
          "isSecret": true
        }
      ]
    }
  ]
}
JSON
