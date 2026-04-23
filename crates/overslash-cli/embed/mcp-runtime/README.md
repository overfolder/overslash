# Embedded MCP runtime bundle

This directory holds the pre-built `mcp-runtime.mjs` that `overslash web --mcp-runtime=local`
extracts to a tmpdir and spawns via `node`. It's included into the binary
via `rust-embed` when built with the `mcp` Cargo feature.

The placeholder file is a sentinel so `rust-embed` has a path to compile
against. The real bundle is produced by:

    make build-mcp-runtime

which runs esbuild in `docker/mcp-runtime/` and copies the output here.
`make build-web` invokes that target first, so `overslash web` always
ships a fresh bundle.

Don't commit the built bundle — `.gitignore` keeps it out.
