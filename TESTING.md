# Testing

Run repository validation:

```sh
pnpm test
pnpm typecheck
pnpm build
```

## Fake stdio backend smoke test

Use the fake stdio backend for deterministic local checks of Levitate's HTTP proxy and policy behavior:

```sh
export LEVITATE_TOKEN="dev-secret"
pnpm build
pnpm start -- --config config/fake-stdio.toml
```

Server listens on port `8790`.
In another terminal, check deployment endpoints:

```sh
curl http://127.0.0.1:8790/health
curl http://127.0.0.1:8790/ready
```

Connect MCP Inspector over Streamable HTTP with bearer authentication:

```sh
npx -y @modelcontextprotocol/inspector@0.22.0 \
  --cli \
  --transport http \
  --header "Authorization: Bearer ${LEVITATE_TOKEN}" \
  -- http://127.0.0.1:8790/mcp \
  --method tools/list
```

Call the allowed tool:

```sh
npx -y @modelcontextprotocol/inspector@0.22.0 \
  --cli \
  --transport http \
  --header "Authorization: Bearer ${LEVITATE_TOKEN}" \
  -- http://127.0.0.1:8790/mcp \
  --method tools/call \
  --tool-name fake_allowed \
  --tool-arg message=hello
```

Call the denied tool directly:

```sh
npx -y @modelcontextprotocol/inspector@0.22.0 \
  --cli \
  --transport http \
  --header "Authorization: Bearer ${LEVITATE_TOKEN}" \
  -- http://127.0.0.1:8790/mcp \
  --method tools/call \
  --tool-name fake_denied
```

Expected result:

- initialization succeeds
- `tools/list` advertises `fake_allowed`
- `fake_denied` is not advertised
- calling `fake_allowed` returns fixture JSON
- directly calling `fake_denied` returns an MCP tool error from Levitate

Automated coverage:

```sh
pnpm test test/mcp.test.ts
```

## Real backend smoke test

Test Levitate against any real stdio MCP backend using an ignored local config.
This is optional for normal development and CI.
Choose one safe allowed tool and one denied tool for policy testing.
Copy the documented bearer example, then replace its `[stdio]` command and tool policy with values for the real backend:

```sh
cp config/bearer.example.toml config/bearer.local.toml
```

```sh
export LEVITATE_TOKEN="$(openssl rand -hex 32)"
export LEVITATE_CONFIG="config/bearer.local.toml"
export LEVITATE_SMOKE_URL="http://127.0.0.1:8787/mcp"
export LEVITATE_SAFE_TOOL="example_safe_tool"
export LEVITATE_DENIED_TOOL="example_denied_tool"
pnpm build
pnpm start -- --config "$LEVITATE_CONFIG"
```

Set `LEVITATE_SMOKE_URL` from `server.port` and `server.mcp_path` in the copied config if either value differs from the example.

In another terminal, connect MCP Inspector:

```sh
npx -y @modelcontextprotocol/inspector@0.22.0 \
  --cli \
  --transport http \
  --header "Authorization: Bearer ${LEVITATE_TOKEN}" \
  -- "$LEVITATE_SMOKE_URL" \
  --method tools/list
```

Call a safe read-only tool:

```sh
npx -y @modelcontextprotocol/inspector@0.22.0 \
  --cli \
  --transport http \
  --header "Authorization: Bearer ${LEVITATE_TOKEN}" \
  -- "$LEVITATE_SMOKE_URL" \
  --method tools/call \
  --tool-name "$LEVITATE_SAFE_TOOL"
```

Call a denied tool directly:

```sh
npx -y @modelcontextprotocol/inspector@0.22.0 \
  --cli \
  --transport http \
  --header "Authorization: Bearer ${LEVITATE_TOKEN}" \
  -- "$LEVITATE_SMOKE_URL" \
  --method tools/call \
  --tool-name "$LEVITATE_DENIED_TOOL"
```

If a tool requires arguments, add `--tool-arg key=value` entries according to the backend's advertised input schema.

Verify in Inspector:

- initialization succeeds
- `tools/list` shows allowed backend tools
- allowed tool calls work through Levitate
- denied direct calls return an MCP tool error instead of an HTTP error or server crash

MCP Inspector `0.22.0` CLI supports HTTP headers with `--header`, so the smoke test keeps bearer-token authentication enabled.
The browser UI may require entering headers manually; the CLI commands above are the reproducible smoke path.
