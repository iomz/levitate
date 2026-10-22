# Testing

Run repository validation:

```sh
pnpm test
pnpm typecheck
pnpm build
```

## eMudhra container trust regression

The Dockerfiles pin Node 22.23.4 (including its bundled trust store) and Alpine
`ca-certificates` / `ca-certificates-bundle` 20261020-r0. Host updates do not
update either container trust store. Update these pins together when upgrading.
See the [incident advisory](https://emudhra.we-have-a-problem.com/) and
[Node release](https://github.com/nodejs/node/releases/tag/v22.23.4).

Build a separate candidate tag; this does not replace the running container:

```sh
docker build --pull --no-cache -t levitate:emudhra-20261023 .
docker run --rm -i --entrypoint node levitate:emudhra-20261023 \
  --input-type=module < scripts/check-emudhra.mjs
```

For the ignored local deployment, build with `-f Dockerfile.brain-vault.local`
and tag `levitate-levitate:emudhra-20261023` instead. Run the same check against
that tag. The check exercises native fetch, JOSE JWKS, the compiled CIMD resolver,
and HTTPS with the system CA bundle. Both compromised-chain hosts must produce
certificate trust errors; DNS/connection errors and timeouts fail the check.
Normal HTTPS must return 200 with verification enabled. No production config,
vault, state volumes, or credentials are mounted during these checks.

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
- initialization returns the fixture backend's own instructions, because no `[instructions]` block overrides them
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
