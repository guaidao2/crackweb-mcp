# crackweb-mcp

Maintained by **coolmoon & guaidao2**

**English** · [简体中文](README.zh-CN.md)

> An MCP server for the [crackweb](https://github.com/guaidao2/crackweb) CLI: the scanner's
> own commands, as tools a client can call.

It runs those commands and returns their results as data, so a caller never has to quote
shell arguments, keep a background process alive, or read console output that was written
for a person.

## What you get

| Tool | What it does |
| --- | --- |
| `list_checks` | Every check the installed binary offers: id, severity, tags, and whether it is opt-in. |
| `scan` | Test one request once; returns the report's findings and what the CLI said on stderr. |
| `crawl` | Discover a target's pages and test them — usually the first call against a site. |
| `start_proxy` | Start an intercepting proxy and return its address. **Scope is required.** |
| `proxy_status` | Findings confirmed since your cursor, and whether the proxy is still running. |
| `stop_proxy` | Stop the proxy and return everything it found. Safe to call twice. |
| `start_oob` | Start an out-of-band listener, for the vulnerabilities that are only provable by a callback. |
| `oob_status` | Callbacks collected since your cursor: when, over which protocol, from where, and which injection caused them. |
| `stop_oob` | Stop the listener and return every callback it collected. |
| `local_jwt` | Offline: decode a JSON Web Token, recover its signing key, and sign one of your own. Nothing is sent. |
| `local_hash` | Offline: identify a hash and try to recover what it was made from. |
| `ca` | Load or generate the interception certificate authority, and say what it is. |

Every flag the corresponding command takes is a parameter of these tools. The scanning ones —
`scan`, `crawl`, `start_proxy` — share one set: `checks`, `enable_unsafe`, `sessions`,
`cookies`, `headers`, `basic_auth`, `jwt_secrets`, `proxy`, `request_timeout`, `rate`,
`threads`, `sensitivity`, `insecure`, `user_agent`, `random_ua`, `templates`, `skip_params`,
`no_normalize`, `verbose`, `no_waf`, `no_assume_waf`, the five `oob_*` addresses,
`report_path`, and `timeout_s` for the call itself. `crawl` adds `depth`, `engine`,
`max_pages`, `scope`, `api_docs`, `no_discovery` and `allow_state_change`; `start_proxy` adds
`listen`, `upstream`, `passive_only` and `export_ca`.

Every result also carries `processes`: what is running, and how much is waiting after your
cursor. A caller that never thinks to ask still sees that something arrived.

## Install

```sh
pipx install git+https://github.com/guaidao2/crackweb-mcp@v0.3.0
# from a checkout:
pip install .
```

Needs Python 3.10+, an MCP client, and a crackweb binary (v1.6.8 or later). `mcp` is the
only dependency. Point at the binary with `CRACKWEB_BIN`, or put `crackweb` on `PATH`.

### Running it without installing anything

On a distribution Python that refuses `pip install .` — PEP 668, which is Kali, Debian and
Ubuntu by default — or anywhere a checkout is simpler than an install, the server runs
straight from the tree:

```sh
git clone https://github.com/guaidao2/crackweb-mcp
cd crackweb-mcp
python3 server.py /path/to/crackweb
```

It is the same server: it puts `src/` on the import path, points `CRACKWEB_BIN` at the
binary you named, and speaks MCP over stdio. The dependency is still the MCP SDK, and if it
is not importable the script says exactly how to get it — including the route that leaves
the system Python alone.

## Point a client at it

```json
{
  "mcpServers": {
    "crackweb": {
      "command": "crackweb-mcp",
      "env": { "CRACKWEB_BIN": "/path/to/crackweb" }
    }
  }
}
```

## The proxy tools, which are the ones worth reading about

crackweb tests traffic that passes through its proxy, so the loop is:

1. `start_proxy(scope=["example.com"])` → `{proxy_id, listen}`
2. point whatever generates traffic at `listen` (`curl -x`, a script's proxy setting)
3. `proxy_status(proxy_id)` → findings confirmed since the cursor, and the next cursor
4. `stop_proxy(proxy_id)` → everything it found

Notes on the pieces that are decisions rather than mechanics:

- **`scope` is required.** It is the list of host patterns the proxy may intercept;
  everything else is tunnelled untouched. A default here would be intrusive rather than
  merely wrong, so there is none.
- **The cursor is monotonic and only a status call moves it.** Calling status twice returns
  nothing twice; omitting the cursor continues from the last read. Every other tool's
  `processes` field reports how much is *waiting* without consuming it — for a proxy that is
  findings, for the out-of-band listener that is callbacks. Stopping hands everything over at
  once and moves the cursor to the end, so a process that has been stopped and read stops
  appearing in other results.
- **The proxy dies with this server**, and an idle one is stopped on its own
  (`CRACKWEB_MCP_IDLE_TIMEOUT`, default 30 minutes, `0` disables). An agent will not
  remember to stop a proxy, so nothing depends on it remembering. The out-of-band listener is
  held the same way.
- **Opt-in checks need `enable_unsafe=True`.** These run page scripts or write to a shared
  cache; `list_checks` marks them, and the wrapper never turns them on by itself.

### Where the findings come from

crackweb has no runtime query interface: its report is written when it exits. So the
wrapper redirects the stream crackweb prints as each finding is confirmed to a file, and
`proxy_status` reads that file — which is why status works while the proxy is still up,
and why a finding appears the moment it is confirmed rather than at the end.

Two consequences worth knowing:

- Findings from the stream carry severity, title, check id, URL, method, and the
  name/value details (param, payload). The full evidence — the response excerpt, the
  baseline it was compared against — is in the report, which exists after a stop.
- **On Windows the report may not exist at all.** crackweb writes its report on the way
  out, and a process stopped on Windows runs no code: the proxy handles SIGINT and SIGTERM,
  neither of which Windows delivers to a process being stopped. The findings are unaffected
  — they come from the stream, and `stop_proxy` says `report_written: false` with a
  `report_note` rather than pretending otherwise.

## Environment

| Variable | Meaning |
| --- | --- |
| `CRACKWEB_BIN` | The crackweb binary. Falls back to `PATH`. |
| `CRACKWEB_MCP_IDLE_TIMEOUT` | Seconds before an untouched process is stopped. Default `1800`, `0` disables. |
| `CRACKWEB_MCP_TMP` | Where a run's logs live. Default: the system temp directory. |

## Development

```sh
python -m pytest                 # unit tests: a stand-in binary, no lab, no browser
python scripts/acceptance.py     # needs a real crackweb binary; see its docstring
```

The stand-in binary is `tests/fake_crackweb.py`: it prints findings the way crackweb does
and writes a report when it is stopped, so argument building, parsing, cursors and process
lifetime are all exercised against real processes.

## Limits

- The proxy tools report findings, not traffic: a caller already knows what it sent, and
  crackweb exposes no traffic table to read.
- `scan` and `crawl` block until the scan finishes. Pass `timeout_s`, or use a proxy with
  `proxy_status` polling for anything long.
- The tools are the scanner's own commands: what crackweb cannot do, these cannot do
  either.
- If the server is killed outright — `SIGKILL`, or `TerminateProcess` on Windows — the
  proxy it started outlives it: no code runs on that path, so nothing gets the chance to
  stop it. Stop proxies normally, or check for a stray process after a hard kill.

## License

MIT — see [LICENSE](LICENSE).
