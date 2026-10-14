# crackweb-mcp

An MCP server for [crackweb](https://github.com/guaidao2/crackweb): it runs the scanner's
CLI and hands an agent the results as data.

crackweb itself is not changed by any of this. It is a wrapper — the same binary, the same
checks, with three things taken care of that a caller should not have to think about: the
shell quoting, the lifetime of the proxy process, and reading findings out of a console
stream that was written for a person.

## What you get

| Tool | What it does |
| --- | --- |
| `list_checks` | Every check the installed binary offers: id, severity, tags, and whether it is opt-in. |
| `scan` | Test one URL once; returns the report's findings and what the CLI said on stderr. |
| `crawl` | Discover a target's pages and test them — usually the first call against a site. |
| `start_proxy` | Start an intercepting proxy and return its address. **Scope is required.** |
| `proxy_status` | Findings confirmed since your cursor, and whether the proxy is still running. |
| `stop_proxy` | Stop the proxy and return everything it found. Safe to call twice. |

Every result also carries `proxies`: what is running, and how many findings are waiting
after your cursor. A caller that never thinks to ask still sees that something was found.

## Install

```sh
pipx install git+https://github.com/guaidao2/crackweb-mcp@v0.1.0
# from a checkout:
pip install .
```

Needs Python 3.10+, an MCP client, and a crackweb binary (v1.6.8 or later). `mcp` is the
only dependency. Point at the binary with `CRACKWEB_BIN`, or put `crackweb` on `PATH`.

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

Nothing here asks a client to behave in a particular way. The tools describe themselves,
and no tool description asks to be called on a schedule — a promise this server could not
keep. What it can do is make the cheap question cheap.

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
- **The cursor is monotonic and only `proxy_status` moves it.** Calling status twice
  returns nothing twice; omitting the cursor continues from the last read. Every other
  tool's `proxies` field reports how much is *waiting* without consuming it.
- **The proxy dies with this server**, and an idle one is stopped on its own
  (`CRACKWEB_MCP_IDLE_TIMEOUT`, default 30 minutes, `0` disables). An agent will not
  remember to stop a proxy, so nothing depends on it remembering.
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
  out, and stops the way it can be stopped there run no code: the proxy handles SIGINT and
  SIGTERM, neither of which Windows delivers to a process that is being stopped. The
  findings are unaffected — they come from the stream, and `stop_proxy` says
  `report_written: false` with a `report_note` rather than pretending otherwise.

## Environment

| Variable | Meaning |
| --- | --- |
| `CRACKWEB_BIN` | The crackweb binary. Falls back to `PATH`. |
| `CRACKWEB_MCP_IDLE_TIMEOUT` | Seconds before an untouched proxy is stopped. Default `1800`, `0` disables. |
| `CRACKWEB_MCP_TMP` | Where a run's logs live. Default: the system temp directory. |

## Development

```sh
python -m pytest                 # unit tests: a stand-in binary, no lab, no browser
python scripts/acceptance.py     # needs a real crackweb binary; see its docstring
```

The stand-in binary is `tests/fake_crackweb.py`: it prints findings the way crackweb does
and writes a report when it is stopped, so the wrapper's own behaviour — argument
building, parsing, cursors, process lifetime — is tested against real processes.

## Limits

- The proxy tools report findings; they do not report traffic. A caller already knows what
  it sent, and crackweb does not expose a traffic table to read.
- `scan` and `crawl` block until the scan finishes. Pass `timeout_s`, or use a proxy with
  `proxy_status` polling for anything long.
- Checks are not reimplemented here in any form, so anything crackweb cannot do, these
  tools cannot do either.

## 简体中文

给 [crackweb](https://github.com/guaidao2/crackweb) 用的 MCP server：把扫描器的 CLI 变成 agent 可以直接调用的工具。

**crackweb 一行都不用改** —— 这是外壳：同一个二进制、同一套检查，只是替你处理三件不该让调用方操心的事：shell 引号、代理进程的生命周期、以及从"写给人看的控制台输出"里把 findings 读出来。

**工具清单**：`list_checks`（有哪些检查、判级、标签、是否 opt-in）、`scan`（单 URL 扫一次）、`crawl`（发现页面再扫描，通常第一步就用它）、`start_proxy` / `proxy_status` / `stop_proxy`（代理三件套）。每个返回值都带 `proxies` 字段，说明现在有什么在跑、还有多少 findings 等着被读 —— 不靠调用方"记得问"。

**代理那套的用法**：`start_proxy(scope=[...])` 拿到 `{proxy_id, listen}` → 把自己的脚本/curl 的代理指过去 → `proxy_status` 读游标之后的 findings → `stop_proxy` 收尾。几个设计点：`scope` **必填**（它决定代理能拦截哪些主机，别的原样透传；这里给默认值会变成"擅自动手"，所以没有默认值）；**游标单调、只有 `proxy_status` 会推进它**（重复调用不会重复给，别的工具只报"还有多少待读"而不消耗）；**代理随本 server 一同退出**，闲置也会自己停（`CRACKWEB_MCP_IDLE_TIMEOUT`，默认 30 分钟，`0` 关闭）；opt-in 检查（会执行页面脚本或写共享缓存的那些）必须显式 `enable_unsafe=True`，外壳绝不自己打开。

**findings 从哪来**：crackweb 没有运行期查询接口（报表是退出时写的），所以外壳把"每条 finding 确认时打印的那一行"重定向到文件，`proxy_status` 读这个文件 —— 这就是为什么代理还在跑就能查、而且 finding 一确认就能看到。两点要知道：流里的 finding 带 severity/title/检查名/URL/方法/参数与 payload，完整的证据（响应片段、对照基线）在退出后的报表里；**Windows 上报表可能没有** —— crackweb 只在正常退出路径上写报表，而 Windows 上停进程时它跑不到任何代码，返回值会明确给出 `report_written: false` 与 `report_note`，findings 本身不受影响（来自流）。

安装：`pipx install git+https://github.com/guaidao2/crackweb-mcp@v0.1.0`，需要 Python 3.10+ 与一个 crackweb 二进制（v1.6.8 以上），依赖只有 `mcp`。

## License

MIT — see [LICENSE](LICENSE).
