# crackweb-mcp

维护者：**coolmoon & guaidao2**

[English](README.md) · **简体中文**

> 给 [crackweb](https://github.com/guaidao2/crackweb) 命令行做的 MCP server：把扫描器自己的子命令，变成客户端可以直接调用的工具。

它负责跑那些命令、把结果整理成数据 —— 调用方不用拼 shell 引号、不用管后台进程的生死、也不用去读"写给人看的"控制台输出。

## 你拿到什么

| 工具 | 作用 |
| --- | --- |
| `list_checks` | 当前二进制里有哪些检查：id、判级、标签、是否 opt-in |
| `scan` | 对单个请求测一次，返回报表里的 findings 与 CLI 的 stderr |
| `crawl` | 先发现页面再扫描 —— 对站点通常第一步就用它 |
| `start_proxy` | 起一个拦截代理并返回地址。**`scope` 必填** |
| `proxy_status` | 返回游标之后确认的 findings，以及代理是否还在跑 |
| `stop_proxy` | 停止代理并交出它找到的全部内容，幂等 |
| `start_oob` | 起一个带外监听，给那些只有"目标回调过来"才能证明的漏洞用 |
| `oob_status` | 返回游标之后收到的回调：时间、协议、来源，以及是哪次注入引起的 |
| `stop_oob` | 停止监听并交出它收到的全部回调 |
| `local_jwt` | 离线：解码 JWT、恢复签名密钥、用你的密钥再造一个 token。不发任何流量 |
| `local_hash` | 离线：识别一个 hash，并在可能时还原出原文 |
| `ca` | 加载或生成拦截用的 CA，并说明它是什么 |

对应命令的**每一个 flag 都是这些工具的参数**。扫描类（`scan` / `crawl` / `start_proxy`）共用一组：`checks`、`enable_unsafe`、`sessions`、`cookies`、`headers`、`basic_auth`、`jwt_secrets`、`proxy`、`request_timeout`、`rate`、`threads`、`sensitivity`、`insecure`、`user_agent`、`random_ua`、`templates`、`skip_params`、`no_normalize`、`verbose`、`no_waf`、`no_assume_waf`、五个 `oob_*` 地址、`report_path`，以及 `timeout_s`（这一次工具调用最多等多久）。`crawl` 另有 `depth`、`engine`、`max_pages`、`scope`、`api_docs`、`no_discovery`、`allow_state_change`；`start_proxy` 另有 `listen`、`upstream`、`passive_only`、`export_ca`。

每个返回值还都带 `processes`：现在有什么在跑、你游标之后还等着多少 —— 即使调用方从没想过要问，也能看到"有东西出来了"。

## 安装

```sh
pipx install git+https://github.com/guaidao2/crackweb-mcp@v0.3.0
# 或者从检出的代码装：
pip install .
```

需要 Python 3.10+、一个 MCP 客户端，以及一个 crackweb 二进制（v1.6.8 以上）；依赖只有 `mcp`。用 `CRACKWEB_BIN` 指定二进制，或者把 `crackweb` 放进 `PATH`。

### 什么都不装，直接跑

发行版 Python 会因为 PEP 668 拒绍 `pip install .`（Kali、Debian、Ubuntu 默认都如此），而有些机器上也没有 pipx —— 那就直接在仓库里跑：

```sh
git clone https://github.com/guaidao2/crackweb-mcp
cd crackweb-mcp
python3 server.py /path/to/crackweb
```

这就是同一个 server：脚本把 `src/` 挂进 import 路径、把你给的二进制写进 `CRACKWEB_BIN`，然后用 stdio 说 MCP。依赖依旧只有 MCP SDK；如果它 import 不到，脚本会把补救命令直接打出来（包括不动系统 Python 的那种）。

## 配置客户端

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

## 代理那组工具（最值得读的部分）

crackweb 测的是经过它代理的流量，所以用法是一个循环：

1. `start_proxy(scope=["example.com"])` → `{proxy_id, listen}`
2. 把产生流量的一端指向 `listen`（`curl -x`、脚本的代理设置）
3. `proxy_status(proxy_id)` → 游标之后确认的 findings，以及下一个游标
4. `stop_proxy(proxy_id)` → 它找到的全部内容

几条"是决定、不是机制"的说明：

- **`scope` 必填。** 它决定代理能拦截哪些主机，其余一律原样透传。这里给默认值会变成"擅自动手"，而不是"仅仅做错"，所以没有默认值。
- **游标单调，且只有 status 调用会推进它。** 连猜两次不会重复给；不传游标就从上次读完的地方继续。别的工具的 `processes` 字段只报"还有多少待读"而不消耗游标 —— 代理是 findings，带外监听是回调。停止会一次性交出全部内容并把游标推到末尾，所以"已停且已读完"的进程不会再出现在别的结果里。
- **代理随本 server 一同退出**，闲置的会自己停（`CRACKWEB_MCP_IDLE_TIMEOUT`，默认 30 分钟，`0` 关闭）。agent 不会记得停代理，所以没有一件事指望它记得；带外监听同此。
- **opt-in 检查需要显式 `enable_unsafe=True`。** 它们会执行页面脚本或写共享缓存；`list_checks` 会把它们标出来，wrapper 不会自己打开。

### findings 是从哪来的

crackweb 没有运行期查询接口：报表是退出时写的。所以 wrapper 把"每条 finding 确认时打印的那一行"重定向到文件，`proxy_status` 读这个文件 —— 这就是为什么代理还在跑就能查，也是为什么 finding 一确认就能看到，而不是等到结束。

两点后果值得一提：

- 流里的 finding 带 severity、title、检查 id、URL、方法，以及名称/值形式的细节（param、payload）。完整证据（响应片段、对照基线）在报表里，而报表要停止之后才有。
- **Windows 上报表可能根本不存在。** crackweb 只在正常退出的路径上写报表，而在 Windows 上被停止的进程跑不到任何代码：代理处理的是 SIGINT 与 SIGTERM，而 Windows 停进程时两者都不会送达。findings 不受影响 —— 它们来自实时流，且 `stop_proxy` 会明确给出 `report_written: false` 与 `report_note`，而不是装作一切正常。

## 环境变量

| 变量 | 含义 |
| --- | --- |
| `CRACKWEB_BIN` | crackweb 二进制；没给就找 `PATH` |
| `CRACKWEB_MCP_IDLE_TIMEOUT` | 多久没被过问就停掉代理（秒），默认 `1800`，`0` 关闭 |
| `CRACKWEB_MCP_TMP` | 一次运行的日志放在哪，默认系统临时目录 |

## 开发

```sh
python -m pytest                 # 单测：替身二进制，不需要靶场与浏览器
python scripts/acceptance.py     # 需要真的 crackweb 二进制，见脚本内注释
```

替身二进制是 `tests/fake_crackweb.py`：它按 crackweb 的样子打印 finding、被停止时写出报表 —— 所以参数拼接、解析、游标与进程生命周期，都是拿真进程验的。

## 边界

- 代理那组只报发现，不报流量：调用方本来就知道自己发了什么，而 crackweb 不对外暴露可读的流量表。
- `scan` 与 `crawl` 会一直阻塞到扫完；长任务请传 `timeout_s`，或改用代理 + `proxy_status` 轮询。
- 这些工具就是扫描器自己的命令：crackweb 做不到的，这里也做不到。
- 如果 server 被强杀（`SIGKILL`，或 Windows 的 `TerminateProcess`），它起的代理会残留：那条路径上没有任何代码会执行。正常停止，或者在强杀后检查一下有没有残留进程。

## 许可

MIT，见 [LICENSE](LICENSE)。
