# 防火墙变更上线前检查

给网络管理员使用的上线前检查工具：精确对比**旧规则（当前线上）**与**新规则（待上线）**，
逐条判断新规则中的每条 `allow` 是否放行了旧规则（含默认拒绝）所拒绝的流量，
找出“意外放开的流量”。

附带应急响应工具 **日志解密下载**（`/decrypt`）：现场采集器导出的 AES-256-GCM
加密日志在服务端完成流式认证与解密，完整认证通过后才输出明文附件。

## 快速开始

```bash
docker compose up --build
# 防火墙检查：  http://localhost:8000
# 日志解密下载：http://localhost:8000/decrypt
```

本地开发（无需 Docker）：

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

运行正确性测试（穷举交叉验证，不依赖第三方库）：

```bash
python3 tests/test_exactness.py
```

运行解密功能测试（TestClient 基于 httpx2，已包含在 requirements.txt 中）：

```bash
python3 tests/test_decrypt.py
```

## 规则语义

- 每侧规则集是一个 JSON 数组，**最多 30 条**；
- 规则**按顺序匹配，首条命中生效**；未命中任何规则的流量**默认拒绝**；
- 每条规则字段：

| 字段 | 含义 | 取值 |
|---|---|---|
| `src` | 源地址 | IPv4 CIDR，如 `"10.0.0.0/8"`；单主机 `"10.0.0.1"`（=/32）；`"0.0.0.0/0"` 任意 |
| `dst` | 目的地址 | 同上 |
| `proto` | 协议 | `"tcp"` 或 `"udp"`（不区分大小写） |
| `ports` | 目的端口闭区间 | `[下界, 上界]`，如 `[80, 443]`；单端口可写 `[80, 80]` 或 `80`；范围 0–65535 |
| `action` | 动作 | `"allow"` 或 `"deny"` |
| `comment` | 备注（可选） | 字符串 |

示例：

```json
[
  {"src": "0.0.0.0/0", "dst": "10.0.0.10/32", "proto": "tcp", "ports": [443, 443],
   "action": "allow", "comment": "HTTPS"}
]
```

## 判定方法（精确，非抽样）

每条规则是 (源IP, 目的IP, 端口) 空间中的一个长方体，TCP/UDP 两个协议空间分别处理。
工具对新旧规则集做**长方体精确差集运算**，覆盖全部 2³² × 2³² × 65536 × 2 种组合，
**不使用任何抽样**：

1. 对每条新 `allow` 规则，求其**实际生效区域**＝自身矩形 − 顺序在前的所有新规则（首条匹配语义）；
2. 再减去旧规则集实际放行的区域（旧 allow 规则的生效区域之并）；
3. 剩余区域非空 ⇒ 该规则放开了旧规则（含默认拒绝）拒绝的流量，此时给出一个具体
   **witness**（源/目的 IP、协议、端口）以及该流量在**新旧两侧各自命中的规则**
   （旧侧可能是某条显式 `deny`，也可能是**默认拒绝**）。

多条规则联合覆盖（如两条 /24 合并为一条 /23）、规则顺序变化（含死规则被激活）
均被正确处理。`tests/test_exactness.py` 在小空间内用暴力枚举逐点验证了该算法与
全空间穷举完全等价。

非法输入（JSON 语法、缺字段、CIDR/端口/协议/动作非法、未知字段、超过 30 条等）
会**逐条定位到具体规则**并整体拒绝计算。

## API

- `GET /` — 页面
- `GET /api/example` — 一键载入的变更示例
- `POST /api/diff` — 请求体 `{"old": [...], "new": [...]}`

成功响应：

```json
{
  "ok": true,
  "findings": [
    {"rule_index": 2, "rule_text": "allow tcp 0.0.0.0/0 → 10.0.0.10/32 端口 80-443",
     "comment": "...", "opened": true,
     "witness": {"src": "0.0.0.0", "dst": "10.0.0.10", "proto": "tcp", "port": 81},
     "old_match": {"type": "default_deny"}}
  ],
  "stats": {"old_rules": 7, "new_rules": 6, "new_deny_rules": 1,
            "allow_rules_checked": 5, "opened_rules": 2}
}
```

`old_match` 为 `{"type": "rule", "rule_index": ..., "rule_text": ...}`（命中显式 deny）
或 `{"type": "default_deny"}`（未命中任何旧规则）。校验失败返回
`{"ok": false, "errors": [{"side": "old|new", "rule": 序号, "message": ...}]}`（HTTP 400）。

## 日志解密下载（AES-256-GCM）

应急响应场景：现场采集器导出的加密日志需要解密后进入分析流程，同时要避免
篡改内容混入、避免明文残留在服务器磁盘。页面入口为首页头部的
“应急响应：日志解密下载”，直接访问 `/decrypt`。

**参数约定**

| 项目 | 约定 |
|---|---|
| 算法 | AES-256-GCM（`cryptography` 库），AAD 固定为空 |
| 密文 | 原始密文（不含 tag），最大 **128 MiB**（134217728 字节） |
| nonce | 12 字节，十六进制 24 个字符 |
| tag | 16 字节，十六进制 32 个字符 |
| 密钥 | 服务启动时从 `GCM_KEY_FILE` 指定的 **32 字节文件**读取；缺失或长度不符**拒绝启动** |

**安全性质**

- 上传、认证、下载三阶段全部按 1 MiB 分块**流式**处理，服务端内存占用与文件大小无关；
- 密文仅在**每请求独立**的临时文件中暂存（`mkstemp`，0600，目录 0700）；
  上传中断、认证失败、下载完成或客户端断连，都会清理**本请求**的暂存文件，
  不扫描目录、不误删其他请求的文件；
- **明文不写入任何文件、数据库或日志**：认证阶段的明文块随即丢弃，
  下载阶段的明文块直接流式发往客户端；
- **完整认证通过后才返回成功状态与明文附件**；篡改、截断或超限的输入一律
  返回错误（400/413），不输出任何明文；
- Compose 中暂存目录为 **tmpfs**（仅驻留内存），密钥通过 secret 挂载。

**接口**

- `POST /api/decrypt` — `multipart/form-data`，字段 `file`（密文）、`nonce`、`tag`（hex）。
  认证通过返回 `200` + `application/octet-stream` 附件（`decrypted-<原文件名>`，
  带 `Content-Length`）；失败返回 `{"ok": false, "error": ...}`（400 认证失败/参数非法，413 超限）。
- `GET /api/decrypt/samples` — 演示样例的 nonce/tag（hex）。
- `GET /api/decrypt/samples/{good|tampered|truncated}` — 下载正常 / 篡改 / 截断样例密文。

命令行示例（大文件推荐，浏览器内下载会在客户端内存中缓冲）：

```bash
curl -fS -o decrypted.log \
  -F "file=@ciphertext.bin" \
  -F "nonce=00112233445566778899aabb" \
  -F "tag=0123456789abcdef0123456789abcdef" \
  http://localhost:8000/api/decrypt
```

**配置**

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `GCM_KEY_FILE` | `demo/gcm-demo-key.bin` | 32 字节密钥文件路径（Compose 中挂载为 `/run/secrets/gcm_key`） |
| `GCM_UPLOAD_DIR` | 系统临时目录下 `incident-gcm-uploads` | 密文暂存目录（Compose 中为 tmpfs `/tmp/gcm-uploads`） |

> ⚠ `demo/gcm-demo-key.bin` 仅为演示密钥，随仓库分发；生产环境务必替换为
> 独立分发的密钥文件（修改 Compose 的 `secrets.gcm_key.file` 指向即可）。

## 目录结构

```
app/
  firewall.py        # 核心：校验 + 长方体精确差集判定
  example.py         # 一键载入的变更示例
  decrypt.py         # 日志解密：流式上传/认证/下载、样例、临时文件管理
  main.py            # FastAPI 入口
  static/index.html  # 防火墙检查页（含解密页入口）
  static/decrypt.html# 日志解密下载页
demo/gcm-demo-key.bin    # 演示密钥（32 字节，仅演示用途）
tests/test_exactness.py  # 穷举交叉验证 + 示例与校验测试
tests/test_decrypt.py    # 解密功能测试（往返/篡改/超限/清理/并发/断连）
Dockerfile
docker-compose.yml
```
