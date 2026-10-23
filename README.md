# BackendSecurityKit 1.0.0

[![tests](https://github.com/Xiudouer/Enterprise-level-permissions-and-auditing-system/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/Xiudouer/Enterprise-level-permissions-and-auditing-system/actions/workflows/tests.yml)

从 Tencent/WeKnora 的安全设计中抽取思路并独立实现的通用后端安全组件。提供 **Python 库 + WSGI 中间件 + HTTPS/gRPC 示例服务**；不依赖 WeKnora、Go、Docker、数据库服务器或模型。

本仓库包含 **完整 `securitykit` 源码、CLI、测试、示例和构建脚本**。Windows x64 便携 EXE、`_internal/` 运行时、依赖 wheels、证书、凭据和运行数据库不在此仓库，需按 `build-windows.ps1` 或单独发布的离线包获取。

这是用于学习和集成的参考实现，尚未经过独立安全审计；企业上线前需按自身身份系统、密钥托管、部署和审计留存要求完成集成。源码对应关系与有意改变的行为见 [UPSTREAM.md](UPSTREAM.md)。

## 快速开始

需要 Python 3.11+。建议使用虚拟环境：

```sh
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: . .venv/bin/activate
python -m pip install -r requirements.txt
python run.py demo
python -m examples.integration
python -m unittest discover -s tests -v
```

`demo` 会在临时目录生成一次性密钥和证书，执行真实 HTTPS 与 gRPC 调用，展示正常读取、越权拒绝、租户隔离和审计校验，结束后删除临时状态。它不需要网络账号、真实 API Key 或模型。

启动本地演示服务：

```sh
python run.py init --state private-state
python run.py serve --state private-state
```

首次初始化后，`private-state/` 含访问令牌、AES/HMAC 密钥、证书私钥、SQLite 数据库和客户端配置。**该目录已被 `.gitignore` 排除，不能提交、转发或重新打包。** 每个人首次运行会生成不同凭据。

Windows 用户也可以使用 `start.bat` / `demo.bat`；它们优先使用同目录的便携 EXE（单独分发），没有 EXE 时回退到 `python run.py`。

## 四个组成部分

| 组件 | 行为 |
|---|---|
| 多租户 RBAC | 服务端 Token 哈希映射到身份及租户成员关系；owner/admin/contributor/viewer 四级；默认拒绝，无跨租户超级用户旁路 |
| AES-256-GCM | 32 字节随机密钥、12 字节随机 nonce；认证附加数据绑定版本、key ID、租户、资源类型和资源 ID；拒绝明文、未知 key 和认证失败 |
| HTTPS 与 gRPC TLS | 两端验证 CA 和服务端名称；要求客户端证书；再验证 Bearer Token；HTTPS 最低 TLS 1.2；gRPC 使用 grpcio/BoringSSL 的安全传输默认协商，不开放明文端口 |
| 审计 | SQLite 持久化，业务写入和成功审计同事务；拒绝与执行错误记录安全元数据；独立 HMAC-SHA256 链检测记录修改、插入、重排等；审计失败不放行业务操作 |

读请求也要求成功审计提交后才向客户端返回结果。凭据、请求正文、密文、Authorization、完整 URL 和异常原文不写入审计。标识符及身份名称仍属于业务元数据，请按你的隐私和留存要求保护它们。

## 权限矩阵

| 操作 | Viewer | Contributor | Admin | Owner |
|---|---|---|---|---|
| 读取本租户示例 secret | 是 | 是 | 是 | 是 |
| 创建本租户资源 | 否 | 是 | 是 | 是 |
| 修改/删除自己创建的资源 | 否 | 是 | 是 | 是 |
| 修改/删除他人资源 | 否 | 否 | 是 | 是 |
| 查询本租户审计 | 否 | 否 | 是 | 是 |
| 跨租户操作 | 否 | 否 | 否 | 否 |

本示例没有租户删除或所有权转移管理接口，因此 owner/admin 在现有路由上权限相同。宿主可使用 `SecurityKernel.run(..., required="owner", ...)` 给新接口设置更高门槛。Viewer 在这里可读取 secret 明文是示例领域的明确策略，接入真实凭据管理系统时应调整读取权限。

认证信息来自 `private-state/server.json` 中服务端持有的成员关系；`X-Role`、`X-User`、`X-Tenant` 和 forwarded 请求头不授予权限。Token 只以 SHA-256 哈希形式存于服务端配置，明文只保存在演示客户端文件 `clients.json`。这是高熵随机机器 Token 方案，不是密码哈希或完整登录系统；未附带密码登录、JWT/OIDC、MFA 或在线用户管理。

## 命令行

```sh
python run.py demo
python run.py init --state private-state
python run.py serve --state private-state
```

`init` 遇到已存在目录会拒绝覆盖。服务运行后，在另一个终端调用：

```sh
# 创建资源；值从文件读取，避免进入终端命令历史
python run.py call create --identity writer-a --value-file examples/sample-value.txt
# Viewer 可读取
python run.py call read --identity viewer-a
# Viewer 写入被拒绝
python run.py call update --identity viewer-a --value-file examples/sample-value.txt
# tenant-b 的 Owner 访问 tenant-a 被拒绝
python run.py call read --identity owner-b --tenant tenant-a
# 使用同一套策略和数据走 gRPC
python run.py call read --transport grpc --identity viewer-a
python run.py call audit --identity admin-a
```

客户端调用失败返回非零退出码；CLI 仅输出安全错误类型，不回显远端错误正文。成功的 `read` 命令会按业务要求在终端打印读取值。

本地演示身份：`owner-a`、`admin-a`、`writer-a`、`writer2-a`、`viewer-a` 属于 tenant-a；`owner-b` 属于 tenant-b。证书与 Token 是独立的两层控制：证书允许客户端连接，Token 确定业务身份和租户。演示客户端共用一份本地客户端证书；实际部署应向不同调用方签发各自证书。

Token 到期/禁用与角色变化：本地维护 `server.json` 的哈希记录、`expires_at`、`disabled` 和 `memberships`，然后重启服务生效。此版本不含在线吊销缓存同步或证书 CRL/OCSP 管理。

## 库集成

通用接口位于 `securitykit/core.py`：

```python
result = kernel.run(
    authorization,           # 来自传输层的 Authorization 值
    tenant="tenant-a",       # 路由选出的目标，核心仍校验成员关系
    action="reports.read",   # 服务端定义的审计动作
    resource="report-1",
    required="viewer",       # 服务端策略，不能从请求 JSON 获取
    operation=lambda tx, principal: {"subject": principal.subject},
)
```

`operation` 在已校验身份、租户和角色之后执行。所有业务 SQL 必须使用 `tx` 并包含 `tenant` 过滤；组件不能自动修复宿主回调中的无租户 SQL。需要 Contributor 仅操作自身资源时，传入同租户查询的 `owner_lookup(tx, principal)`；Admin/Owner 满足门槛时不走所有者例外。缺失成员关系、未知角色或低权限角色均不放行。

`Vault` 是使用该接口的最小 CRUD 领域示例；所有查询使用 `(tenant, id)`，并在同一事务内完成所有权检查和更新。宿主可替换 Vault，复用 SecurityKernel、CipherBox 和审计能力。

`securitykit.transports.SecurityMiddleware(kernel)` 是 WSGI callable，接收标准 `environ/start_response` 并提供示例资源路由；它要求服务器设置 `wsgi.url_scheme=https`。示例 HTTP server 和 gRPC `SecurityInterceptor` 适配同一套 Vault/Kernel。gRPC 只实现 unary-unary JSON 字节服务 `/securitykit.Vault/Call`，无需 protoc；它不是 protobuf CRUD 通用代理，也不支持流式 RPC。

## 服务接口

HTTPS 默认 `https://localhost:8443`，要求信任本地 CA、客户端证书和 `Authorization: Bearer ...`。

| Method | Path | Body |
|---|---|---|
| POST | `/v1/tenants/{tenant}/secrets/{id}` | `{"value":"..."}` |
| GET | 同上 | 无 |
| PUT | 同上 | `{"value":"..."}` |
| DELETE | 同上 | 无 |
| GET | `/v1/tenants/{tenant}/audit` | 无，返回本租户最近 100 条 |

gRPC 默认 `localhost:50051`；请求 JSON 字段为 `tenant/action/resource/value`，action 为 `create/read/update/delete/audit`，认证走 metadata。写入必须是 UTF-8 字符串，最多 16 KiB；请求体最多 64 KiB。重复 JSON 字段、重复认证头、未知 JSON 字段和不支持的路由被拒绝。健康探针不设免认证业务旁路。

## 审计校验与边界

```sh
python run.py verify-audit --state private-state
```

输出 `{"seq":...,"tag":"..."}`。把输出保存到**独立、受保护的外部位置**作为 checkpoint；后续使用 `--checkpoint checkpoint.json` 检测删除尾部或回滚到早期链。不要只把 checkpoint 与数据库放在同一个攻击者可写目录。

HMAC 链提供篡改证据，**不是不可篡改存储或数字签名**。没有外部 checkpoint 时，删去整个尾部或整个数据库不能可靠检测；同时拿到数据库与 HMAC 密钥的本机管理员也可以重算链。启动时自动校验已有链，但进程运行期间的外部改库需执行 verify-audit/重启才能发现。生产留存应接入外部收集、WORM/对象锁、告警和受保护的周期性 checkpoint；本版不提供这些基础设施。

只有进入有效领域操作的成功/拒绝/执行错误记录在审计中；TLS 握手失败、HTTP framing/路由/JSON 解析失败、RPC 超限/未知方法属于传输层拒绝，不持久化到业务审计。`_system` 是 CLI 审计校验可见的中立范围，用于无身份或无目标租户成员关系的尝试；租户审计接口不展示该范围。

## 密钥、证书与数据

- 初始化通过操作系统随机源生成 256 位 AES 密钥、独立 256 位 HMAC 密钥及 256 位随机 Token。没有默认固定密码或密钥。
- `server.json` 含 AES/HMAC 秘密，`clients.json` 含 Token，`pki/*-key.pem` 含私钥，`security.db*` 含业务和审计数据。POSIX 文件使用 0600/目录 0700；Windows 继承所在目录 ACL，需在受控用户目录部署并按组织要求限制 ACL。
- 演示 CA 私钥只在内存中签发，不写入磁盘；叶证书 30 天有效。此版本不负责自动续期。
- 加密密钥配置支持 key ID：新增随机 key2、把 active_key 改为 key2，保留 key1 即可读取旧密文；旧记录需要宿主在受控迁移中解密并重新加密，完成后再退役旧 key。不能直接删除仍在使用的旧 key。应在高写入量场景定期轮换随机 nonce 所用密钥。
- HMAC 密钥没有在线轮换功能；已有审计链需要原密钥才能验证，长期备份和轮换需规划分段归档和外部锚点。
- SQLite 文件及 WAL 只保存 secret 密文；字段标识符、拥有者和审计元数据不加密，文件加密不覆盖进程内存、终端输出或客户端磁盘。

## 仓库结构

| 路径 | 内容 |
|---|---|
| `securitykit/` | 内核、AES-GCM、RBAC、审计、TLS/gRPC 传输、CLI、PKI |
| `tests/` | 24 项标准库 unittest：加密、权限、租户隔离、审计、TLS/gRPC |
| `examples/` | 无凭据的集成示例与示例值 |
| `run.py` | 源码 CLI 入口 |
| `requirements.txt` / `pyproject.toml` | 运行与构建依赖配置 |
| `scripts/build_release.py` | 按白名单装配发布包的工具 |
| `build-windows.ps1` | Windows 便携包构建（PyInstaller） |
| `start.bat` / `demo.bat` | 便携包启动与演示入口 |
| `private-state/` | 运行后生成的凭据与数据库，已被忽略 |
| `licenses/` | WeKnora 上游许可证 |
| `UPSTREAM.md` / `THIRD-PARTY.md` | 上游对应关系与第三方声明 |
| `TEST-RESULTS.md` / `RELEASE-INFO.json` | 验证记录与 1.0.0 发布元数据 |
| `CONTRIBUTING.md` / `CHANGELOG.md` | 贡献流程与版本记录 |
| `SECURITY.md` | 私密漏洞报告渠道与安全边界 |

## 部署与测试范围

附带服务面向本机学习和联调，固定 loopback；HTTP 使用标准库参考服务器，最多同时处理 32 个连接，socket 超时 5 秒；gRPC 最多 32 个并发 RPC。它们不替代生产反向代理的限流、完整 HTTP 防护、容量治理或证书管理。

通用内核以 SQLite 单机事务作为示例，没有集群权限缓存、跨进程即时吊销、外部 KMS/HSM、自动凭据轮换、登录防爆破、租户配额或审计保留策略。回调中的网络/邮件等外部副作用无法通过 SQLite 回滚，应使用事务 outbox。已验证范围见 [TEST-RESULTS.md](TEST-RESULTS.md)。

安全问题请按 [SECURITY.md](SECURITY.md) 使用私密渠道报告，不要在公开 Issue 中粘贴凭据、私钥或真实数据。

源码采用 MIT；上游和第三方许可证见 [LICENSE](LICENSE)、[THIRD-PARTY.md](THIRD-PARTY.md) 与 `licenses/`。本项目不是腾讯官方发行版。
