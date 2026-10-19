# WeKnora 源码溯源与实现差异

参考公开仓库 [Tencent/WeKnora](https://github.com/Tencent/WeKnora)，固定提交 `2fbfb4471581cd5e7d731bc7a2d443fe7d8e95b5`（0.8.3）。分析本地固定源码，而非对线上服务或闭源程序进行破解。本版独立用 Python 重新实现通用结构，没有复制整个 Go 后端或上游业务数据库。

| 固定源码路径 | 上游行为 | 本版对应 |
|---|---|---|
| `internal/types/tenant_member.go` | owner/admin/contributor/viewer 四级；每用户每租户成员关系及状态 | `core.py` LEVELS、Principal 与服务端 memberships |
| `internal/middleware/rbac.go` | RequireRole、RequireOwnershipOrRole；可配置 rollout；API-key 特殊 gate 与跨租户操作员例外 | `SecurityKernel.run` 角色门槛和受限所有者例外；始终执行；无超级用户旁路 |
| `internal/application/access/ownership.go` | Contributor 为创建者例外最低门槛；lookup 必须租户可见 | 同事务内、同租户 owner_lookup；Viewer 即使拥有资源仍不能修改 |
| `internal/utils/crypto.go` | AES-GCM，`enc:v1:`，随机 nonce；上游格式没有 AAD，部分路径兼容明文 | `CipherBox`：仅接受加密 envelope；显式 key ID；租户/资源绑定 AAD；不兼容上游 enc:v1 数据 |
| `docreader/client/auth.go` | TLS 最低 1.2、CA/主机名、可选客户端证书和 per-RPC Token | `transports.py`：只建 secure channel/port，mTLS 和 Token 必须；客户端验证名称 |
| `docreader/auth.py` | 服务端 TLS/可选 mTLS；Token interceptor；错误配置不静默退回明文 | 同一应用内核供 HTTPS 与 gRPC 使用；无 TLS-off、无免认证健康业务接口 |
| `internal/types/audit_log.go` | 点分动作名、actor/tenant/target/outcome，避免秘密值进入详情 | 显式安全字段白名单；成功、拒绝、业务错误 |
| `internal/application/service/audit_log.go` | 审计服务、拒绝事件去重与留存；多数调用不让审计失败阻断业务 | 本版不同：审计失败阻断；SQLite 事务+HMAC 链；不实现去重/自动留存 |
| `internal/middleware/audit_provider.go` | 通过请求 context 注入审计服务，允许空服务降级 | 内核构造时要求有效独立 HMAC key，审计不可关闭 |

新增的 AAD、key ID、审计 HMAC 链、外部 checkpoint 和 fail-closed 事务策略是本版设计，不能归因于上游。上游有更多配置、API-key 能力范围、资源可见性及认证路径，本版不宣称功能/协议/数据兼容。

上游完整许可证见 `licenses/WeKnora-LICENSE.txt`。构建依赖许可证随发布包一并保留。库内通用回调的业务授权策略、SQL 租户过滤、外部副作用和上线条件仍由宿主实现。

相关原始技术资料：

- [cryptography AESGCM](https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM)
- [gRPC Authentication](https://grpc.io/docs/guides/auth/)
- [Python ssl](https://docs.python.org/3/library/ssl.html)
- [SQLite transactions](https://www.sqlite.org/lang_transaction.html)
