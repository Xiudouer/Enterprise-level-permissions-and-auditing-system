# Contributing

BackendSecurityKit 是一个用于学习和集成的参考实现。安全相关改动需要特别谨慎：**正确性、默认拒绝和测试覆盖优先于接口便利**。

## 开发环境

- Python 3.11+
- 本地 loopback 可用（测试会启动 HTTPS 与 gRPC 示例服务）
- 建议使用虚拟环境：

```sh
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: . .venv/bin/activate
python -m pip install -r requirements.txt
```

运行验证：

```sh
python run.py demo
python -m examples.integration
python -m unittest discover -s tests -v
```

测试会生成一次性证书和密钥，不访问公网、不需要模型或外部账号。

## 修改准则

- **默认拒绝**：新增路由、角色或资源类型时必须显式授权，不能因为缺少元数据而放宽。
- 任何加密、认证、RBAC、审计或 TLS 改动都必须补充测试，并说明失败模式和回滚行为。
- 保持服务只监听 loopback；不要加入明文端口、TLS 关闭开关、免认证业务旁路或跨租户超级用户。
- 所有业务 SQL 必须使用组件提供的事务并带 `tenant` 过滤；不要接受模型/请求传入的 SQL、数据库路径或文件路径。
- 审计失败必须继续阻断业务操作；不要把 secret、Token、Authorization、请求正文或异常原文写入审计。
- 更新用户可见行为时同步修改 README、`TEST-RESULTS.md` 和 `CHANGELOG.md`。
- **不要提交** `private-state/`、`*-state/`、`*.db`、`*.pem`、`clients.json`、`server.json`、`.env`、wheel、EXE、`_internal/` 或发布 ZIP。这些路径已在 `.gitignore` 中排除。

## 提交与 Pull Request

1. 从最新 `main` 创建分支，一个提交只做一类改动。
2. 提交信息说明动机和安全影响；不要只在标题里写“fix”。
3. PR 描述包含：威胁模型变化、测试命令、未覆盖的边界。
4. 确保 `python -m unittest discover -s tests -v` 通过；新增测试应可在无网络环境运行。
5. 如果改动涉及密码学、证书、审计链或权限，请在 PR 中明确标注，便于重点审查。

## 安全报告

请不要在公开 Issue 中粘贴真实凭据、私钥、可利用细节或生产数据。请按 [SECURITY.md](SECURITY.md) 使用 GitHub 私密漏洞报告；如果入口不可用，只发一个不含敏感内容的最小说明，等待后续沟通。

## 许可证

提交即表示你同意以本仓库的 MIT 许可证（见 [LICENSE](LICENSE)）发布你的贡献。第三方组件仍遵循各自许可证，见 [THIRD-PARTY.md](THIRD-PARTY.md)。
