# Changelog

本项目的显著变更记录在此文件。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [1.0.0] - 2026-10-19

### Added

- 完整的 `securitykit` 源码：多租户 RBAC、AES-256-GCM、审计链、PKI、HTTPS/gRPC 传输和 CLI。
- 四级角色模型（viewer/contributor/admin/owner），默认拒绝、无跨租户旁路。
- 认证附加数据绑定版本、key ID、租户、资源类型和资源 ID；支持密钥轮换。
- 审计与业务写入同事务，HMAC-SHA256 链检测修改、插入和重排；支持外部 checkpoint 校验。
- 双向 TLS 的 HTTPS 与 gRPC 示例服务，共用同一套授权、加密和审计内核。
- 无凭据的集成示例、`demo` 命令和 24 项标准库 `unittest`。
- Windows 构建脚本与便携包发布装配脚本。
- `UPSTREAM.md`、`THIRD-PARTY.md` 与 WeKnora 上游对应关系。

### Verified

- Windows x64 / CPython 3.12.14，cryptography 48.0.0、grpcio 1.84.0：24 项源码测试通过。
- 便携程序 demo、CLI、HTTPS 与 gRPC 联调通过；未做独立安全审计、渗透测试或生产负载验证。

### Notes

- 1.0.0 是学习/集成参考实现，不提供集群、KMS/HSM、OIDC/MFA、在线吊销或合规认证。
- Windows EXE、`_internal/`、wheels、证书和运行数据库不包含在此源码仓库。
