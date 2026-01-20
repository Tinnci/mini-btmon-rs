# 贡献指南

感谢您对 mini-btmon-rs 的关注！

## 开发环境搭建

1. 克隆代码库。
2. 安装 Rust (https://rustup.rs/)。
3. 构建项目：`cargo build`。

## 测试变更

由于本库需要 `CAP_NET_RAW` 权限，您需要：
- 授予权限：`sudo setcap 'cap_net_raw+ep' target/debug/examples/basic`。
- 或使用 sudo 运行：`sudo cargo run --example basic`。

## 代码风格

- 提交前运行 `cargo fmt`。
- 运行 `cargo clippy` 并修复所有警告。
- 根据需要添加测试用例。

## 合并请求 (PR) 流程

1. 如果修改了 API，请同步更新文档。
2. 如果添加了新功能，请提供示例程序。
3. 确保所有测试通过。
4. 必要时更新 README.md。

## 许可证

通过参与贡献，您同意您的贡献将基于项目原有的许可证（MIT）发布。
