# 项目状态报告

**维护状态**: 核心功能已实现

## 项目统计

- **核心库**: 包含 9 个核心模块。
- **示例程序**: 提供 8 个完整示例。
- **文档**: 包含 README, ARCHITECTURE, QUICKSTART, CONTRIBUTING。
- **工具**: 包含 Makefile 与 Pre-commit hooks。

## 已完成功能

### 核心功能
- HCI Monitor Socket 绑定。
- 异步数据包读取（基于 Tokio）。
- HCI 数据包解析（Command, Event, ACL, SCO）。
- L2CAP 协议解析（信令、CID 识别）。
- ATT 协议完整解析（全部 PDU 类型）。
- **GATT 层级深度解析**（服务、特征、描述符发现）。
- UUID 解析（16/32/128-bit，含蓝牙 SIG 标准名称映射）。
- GATT 数据库动态构建。
- 零拷贝缓冲区管理。
- 数据包过滤架构。
- btsnoop 文件格式支持（读取/写入）。
- **SMP 协议解析**（配对、密钥分发、安全连接）。
- **控制器过滤**（按 HCI 索引过滤数据包）。
- **GATT 数据库持久化**（JSON 序列化，需启用 `persist` feature）。

### 测试支持
- `expect()`：带超时的断言接口。
- 数据包匹配器（Command, Event, ACL）。
- `collect_for()`：批量数据包收集。
- `assert_no_match()`：验证事件缺失。

### 开发工具
- Pre-commit hooks（格式化、Clippy、编译检查、测试）。
- Makefile 快捷命令。
- CI 流程配置。

## 核心设计

- **强类型接口**：使用 Rust 结构体表示 HCI 数据包，避免文本解析。
- **事件驱动断言**：提供精确的超时等待机制。
- **权限分离**：仅在必要时请求 `CAP_NET_RAW` 权限。

## 质量指标

- **格式化**: 已通过 `rustfmt`。
- **代码检查**: `clippy` 无警告。
- **测试**: 核心测试用例已通过。

## 未来规划

### 短期
- 控制器级别过滤的 UI 集成。
- 数据包注入接口。

### 中期
- 守护进程模式（IPC 架构）。
- 性能优化与指标分析。

## 贡献要求

1. 提交前必须通过 pre-commit hooks 检查。
2. 新功能需附带单元测试与示例代码。
3. 遵循项目既定的 API 设计风格。

---

**当前版本**: v0.1.0
**维护人**: tinnci
