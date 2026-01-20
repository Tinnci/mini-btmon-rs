# 架构设计

## 项目目标

mini-btmon-rs 提供 Linux 蓝牙 HCI 监控数据的程序化访问接口。其主要解决以下问题：

1. **解析稳定性**：避免使用正则表达式解析 btmon 的文本格式输出。
2. **同步机制**：提供 HCI 事件与测试动作的同步关联能力。
3. **权限管理**：通过最小化特权级需求，避免整个测试环境都需要 root 权限。

## 系统架构

```
[测试代码 (用户态)]  
       ↓ Rust API
[mini-btmon-rs (CAP_NET_RAW)]
       ↓ HCI Monitor Socket
[Linux 内核 Bluetooth 子系统]
```

## 架构特性

### 1. 权限分离

- **最小特权**：仅 Socket 创建阶段需要 `CAP_NET_RAW` 权限。
- **配置方式**：推荐使用 `setcap` 授予权限。
- **部署模式**：支持 systemd 或 daemon 模式部署。

### 2. 强类型接口

本项目提供强类型的 HCI 数据包定义，避免文本解析带来的不确定性。

```rust
if let HciPacket::Event { event_code: HciEvent::ConnectionComplete, .. } = packet {
    assert_eq!(packet.status(), 0x00);
}
```

### 3. 测试接口设计

核心 API 针对自动化测试场景进行了设计：

- `expect()`：等待特定数据包，支持超时。
- `expect_command()` / `expect_event()`：类型安全的断言。
- `collect_for()`：批量收集数据包进行后续验证。
- `assert_no_match()`：验证特定时间内未发生某事件。

## 项目结构

```
mini-btmon-rs/
├── src/
│   ├── lib.rs           # 入口点与文档
│   ├── error.rs         # 错误类型
│   ├── socket.rs        # HCI Monitor Socket 绑定
│   ├── packet.rs        # HCI 数据包解析
│   ├── monitor.rs       # 监控核心 API
│   └── testing.rs       # 测试辅助工具
├── examples/
│   ├── basic.rs         # 基础监控示例
│   ├── att_filter.rs    # ATT/GATT 过滤示例
│   ├── integrated.rs    # 集成示例
│   ├── test_scenario.rs # 自动化测试场景
│   └── gatt_testing.rs  # BLE GATT 测试
├── Makefile             # 开发管理
└── README.md            # 项目说明
```

## 功能说明

### 1. 数据包监控

- 实时捕获 HCI 数据包。
- 支持 Command、Event、ACL Data、SCO Data 等类型。
- 使用 `bytes` crate 进行缓冲区管理。
- 基于 tokio 提供异步接口。

### 2. 数据过滤

```rust
// 过滤 ATT/GATT 数据包
monitor.next_filtered(|p| p.is_att()).await?;

// 过滤特定 Handle 的 ACL 数据
monitor.next_filtered(|p| matches!(p, 
    HciPacket::AclData { handle, .. } if handle == 0x0001
)).await?;
```

### 3. 测试断言

```rust
#[tokio::test]
async fn test_connection_sequence() {
    let mut monitor = Monitor::new().await?;
    
    app.connect_device().await?;
    
    // 验证 HCI 命令
    let cmd = monitor.expect_command(
        HciOpcode::CREATE_CONNECTION,
        Duration::from_secs(2)
    ).await?;
    
    // 验证 Connection Complete 事件
    let evt = monitor.expect_event(
        HciEvent::ConnectionComplete,
        Duration::from_secs(5)
    ).await?;
    
    // 验证无 DisconnectionComplete 事件
    monitor.assert_no_match(
        |p| matches!(p, HciPacket::Event { 
            event_code: HciEvent::DisconnectionComplete, .. 
        }),
        Duration::from_secs(5)
    ).await?;
}
```

## 开发工具

### Pre-commit Hooks

- `cargo fmt --check`
- `cargo clippy`
- `cargo check`
- `cargo test --lib`

### Makefile 命令

- `make fmt`
- `make check`
- `make clippy`
- `make test`
- `make build`
- `make examples`
- `make ci`

## 使用场景

### 1. 自动化集成测试

在蓝牙应用集成测试中，验证底层是否发送了预期的 HCI 命令及对应的参数。

### 2. 协议调试

监控 GATT 交互，查看实时数据。

### 3. 性能分析

收集特定时间段内的数据包，分析命令延迟等指标。

## 权限管理

### 开发环境

使用 `setcap` 授予二进制文件权限：
```bash
cargo build --examples
sudo setcap 'cap_net_raw+ep' target/debug/examples/basic
./target/debug/examples/basic
```

### GitHub Actions

```yaml
- name: Setup capabilities
  run: sudo setcap 'cap_net_raw+ep' target/debug/your-test-binary
    
- name: Run Bluetooth tests
  run: cargo test
```

### Systemd 配置

```ini
[Service]
ExecStart=/usr/bin/mini-btmon-daemon
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
User=bluetooth
Group=bluetooth
```

## 与 btmon 的差异

| 特性 | btmon (BlueZ) | mini-btmon-rs |
|------|---------------|---------------|
| 类型 | 命令行工具 | 程序化库 |
| 输出 | 文本 | 强类型结构体 |
| 异步支持 | 无 | 支持 (Tokio) |
| 测试 API | 无 | 支持 |
| 协议解析 | 相对完整 | 基础（可扩展） |

## 路线图

### 短期目标
- L2CAP/ATT/GATT 完整解析。
- btsnoop 文件格式支持（导入/导出）。
- 多控制器过滤支持。

### 中期目标
- 守护进程模式（特权分离）。
- 统计数据收集 API。

## 相关资源

- [BlueZ 官方网站](http://www.bluez.org/)
- [Bluetooth Core Specification](https://www.bluetooth.com/specifications/specs/)
- [Linux Bluetooth HCI 文档](https://www.kernel.org/doc/html/latest/networking/bluetooth.html)

## 贡献

请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 许可证

MIT
