# mini-btmon-rs

**适用于 Linux 的蓝牙 HCI 监控 Rust 库**

`mini-btmon-rs` 提供对 Linux 蓝牙 HCI 监控数据的程序化访问，类似于 BlueZ 的 `btmon` 工具。本项目提供异步接口，便于集成到 Rust 应用程序中。

## 项目特性

- 支持 HCI 数据包监控。
- 基于 tokio 的异步接口。
- 强类型数据包解析。
- 支持数据包过滤。
- 易于集成。

## 使用场景

- **BLE GATT 调试**：查看 ATT 数据包交换。
- **协议分析**：分析 HCI 命令与事件流。
- **自动化测试**：验证蓝牙交互逻辑。
- **结构化日志**：记录 HCI 交互。

## 权限说明

本库需要 `CAP_NET_RAW` 权限以打开 HCI 监控套接字。

### 方式 1：使用 setcap（推荐）

```bash
# 授予二进制文件权限
sudo setcap 'cap_net_raw+ep' target/debug/your-app

# 直接运行
./target/debug/your-app
```

### 方式 2：使用 sudo

```bash
sudo cargo run
```

### 方式 3：Systemd 服务

在生产环境中，可通过 systemd 配置文件限制权限：

```ini
[Service]
ExecStart=/usr/bin/your-app
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
```

## 快速开始

在 `Cargo.toml` 中添加依赖：

```toml
[dependencies]
mini-btmon-rs = "0.1"
tokio = { version = "1", features = ["full"] }
```

### 基础用法

```rust
use mini_btmon_rs::Monitor;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut monitor = Monitor::new().await?;
    
    while let Some(packet) = monitor.next_packet().await? {
        println!("{:?}", packet);
    }
    Ok(())
}
```

### 过滤 ATT 数据包

```rust
use mini_btmon_rs::{Monitor, HciPacket};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut monitor = Monitor::new().await?;
    
    while let Some(packet) = monitor.next_filtered(|p| p.is_att()).await? {
        if let HciPacket::AclData { handle, data, .. } = packet {
            println!("Handle {:#x}: {} bytes", handle, data.len());
        }
    }
    Ok(())
}
```

## 示例程序

```bash
# 编译示例
cargo build --examples

# 设置权限并运行
sudo setcap 'cap_net_raw+ep' target/debug/examples/basic
target/debug/examples/basic
```

## 架构

本项目遵循最小特权原则：

1. **权限最小化**：仅在创建套接字时需要特权。
2. **异步设计**：基于 tokio 实现。
3. **高效处理**：使用 `bytes` crate 管理缓冲区。

## 与 btmon 比较

| 特性 | btmon | mini-btmon-rs |
|---------|-------|---------------|
| 命令行工具 | 是 | 否 |
| Rust 库 | 否 | 是 |
| 异步接口 | 否 | 是 |
| 强类型解析 | 否 | 是 |
| 程序化集成 | 文本解析 | 原生 API |

## 路线图

- L2CAP, ATT, GATT 协议完整解析。
- btsnoop 文件格式支持。
- 数据包注入接口。
- 控制器过滤。

## 贡献

请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 许可证

MIT

## 相关资源

- [BlueZ](http://www.bluez.org/)
- [btsnoop 格式说明](https://www.fte.com/webhelp/bpa600/Content/Technical_Information/BT_Snoop_File_Format.htm)
