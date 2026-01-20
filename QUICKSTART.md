# 快速开始指南

## 安装

在 `Cargo.toml` 中添加以下内容：

```toml
[dependencies]
mini-btmon-rs = "0.1"
tokio = { version = "1", features = ["full"] }
```

## 权限配置

### 开发环境

```bash
# 构建项目
cargo build

# 方式 1: 使用 setcap（推荐）
sudo setcap 'cap_net_raw+ep' target/debug/your-binary

# 方式 2: 使用 sudo
sudo ./target/debug/your-binary
```

### CI/CD

```yaml
# .github/workflows/test.yml
- name: Setup
  run: sudo setcap 'cap_net_raw+ep' target/debug/deps/your_test-*
  
- name: Test
  run: cargo test
```

## 基础用法

### 1. 基础监控

```rust
use mini_btmon_rs::Monitor;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut monitor = Monitor::new().await?;
    
    while let Some(packet) = monitor.next_packet().await? {
        println!("Packet: {:?}", packet);
    }
    Ok(())
}
```

### 2. 过滤数据包

```rust
use mini_btmon_rs::{Monitor, HciPacket};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut monitor = Monitor::new().await?;
    
    // 过滤 ATT/GATT 数据包 (BLE)
    while let Some(packet) = monitor.next_filtered(|p| p.is_att()).await? {
        println!("GATT packet: {:?}", packet);
    }
    Ok(())
}
```

### 3. 自动化测试

```rust
use mini_btmon_rs::{Monitor, HciEvent};
use std::time::Duration;

#[tokio::test]
async fn test_connection() -> Result<(), Box<dyn std::error::Error>> {
    let mut monitor = Monitor::new().await?;
    
    // 触发连接动作
    // my_bluetooth_app.connect().await?;
    
    // 等待 Connection Complete 事件（5秒超时）
    let packet = monitor.expect_event(
        HciEvent::ConnectionComplete,
        Duration::from_secs(5)
    ).await?;
    
    println!("Connection established: {:?}", packet);
    Ok(())
}
```

## 常见场景

### BLE 广播监控

```rust
use mini_btmon_rs::{Monitor, HciPacket};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut monitor = Monitor::new().await?;
    
    while let Some(packet) = monitor.next_packet().await? {
        if let HciPacket::Event { event_code, params } = packet {
            if event_code == mini_btmon_rs::HciEvent::LeMetaEvent {
                // LE Meta Event - 包含广播报告
                println!("Advertising packet: {:02x?}", params);
            }
        }
    }
    Ok(())
}
```

### GATT 交互调试

```rust
use mini_btmon_rs::{Monitor, HciPacket};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut monitor = Monitor::new().await?;
    
    // 收集 10 秒内的 GATT 操作
    let packets = monitor.collect_for(Duration::from_secs(10)).await?;
    
    for packet in packets {
        if packet.is_att() {
            if let HciPacket::AclData { data, .. } = packet {
                if data.len() > 4 {
                    let opcode = data[4];
                    println!("GATT operation: {:#x}", opcode);
                }
            }
        }
    }
    Ok(())
}
```

### 验证事件缺失（负面测试）

```rust
use mini_btmon_rs::{Monitor, HciEvent, HciPacket};
use std::time::Duration;

#[tokio::test]
async fn test_no_disconnect() -> Result<(), Box<dyn std::error::Error>> {
    let mut monitor = Monitor::new().await?;
    
    // 验证 5 秒内未发生断开连接事件
    monitor.assert_no_match(
        |p| matches!(p, HciPacket::Event { 
            event_code: HciEvent::DisconnectionComplete, .. 
        }),
        Duration::from_secs(5)
    ).await?;
    
    Ok(())
}
```

## 错误处理

```rust
use mini_btmon_rs::{Monitor, Error};

#[tokio::main]
async fn main() {
    match Monitor::new().await {
        Ok(monitor) => {
            // 使用 monitor...
        },
        Err(Error::PermissionDenied) => {
            eprintln!("Error: CAP_NET_RAW capability required");
            eprintln!("Run: sudo setcap 'cap_net_raw+ep' /path/to/binary");
            std::process::exit(1);
        },
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
```

## 示例程序

```bash
# 基础监控
cargo run --example basic

# ATT/GATT 过滤
cargo run --example att_filter

# 测试场景
cargo run --example test_scenario

# GATT 测试
cargo run --example gatt_testing

# 集成示例
cargo run --example integrated
```

注意：运行前请确保已授予 `CAP_NET_RAW` 权限。

## 开发工具

```bash
make fmt      # 代码格式化
make check    # 编译检查
make clippy   # Lint 检查
make test     # 运行测试
make ci       # 运行 CI 流程
```

## 故障排查

### 权限不足 (Permission denied)

**解决方案：**
```bash
sudo setcap 'cap_net_raw+ep' /path/to/binary
```

### 未接收到数据包

检查项：
1. 确认存在蓝牙适配器。
2. 确认适配器已启用（`hciconfig hci0 up`）。
3. 确认存在蓝牙活动。

## 更多参考

- [README.md](README.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [examples/](examples/)
