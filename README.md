# BACnet Discovery Tool

A professional-grade, terminal-based diagnostic utility for discovering, inspecting, and monitoring BACnet/IP devices.

## Features

- **Robust Device Discovery**: Uses targeted `Who-Is` broadcasts on selected interfaces to find devices without flooding the network.
- **Deep Inspection**: Drill down into devices to discover objects (Points) and their properties.
- **Live Polling**: Automatically polls discovered points for real-time value updates.
- **Dual-Socket Architecture**: Advanced networking stack allows reliable communication even when sharing the BACnet port with other applications (via `SO_REUSEPORT`).
- **TUI Interface**: A fast, keyboard-driven terminal interface built with `ratatui`.

## Installation

Ensure you have [Rust](https://www.rust-lang.org/) installed.

```bash
git clone https://github.com/homoudachi/bacnet-discovery.git
cd bacnet-discovery
cargo build --release
```

## Usage

### 1. Start the Tool
```bash
cargo run --release
```

### 2. Select Network Interface
Use the **Up/Down** arrows to select the network interface connected to your BACnet network (e.g., `eth0`, `wlan0`, or `127.0.0.1` for local testing) and press **Enter**.

### 3. Discover Devices
Press **'d'** to broadcast a `Who-Is` request. Discovered devices will appear in the list.

### 4. Inspect & Monitor
- Select a device and press **Enter** to view its details.
- Press **'d'** again to discover its objects (Points).
- The tool will automatically poll these points for live updates.

### Controls
| Key | Action |
| --- | --- |
| `d` | Discover Devices / Discover Points |
| `Enter` | Select Interface / Drill-down into Device |
| `Esc` | Go Back / Exit View |
| `r` | Refresh / Clear List |
| `q` | Quit |

## Diagnostics & Testing

The project includes a suite of diagnostic tools for verifying your network environment:

### Virtual Responder
Simulates a BACnet device on your machine. Useful for testing the tool without physical hardware.
```bash
cargo run --bin responder
```

### Network Sniffer
Captures and decodes raw BACnet/IP traffic on port 47808.
```bash
cargo run --bin sniffer
```

### Port Diagnostics
Checks if the BACnet port is available or blocked.
```bash
cargo run --bin diagnostics
```

### Headless Scan
Runs a discovery scan without the UI, logging results to stdout.
```bash
cargo run --bin headless-scan
```

## Architecture

This tool uses a sophisticated **Dual-Socket Architecture** to ensure reliability:
1. **Discovery Socket (47808)**: Listens for broadcast traffic (`I-Am`, `Who-Is`). Shares the port using `SO_REUSEPORT`.
2. **Client Socket (Random Port)**: Handles unicast confirmed requests (`ReadProperty`, `ReadPropertyMultiple`). This ensures responses are routed correctly by the OS, avoiding race conditions common in shared-port environments.

## License

Dual-licensed under MIT and Apache-2.0.
