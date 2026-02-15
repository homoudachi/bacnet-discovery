# BACnet Discovery Tool

A diagnostic utility for discovering and inspecting BACnet/IP devices on a local network.

## Features

- **Device Discovery**: Send `Who-Is` broadcasts to find active devices.
- **Point Discovery**: Inspect a device to list its BACnet objects (Analog Inputs, Binary Values, etc.).
- **TUI Interface**: Interactive terminal interface for easy navigation.
- **Shared Socket**: Uses `SO_REUSEPORT` to coexist with other BACnet apps on the same machine.

## Installation

Ensure you have Rust installed.

```bash
git clone https://github.com/homoudachi/bacnet-discovery.git
cd bacnet-discovery
cargo build --release
```

## Usage

### Discovery Tool
```bash
cargo run --release
```
- **'d'**: Trigger device discovery (broadcast Who-Is).
- **'Enter'**: Drill down into a selected device to view its points.
- **'d' (in device view)**: Discover points (objects) for the selected device.
- **'Esc'**: Go back to the device list.
- **'q'**: Quit.

### Diagnostics & Testing
```bash
# Run a virtual BACnet device for local testing
cargo run --bin responder [device-id]

# Analyze raw BACnet traffic
cargo run --bin sniffer

# Check network capabilities
cargo run --bin diagnostics
```

## License

MIT / Apache-2.0
