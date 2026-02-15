# BACnet Discovery Tool

A professional, terminal-based diagnostic utility for discovering and inspecting BACnet/IP devices on a local area network. Built with Rust, leveraging the `bacnet-rs` protocol stack and `ratatui` for the terminal user interface.

## Overview

The BACnet Discovery Tool provides real-time visibility into BACnet/IP networks. It handles the complexities of the BACnet Virtual Link Layer (BVLL) and the Who-Is/I-Am service cycle to identify active devices, their vendors, and their communication capabilities.

Designed with field engineering in mind, it includes features for multi-tool coexistence and deep packet inspection.

## Key Features

- **Real-time Discovery**: Continuous background scanning using the standard BACnet Who-Is service.
- **Interactive TUI**: A polished terminal interface for navigating device lists and viewing detailed properties.
- **Port Sharing (SO_REUSEPORT)**: Coexists with other BACnet applications on the same host (supported on Linux).
- **Comprehensive Diagnostics**:
  - **Main Discovery**: The primary TUI application.
  - **Responder**: A virtual BACnet device for local testing and validation.
  - **Sniffer**: Low-level packet analyzer for troubleshooting malformed traffic or network filtering.
  - **Network Checker**: Validates local port availability and broadcast permissions.

## Functional Description

The tool operates by binding to the standard BACnet/IP port (`47808`) and broadcasting a `Who-Is` message (Service Choice 8). It then listens for `I-Am` responses (Service Choice 0) from devices on the network.

### Protocol Support
- **BVLL**: Supports `Original-Broadcast-NPDU`, `Original-Unicast-NPDU`, and `Forwarded-NPDU` (via BACnet Routers/BBMDs).
- **NPDU**: Standard network layer parsing.
- **APDU**: Unconfirmed service parsing for discovery.

## Installation

### Prerequisites
- [Rust](https://www.rust-lang.org/tools/install) (1.70 or later)
- Linux (for full `SO_REUSEPORT` support)

### Building
```bash
git clone <repository-url>
cd bacnet-discovery
cargo build --release
```

## Usage

### Primary Discovery Tool
```bash
cargo run --release
```
- **Navigation**: Use **Up/Down Arrows** to select devices.
- **Refresh**: Press **'r'** to clear the current list and force a re-scan.
- **Quit**: Press **'q'** to exit safely.

### Diagnostic Tools

#### 1. Network Responder (Simulation)
Creates a virtual BACnet device on your machine to test discovery logic.
```bash
cargo run --bin responder [device-id]
```

#### 2. Network Sniffer
Analyzes raw BACnet/IP traffic on port 47808.
```bash
cargo run --bin sniffer
```

#### 3. Pre-flight Diagnostics
Checks if the host environment is ready for BACnet communication.
```bash
cargo run --bin diagnostics
```

## Troubleshooting

1. **No Devices Found**:
   - Ensure UDP port **47808** is open in your firewall.
   - Run the `sniffer` to see if `I-Am` packets are arriving but being ignored.
   - Verify you are on the same subnet as the target devices.
2. **Port Conflict**:
   - If `diagnostics` reports the port is in use, the tool will attempt to use `SO_REUSEPORT`. If that fails, ensure no other non-sharing BACnet stacks are active.

## Architecture

- `src/main.rs`: Application entry point and event orchestration.
- `src/app.rs`: State management and navigation logic.
- `src/bacnet.rs`: BACnet protocol encoding and parsing.
- `src/ui.rs`: TUI rendering and layout definition.
- `src/network.rs`: Cross-platform shared socket utilities.

## License

This project is dual-licensed under:
- MIT License ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
