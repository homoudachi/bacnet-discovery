# Functional Description: BACnet Discovery Tool

## 1. Overview
The BACnet Discovery Tool is a terminal-based utility designed for Building Management System (BMS) technicians and engineers. It allows for the discovery, inspection, and monitoring of BACnet/IP devices on a network without requiring heavy proprietary software.

## 2. Core Capabilities

### 2.1 Device Discovery
- **Mechanism**: Uses the BACnet `Who-Is` (Service 0x08) broadcast message.
- **Scope**: Broadcasts are restricted to a user-selected network interface to prevent network flooding.
- **Protocol**: Complies with ASHRAE 135 (BACnet/IP) using BVLC Type 0x81.
- **Behavior**:
  - The tool listens on UDP port 47808 (default BACnet port).
  - It captures `I-Am` (Service 0x00) responses.
  - It supports `SO_REUSEPORT` to coexist with other BACnet software on Linux systems.

### 2.2 Point (Object) Discovery
- **Mechanism**: Uses the `ReadPropertyMultiple` (Service 0x0E) confirmed service.
- **Process**:
  1. Requests the `Object_List` (Property 76) from the `Device` object.
  2. Iterates through the returned list of Object IDs.
  3. Batches requests to read `Object_Name`, `Present_Value`, and `Units` for each object.
- **Supported Objects**: Parses standard objects including Analog Input/Output/Value, Binary Input/Output/Value, and Multi-state objects.

### 2.3 Live Monitoring (Polling)
- **Mechanism**: Periodic `ReadProperty` (Service 0x0C) requests.
- **Default Interval**: 5 seconds (configurable in future).
- **Architecture**: A dedicated asynchronous task manages polling loops for all active points to ensure UI responsiveness is not blocked by network I/O.

## 3. System Architecture

### 3.1 Network Layer (`network.rs`)
- Manages UDP socket creation and configuration.
- Handles `SO_REUSEPORT` for Linux to allow multiple BACnet tools to run simultaneously.
- Abstraction for interface selection.

### 3.2 Dual-Socket Design
To solve reliability issues with unicast responses on shared ports, the application uses two distinct sockets:
1.  **Discovery Socket (Bound to 47808)**:
    -   **Purpose**: Handling Broadcast traffic (`Who-Is`, `I-Am`).
    -   **Configuration**: Uses `SO_REUSEPORT`.
    -   **Why**: BACnet devices expect discovery traffic on the standard port.
2.  **Client Socket (Bound to Random Port)**:
    -   **Purpose**: Handling Unicast Confirmed Requests (`ReadProperty`, `ReadPropertyMultiple`).
    -   **Why**: When sending a request from a specific, unique ephemeral port, the OS guarantees that the response is delivered *only* to that socket. This eliminates race conditions where responses might be "stolen" by other BACnet tools running on the same machine.

### 3.3 Protocol Layer (`bacnet.rs`)
- **Encoding/Decoding**: Maps Rust structs to raw BACnet byte streams (APDU/NPDU/BVLL).
- **Service Handlers**:
  - `send_whois_to`: Constructs discovery broadcasts.
  - `read_device_objects`: Orchestrates complex object list retrieval.
  - `read_present_value`: Handles single-point reads.
- **Concurrency**: Uses `tokio` channels to bridge the synchronous/blocking nature of some BACnet request-response patterns with the async application runtime.

### 3.4 Application State (`app.rs`)
- Uses a `Mutex`-protected shared state pattern (`Arc<Mutex<App>>`).
- **View States**:
  - `InterfaceSelect`: Initial boot screen.
  - `DeviceList`: Results of the Who-Is scan.
  - `ObjectList`: Detailed view of a specific device.

### 3.5 User Interface (`ui.rs`)
- Built with `ratatui` (TUI library).
- Renders widgets based on the current `ViewState`.
- layout logic is decoupled from business logic.

## 4. Workflows

### 4.1 Discovery Workflow
1. User selects Network Interface (e.g., `eth0`).
2. App binds UDP socket to `0.0.0.0:47808` but targets broadcasts to the interface's broadcast address.
3. User presses `d`.
4. App transmits `Who-Is`.
5. Background listener task parses incoming `I-Am` packets and updates `App.devices`.
6. UI refreshes to show new rows.

### 4.2 Inspection Workflow
1. User selects a device and presses `Enter`.
2. View changes to `ObjectList`.
3. User presses `d` to scan points.
4. App initiates `ReadPropertyMultiple` sequence using the **Client Socket**.
5. `Object_List` is retrieved.
6. Objects are populated in the table.
7. Polling task registers these new points and begins cyclic reading.
