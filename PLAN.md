# Development Plan & Roadmap

## Phase 1: Reliability & Testing (Completed)
- [x] **Interface Selection**: Prevent broadcast storms by targeting specific subnets.
- [x] **Unified Receiver**: Fix race conditions between discovery and polling tasks.
- [x] **Dual-Socket Architecture**: Separate broadcast (discovery) and unicast (client) traffic to guarantee response delivery.
- [x] **Automated Tests**: Integration tests for local discovery and point retrieval.
- [x] **Responder Improvements**: Added simulated points and broadcast `I-Am` support.

## Phase 2: Core TUI Enhancements (Next Steps)
- [ ] **Polling Configuration**: Add UI to change the default 5s polling rate.
- [ ] **Object Filtering**: Filter points by type (AI, BI, etc.) or name.
- [ ] **Extended Properties**: Show more than just `Present_Value` (e.g., Description, Status Flags).
- [ ] **Device Sorting**: Sort devices by ID, Vendor, or IP.

## Phase 3: Control Features
- [ ] **Write Property**: Allow users to edit values (Priority Array logic).
    - Press `Enter` on a point -> Open edit dialog -> Select Priority -> Send WriteProperty.
- [ ] **COV Subscription**: Implement `SubscribeCOV` for event-driven updates instead of polling.
- [ ] **Release Priority**: Mechanism to release overrides (write NULL at priority).

## Phase 4: Professional Features
- [ ] **Device Export**: Save discovered devices and points to CSV/JSON.
- [ ] **Traffic Analyzer**: Integrated "Sniffer" view within the main tool.
- [ ] **Health Check**: Ping statistics and error rate tracking.
- [ ] **Network Diagram**: Visualize network topology (routers, subnets).

## Phase 5: CI/CD & Deployment
- [ ] **GitHub Actions**: Automated testing and release builds.
- [ ] **Cross-Platform**: Support for Windows and macOS (handling socket options gracefully).
- [ ] **Docker**: Containerized build for easy deployment.
