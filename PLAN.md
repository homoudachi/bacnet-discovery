# Development Plan & Roadmap

## Phase 1: Reliability & Testing (Current)
- [x] **Interface Selection**: Prevent broadcast storms by targeting specific subnets.
- [x] **Unified Receiver**: Fix race conditions between discovery and polling tasks.
- [ ] **Responder Improvements**: 
    - Fix `I-Am` unicast/broadcast behavior to work reliably with `SO_REUSEPORT`.
    - Support multiple mock devices in one instance.
    - Upgrade to TUI for runtime manipulation of values.

## Phase 2: Core TUI Enhancements
- [ ] **Polling Configuration**: Add UI to change the default 5s polling rate.
- [ ] **Object Filtering**: Filter points by type (AI, BI, etc.) or name.
- [ ] **Extended Properties**: Show more than just `Present_Value` (e.g., Description, Status Flags).

## Phase 3: Control Features
- [ ] **Write Property**: Allow users to edit values (Priority Array logic).
    - Press `Enter` on a point -> Open edit dialog -> Select Priority -> Send WriteProperty.
- [ ] **COV Subscription**: Implement `SubscribeCOV` for event-driven updates instead of polling.

## Phase 4: Professional Features
- [ ] **Device Export**: Save discovered devices and points to CSV/JSON.
- [ ] **Traffic Analyzer**: Integrated "Sniffer" view within the main tool.
- [ ] **Health Check**: Ping statistics and error rate tracking.
