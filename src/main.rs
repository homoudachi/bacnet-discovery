mod app;
mod bacnet;
mod network;
mod ui;

use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{collections::HashMap, io, net::UdpSocket, sync::{Arc, Mutex}, time::Duration};
use tokio::sync::{mpsc, oneshot};
use tracing::{info, error, debug};

use crate::app::{App, ViewState};
use crate::network::create_shared_socket;
use crate::bacnet::{send_whois_to, process_response, read_device_objects, read_present_value, get_interface_broadcast, parse_confirmed_response};

enum AppEvent {
    Input(Event),
    Tick,
    DeviceDiscovered(bacnet::DiscoveredDevice),
    PointsDiscovered(u32, Vec<app::BacnetObject>),
    PointUpdated(u32, bacnet_rs::object::ObjectIdentifier, String),
    StatusUpdate(String),
}

#[tokio::main]
async fn main() -> Result<()> {
    let file_appender = std::fs::File::create("bacnet-discovery.log")?;
    tracing_subscriber::fmt()
        .with_writer(Arc::new(file_appender))
        .with_max_level(tracing::Level::DEBUG)
        .init();
    
    info!("Starting BACnet Discovery Tool");

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let app_arc = Arc::new(Mutex::new(App::new()));
    let (tx, mut rx) = mpsc::channel(100);
    
    let pending_requests: Arc<Mutex<HashMap<u8, oneshot::Sender<Vec<u8>>>>> = Arc::new(Mutex::new(HashMap::new()));
    let (tx_register, mut rx_register) = mpsc::channel::<(u8, oneshot::Sender<Vec<u8>>)>(100);

    let pending_requests_reg = Arc::clone(&pending_requests);
    tokio::spawn(async move {
        while let Some((invoke_id, tx_res)) = rx_register.recv().await {
            pending_requests_reg.lock().unwrap().insert(invoke_id, tx_res);
        }
    });

    let tx_input = tx.clone();
    tokio::spawn(async move {
        loop {
            if event::poll(Duration::from_millis(100)).unwrap_or(false) {
                if let Ok(e) = event::read() {
                    let _ = tx_input.send(AppEvent::Input(e)).await;
                }
            }
            let _ = tx_input.send(AppEvent::Tick).await;
        }
    });

    let mut discovery_socket: Option<Arc<UdpSocket>> = None;
    let mut client_socket: Option<Arc<UdpSocket>> = None;
    let mut receiver_handle: Option<tokio::task::JoinHandle<()>> = None;
    let mut polling_handle: Option<tokio::task::JoinHandle<()>> = None;

    loop {
        terminal.draw(|f| ui::render(f, &mut app_arc.lock().unwrap()))?;

        if let Some(event) = rx.recv().await {
            match event {
                AppEvent::Input(Event::Key(key)) => {
                    let mut app = app_arc.lock().unwrap();
                    match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Enter => {
                            if let ViewState::InterfaceSelect = app.view_state {
                                app.select_interface();
                                if let Some(idx) = app.selected_interface_index {
                                    let iface = app.interfaces[idx].clone();
                                    
                                    // 1. Discovery Socket (47808) for Who-Is/I-Am
                                    let ds = match create_shared_socket(47808) {
                                        Ok(s) => Arc::new(s),
                                        Err(e) => {
                                            error!("Failed to bind discovery socket: {}. Using random port.", e);
                                            Arc::new(UdpSocket::bind("0.0.0.0:0").unwrap())
                                        }
                                    };
                                    discovery_socket = Some(Arc::clone(&ds));

                                    // 2. Client Socket (Random Port) for Unicast Requests
                                    // This bypasses SO_REUSEPORT load balancing for responses.
                                    let cs = Arc::new(UdpSocket::bind("0.0.0.0:0").expect("Failed to bind client socket"));
                                    client_socket = Some(Arc::clone(&cs));

                                    let tx_recv = tx.clone();
                                    let ds_recv = Arc::clone(&ds);
                                    let cs_recv = Arc::clone(&cs);
                                    let pending_recv = Arc::clone(&pending_requests);
                                    
                                    if let Some(h) = receiver_handle.take() { h.abort(); }
                                    receiver_handle = Some(tokio::spawn(async move {
                                        let mut buf = [0u8; 1500];
                                        loop {
                                            // Listen on BOTH sockets
                                            // Priority 1: Client socket (responses)
                                            cs_recv.set_nonblocking(true).ok();
                                            if let Ok((len, _addr)) = cs_recv.recv_from(&mut buf) {
                                                if let Some((id, sdata)) = parse_confirmed_response(&buf[..len]) {
                                                    let mut map = pending_recv.lock().unwrap();
                                                    if let Some(tx_res) = map.remove(&id) { let _ = tx_res.send(sdata); }
                                                }
                                            }

                                            // Priority 2: Discovery socket (I-Am)
                                            ds_recv.set_nonblocking(true).ok();
                                            if let Ok((len, addr)) = ds_recv.recv_from(&mut buf) {
                                                if let Some(device) = process_response(&buf[..len], addr) {
                                                    let _ = tx_recv.send(AppEvent::DeviceDiscovered(device)).await;
                                                }
                                            }
                                            tokio::task::yield_now().await;
                                        }
                                    }));

                                    let tx_poll = tx.clone();
                                    let cs_poll = Arc::clone(&cs);
                                    let devices_poll = Arc::clone(&app.devices);
                                    let objects_poll = Arc::clone(&app.device_objects);
                                    let app_poll = Arc::clone(&app_arc);
                                    let tx_reg_poll = tx_register.clone();
                                    if let Some(h) = polling_handle.take() { h.abort(); }
                                    polling_handle = Some(tokio::spawn(async move {
                                        loop {
                                            tokio::time::sleep(Duration::from_secs(5)).await;
                                            let objects = objects_poll.lock().unwrap().clone();
                                            let devices = devices_poll.lock().unwrap().clone();
                                            for (device_id, points) in objects {
                                                if let Some(device) = devices.get(&device_id) {
                                                    for point in points {
                                                        let invoke_id = app_poll.lock().unwrap().get_next_invoke_id();
                                                        if let Ok(val) = read_present_value(&cs_poll, device.address, point.id, invoke_id, &tx_reg_poll).await {
                                                            let _ = tx_poll.send(AppEvent::PointUpdated(device_id, point.id, val)).await;
                                                        }
                                                        tokio::time::sleep(Duration::from_millis(100)).await;
                                                    }
                                                }
                                            }
                                        }
                                    }));
                                }
                            } else {
                                app.enter_device();
                            }
                        }
                        KeyCode::Esc => app.exit_view(),
                        KeyCode::Char('d') => {
                            match app.view_state {
                                ViewState::DeviceList => {
                                    if let Some(ref ds) = discovery_socket {
                                        app.clear();
                                        let s_send = Arc::clone(ds);
                                        let tx_status = tx.clone();
                                        let iface = app.interfaces[app.selected_interface_index.unwrap()].clone();
                                        tokio::spawn(async move {
                                            let broadcast_addr = get_interface_broadcast(&iface).unwrap_or_else(|| "255.255.255.255:47808".parse().unwrap());
                                            if let Err(e) = send_whois_to(&s_send, broadcast_addr) { error!("Discovery failed: {}", e); }
                                            tokio::time::sleep(Duration::from_secs(3)).await;
                                            let _ = tx_status.send(AppEvent::StatusUpdate("Scan complete.".to_string())).await;
                                        });
                                    }
                                }
                                ViewState::ObjectList(device_id) => {
                                    if let Some(ref cs) = client_socket {
                                        let device = { let d = app.devices.lock().unwrap(); d.get(&device_id).cloned() };
                                        if let Some(device) = device {
                                            app.status_message = format!("Discovering points for device {}...", device_id);
                                            let s_points = Arc::clone(cs);
                                            let tx_points = tx.clone();
                                            let tx_reg_points = tx_register.clone();
                                            let invoke_id = app.get_next_invoke_id();
                                            tokio::spawn(async move {
                                                match read_device_objects(&s_points, device.address, device_id, invoke_id, &tx_reg_points).await {
                                                    Ok(points) => { let _ = tx_points.send(AppEvent::PointsDiscovered(device_id, points)).await; }
                                                    Err(e) => { let _ = tx_points.send(AppEvent::StatusUpdate(format!("Error: {}", e))).await; }
                                                }
                                            });
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        KeyCode::Down => app.next(),
                        KeyCode::Up => app.previous(),
                        _ => {}
                    }
                },
                AppEvent::DeviceDiscovered(device) => {
                    let app = app_arc.lock().unwrap();
                    let mut devices = app.devices.lock().unwrap();
                    devices.insert(device.device_id, device);
                }
                AppEvent::PointsDiscovered(device_id, points) => {
                    let app = app_arc.lock().unwrap();
                    let mut objects = app.device_objects.lock().unwrap();
                    objects.insert(device_id, points);
                }
                AppEvent::PointUpdated(device_id, object_id, value) => {
                    let app = app_arc.lock().unwrap();
                    let mut objects = app.device_objects.lock().unwrap();
                    if let Some(device_objs) = objects.get_mut(&device_id) {
                        if let Some(point) = device_objs.iter_mut().find(|o| o.id == object_id) {
                            point.present_value = value;
                            point.last_updated = std::time::Instant::now();
                        }
                    }
                }
                AppEvent::StatusUpdate(msg) => {
                    app_arc.lock().unwrap().status_message = msg;
                }
                _ => {}
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    Ok(())
}
