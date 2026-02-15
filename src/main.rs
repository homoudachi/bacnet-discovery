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
use tracing::{info, error};

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

    let mut app = App::new();
    let (tx, mut rx) = mpsc::channel(100);
    
    // Map to store pending confirmed request responders
    let pending_requests: Arc<Mutex<HashMap<u8, oneshot::Sender<Vec<u8>>>>> = Arc::new(Mutex::new(HashMap::new()));
    let (tx_register, mut rx_register) = mpsc::channel::<(u8, oneshot::Sender<Vec<u8>>)>(100);

    // Request Registration Task
    let pending_requests_reg = Arc::clone(&pending_requests);
    tokio::spawn(async move {
        while let Some((invoke_id, tx_res)) = rx_register.recv().await {
            pending_requests_reg.lock().unwrap().insert(invoke_id, tx_res);
        }
    });

    let mut socket: Option<Arc<UdpSocket>> = None;

    // Input thread
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

    let mut receiver_handle: Option<tokio::task::JoinHandle<()>> = None;
    let mut polling_handle: Option<tokio::task::JoinHandle<()>> = None;

    loop {
        terminal.draw(|f| ui::render(f, &mut app))?;

        if let Some(event) = rx.recv().await {
            match event {
                AppEvent::Input(Event::Key(key)) => match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Enter => {
                        if let ViewState::InterfaceSelect = app.view_state {
                            app.select_interface();
                            if let Some(idx) = app.selected_interface_index {
                                let _iface = &app.interfaces[idx];
                                match create_shared_socket(47808) {
                                    Ok(s) => {
                                        let s_arc = Arc::new(s);
                                        socket = Some(Arc::clone(&s_arc));
                                        
                                        // Unified Receiver Task
                                        let tx_recv = tx.clone();
                                        let s_recv = Arc::clone(&s_arc);
                                        let pending_recv = Arc::clone(&pending_requests);
                                        if let Some(h) = receiver_handle.take() { h.abort(); }
                                        receiver_handle = Some(tokio::spawn(async move {
                                            let mut buf = [0u8; 1500];
                                            loop {
                                                match s_recv.recv_from(&mut buf) {
                                                    Ok((len, addr)) => {
                                                        let data = &buf[..len];
                                                        // 1. Check for I-Am
                                                        if let Some(device) = process_response(data, addr) {
                                                            let _ = tx_recv.send(AppEvent::DeviceDiscovered(device)).await;
                                                        } 
                                                        // 2. Check for Confirmed Response
                                                        else if let Some((invoke_id, service_data)) = parse_confirmed_response(data) {
                                                            let mut map = pending_recv.lock().unwrap();
                                                            if let Some(tx_res) = map.remove(&invoke_id) {
                                                                let _ = tx_res.send(service_data);
                                                            }
                                                        }
                                                    }
                                                    Err(_) => { tokio::task::yield_now().await; }
                                                }
                                            }
                                        }));

                                        // Start polling task
                                        let tx_poll = tx.clone();
                                        let s_poll = Arc::clone(&s_arc);
                                        let devices_poll = Arc::clone(&app.devices);
                                        let objects_poll = Arc::clone(&app.device_objects);
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
                                                            if let Ok(val) = read_present_value(&s_poll, device.address, point.id, &tx_reg_poll).await {
                                                                let _ = tx_poll.send(AppEvent::PointUpdated(device_id, point.id, val)).await;
                                                            }
                                                            tokio::time::sleep(Duration::from_millis(100)).await;
                                                        }
                                                    }
                                                }
                                            }
                                        }));
                                    }
                                    Err(e) => { app.status_message = format!("Error: {}", e); }
                                }
                            }
                        } else {
                            app.enter_device();
                        }
                    }
                    KeyCode::Esc => app.exit_view(),
                    KeyCode::Char('d') => {
                        if let Some(ref s) = socket {
                            match app.view_state {
                                ViewState::DeviceList => {
                                    app.clear();
                                    let s_send = Arc::clone(s);
                                    let tx_status = tx.clone();
                                    let iface = app.interfaces[app.selected_interface_index.unwrap()].clone();
                                    tokio::spawn(async move {
                                        let broadcast_addr = get_interface_broadcast(&iface).unwrap_or_else(|| "255.255.255.255:47808".parse().unwrap());
                                        if let Err(e) = send_whois_to(&s_send, broadcast_addr) { error!("Discovery failed: {}", e); }
                                        tokio::time::sleep(Duration::from_secs(3)).await;
                                        let _ = tx_status.send(AppEvent::StatusUpdate("Scan complete.".to_string())).await;
                                    });
                                }
                                ViewState::ObjectList(device_id) => {
                                    let devices = app.devices.lock().unwrap();
                                    if let Some(device) = devices.get(&device_id).cloned() {
                                        app.status_message = format!("Discovering points for device {}...", device_id);
                                        let s_points = Arc::clone(s);
                                        let tx_points = tx.clone();
                                        let tx_reg_points = tx_register.clone();
                                        tokio::spawn(async move {
                                            match read_device_objects(&s_points, device.address, device_id, &tx_reg_points).await {
                                                Ok(points) => { let _ = tx_points.send(AppEvent::PointsDiscovered(device_id, points)).await; }
                                                Err(e) => { let _ = tx_points.send(AppEvent::StatusUpdate(format!("Error: {}", e))).await; }
                                            }
                                        });
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    KeyCode::Down => app.next(),
                    KeyCode::Up => app.previous(),
                    _ => {}
                },
                AppEvent::DeviceDiscovered(device) => {
                    let mut devices = app.devices.lock().unwrap();
                    let id = device.device_id;
                    devices.insert(id, device);
                    app.status_message = format!("Found {} devices. 'Enter' to view, 'd' to re-scan.", devices.len());
                }
                AppEvent::PointsDiscovered(device_id, points) => {
                    let mut objects = app.device_objects.lock().unwrap();
                    objects.insert(device_id, points);
                    app.status_message = "Discovered points. Polling active.".to_string();
                }
                AppEvent::PointUpdated(device_id, object_id, value) => {
                    let mut objects = app.device_objects.lock().unwrap();
                    if let Some(device_objs) = objects.get_mut(&device_id) {
                        if let Some(point) = device_objs.iter_mut().find(|o| o.id == object_id) {
                            point.present_value = value;
                            point.last_updated = std::time::Instant::now();
                        }
                    }
                }
                AppEvent::StatusUpdate(msg) => {
                    app.status_message = msg;
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
