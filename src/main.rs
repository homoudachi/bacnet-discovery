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
use std::{io, net::UdpSocket, sync::Arc, time::Duration};
use tokio::sync::mpsc;
use tracing::{info, error};

use crate::app::{App, ViewState};
use crate::network::create_shared_socket;
use crate::bacnet::{send_whois, process_response, read_device_objects, read_present_value};

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
    tracing_subscriber::fmt::init();
    info!("Starting BACnet Discovery Tool");

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    let (tx, mut rx) = mpsc::channel(100);

    let socket = Arc::new(create_shared_socket(47808).unwrap_or_else(|_| {
        UdpSocket::bind("0.0.0.0:0").expect("Failed to bind")
    }));

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

    let tx_recv = tx.clone();
    let socket_recv = Arc::clone(&socket);
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            match socket_recv.recv_from(&mut buf) {
                Ok((len, addr)) => {
                    if let Some(device) = process_response(&buf[..len], addr) {
                        let _ = tx_recv.send(AppEvent::DeviceDiscovered(device)).await;
                    }
                }
                Err(_) => {
                    tokio::task::yield_now().await;
                }
            }
        }
    });

    // Polling task
    let tx_poll = tx.clone();
    let socket_poll = Arc::clone(&socket);
    let devices_poll = Arc::clone(&app.devices);
    let objects_poll = Arc::clone(&app.device_objects);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let objects = objects_poll.lock().unwrap().clone();
            let devices = devices_poll.lock().unwrap().clone();
            
            for (device_id, points) in objects {
                if let Some(device) = devices.get(&device_id) {
                    for point in points {
                        match read_present_value(&socket_poll, device.address, point.id) {
                            Ok(val) => {
                                let _ = tx_poll.send(AppEvent::PointUpdated(device_id, point.id, val)).await;
                            }
                            Err(_) => {
                                // Silently ignore polling errors for now
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    });

    loop {
        terminal.draw(|f| ui::render(f, &mut app))?;

        if let Some(event) = rx.recv().await {
            match event {
                AppEvent::Input(Event::Key(key)) => match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('d') => {
                        match app.view_state {
                            ViewState::DeviceList => {
                                app.clear();
                                let socket_send = Arc::clone(&socket);
                                let tx_status = tx.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = send_whois(&socket_send) {
                                        error!("Discovery failed: {}", e);
                                    }
                                    tokio::time::sleep(Duration::from_secs(3)).await;
                                    let _ = tx_status.send(AppEvent::StatusUpdate("Scan complete.".to_string())).await;
                                });
                            }
                            ViewState::ObjectList(device_id) => {
                                let devices = app.devices.lock().unwrap();
                                if let Some(device) = devices.get(&device_id).cloned() {
                                    app.status_message = format!("Discovering points for device {}...", device_id);
                                    let socket_points = Arc::clone(&socket);
                                    let tx_points = tx.clone();
                                    tokio::spawn(async move {
                                        match read_device_objects(&socket_points, device.address, device_id) {
                                            Ok(points) => {
                                                let _ = tx_points.send(AppEvent::PointsDiscovered(device_id, points)).await;
                                            }
                                            Err(e) => {
                                                error!("Point discovery failed: {}", e);
                                                let _ = tx_points.send(AppEvent::StatusUpdate(format!("Error: {}", e))).await;
                                            }
                                        }
                                    });
                                }
                            }
                        }
                    }
                    KeyCode::Enter => app.enter_device(),
                    KeyCode::Esc => app.exit_device(),
                    KeyCode::Down => app.next(),
                    KeyCode::Up => app.previous(),
                    KeyCode::Char('r') => {
                        app.clear();
                        let socket_send = Arc::clone(&socket);
                        let _ = send_whois(&socket_send);
                    }
                    _ => {}
                },
                AppEvent::DeviceDiscovered(device) => {
                    let mut devices = app.devices.lock().unwrap();
                    let id = device.device_id;
                    devices.insert(id, device);
                    app.status_message = format!("Found {} devices. Press 'Enter' to view points.", devices.len());
                }
                AppEvent::PointsDiscovered(device_id, points) => {
                    let mut objects = app.device_objects.lock().unwrap();
                    objects.insert(device_id, points);
                    app.status_message = format!("Discovered points. Polling active.");
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
                AppEvent::Tick => {}
                _ => {}
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    Ok(())
}
