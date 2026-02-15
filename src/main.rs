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
use std::{io, net::UdpSocket, time::{Duration, Instant}};
use tokio::sync::mpsc;
use tracing::{info, error};

use crate::app::App;
use crate::network::create_shared_socket;
use crate::bacnet::{send_whois, process_response};

enum AppEvent {
    Input(Event),
    Tick,
    DeviceDiscovered(bacnet::DiscoveredDevice),
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();
    info!("Starting BACnet Discovery Tool");

    // Terminal setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // App state and communication
    let mut app = App::new();
    let (tx, mut rx) = mpsc::channel(100);

    // Event Loop: Input handling
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

    // Event Loop: BACnet Discovery
    let tx_bacnet = tx.clone();
    tokio::spawn(async move {
        let socket = match create_shared_socket(47808) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to bind to shared port 47808: {}. Falling back to random port.", e);
                UdpSocket::bind("0.0.0.0:0").expect("Failed to bind even to a random port")
            }
        };

        loop {
            // Periodic Who-Is broadcast
            if let Err(e) = send_whois(&socket) {
                error!("Failed to send Who-Is: {}", e);
            }

            let start_listen = Instant::now();
            let mut buf = [0u8; 1500];
            
            // Listen for 3 seconds before re-broadcasting
            while start_listen.elapsed() < Duration::from_secs(3) {
                match socket.recv_from(&mut buf) {
                    Ok((len, addr)) => {
                        if let Some(device) = process_response(&buf[..len], addr) {
                            let _ = tx_bacnet.send(AppEvent::DeviceDiscovered(device)).await;
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                        // Just a timeout, yield to other tasks
                        tokio::task::yield_now().await;
                    }
                    Err(e) => {
                        error!("Socket receive error: {}", e);
                    }
                }
            }
        }
    });

    // Main UI loop
    loop {
        terminal.draw(|f| ui::render(f, &mut app))?;

        if let Some(event) = rx.recv().await {
            match event {
                AppEvent::Input(Event::Key(key)) => match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('r') => app.clear(),
                    KeyCode::Down => app.next(),
                    KeyCode::Up => app.previous(),
                    _ => {}
                },
                AppEvent::DeviceDiscovered(device) => {
                    let mut devices = app.devices.lock().unwrap();
                    let id = device.device_id;
                    devices.insert(id, device);
                    app.status_message = format!("Found {} devices. 'r' to refresh, 'q' to quit", devices.len());
                }
                _ => {}
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    Ok(())
}
