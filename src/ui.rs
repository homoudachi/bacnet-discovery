use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};
use crate::app::App;

/// Main UI rendering function
pub fn render(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Title
            Constraint::Min(0),    // Main content
            Constraint::Length(3), // Status bar
        ])
        .split(f.area());

    // Title Block
    let title = Paragraph::new("BACnet Discovery Tool")
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL).title("Information"));
    f.render_widget(title, chunks[0]);

    // Main Content: Split into List and Details
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(chunks[1]);

    let devices_lock = app.devices.lock().unwrap();
    let mut device_ids: Vec<_> = devices_lock.keys().cloned().collect();
    device_ids.sort();

    // Device List
    let items: Vec<ListItem> = device_ids
        .iter()
        .map(|id| {
            let d = &devices_lock[id];
            ListItem::new(format!("Device ID: {} ({})", d.device_id, d.vendor_name))
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Discovered Devices"))
        .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .highlight_symbol(">> ");
    f.render_stateful_widget(list, main_chunks[0], &mut app.list_state);

    // Device Details Panel
    let selected_device = app.list_state.selected()
        .and_then(|i| device_ids.get(i))
        .and_then(|id| devices_lock.get(id));

    let details_text = match selected_device {
        Some(d) => format!(
            "Device ID:     {}

             IP Address:    {}

             Vendor:        {} (ID: {})

             Max APDU:      {}

             Segmentation:  {}

             Last Seen:     {}s ago",
            d.device_id,
            d.address,
            d.vendor_name,
            d.vendor_id,
            d.max_apdu,
            match d.segmentation {
                0 => "Both",
                1 => "Transmit",
                2 => "Receive",
                3 => "None",
                _ => "Unknown",
            },
            d.last_seen.elapsed().as_secs()
        ),
        None => "Select a device to view its properties.".to_string(),
    };

    let details = Paragraph::new(details_text)
        .block(Block::default().borders(Borders::ALL).title("Device Details"));
    f.render_widget(details, main_chunks[1]);

    // Status Bar
    let status = Paragraph::new(app.status_message.as_str())
        .block(Block::default().borders(Borders::ALL).title("Status"));
    f.render_widget(status, chunks[2]);
}
