use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, Paragraph, Table, Row},
    Frame,
};
use crate::app::{App, ViewState};

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
    let title_text = match app.view_state {
        ViewState::InterfaceSelect => "BACnet Discovery Tool - Select Interface".to_string(),
        ViewState::DeviceList => "BACnet Discovery Tool - Devices".to_string(),
        ViewState::ObjectList(id) => format!("BACnet Discovery Tool - Device {} Objects", id),
    };
    
    let title = Paragraph::new(title_text)
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL).title("Information"));
    f.render_widget(title, chunks[0]);

    match app.view_state {
        ViewState::InterfaceSelect => render_interface_list(f, chunks[1], app),
        ViewState::DeviceList => render_device_list(f, chunks[1], app),
        ViewState::ObjectList(id) => render_object_list(f, chunks[1], app, id),
    }

    // Status Bar
    let status = Paragraph::new(app.status_message.as_str())
        .block(Block::default().borders(Borders::ALL).title("Status"));
    f.render_widget(status, chunks[2]);
}

fn render_interface_list(f: &mut Frame, area: ratatui::layout::Rect, app: &mut App) {
    let items: Vec<ListItem> = app.interfaces
        .iter()
        .map(|iface| {
            ListItem::new(format!("{} ({})", iface.name, iface.addr.ip()))
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Network Interfaces"))
        .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .highlight_symbol(">> ");
    f.render_stateful_widget(list, area, &mut app.interface_list_state);
}

fn render_device_list(f: &mut Frame, area: ratatui::layout::Rect, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    let devices_lock = app.devices.lock().unwrap();
    let mut device_ids: Vec<_> = devices_lock.keys().cloned().collect();
    device_ids.sort();

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
    f.render_stateful_widget(list, chunks[0], &mut app.list_state);

    let selected_device = app.list_state.selected()
        .and_then(|i| device_ids.get(i))
        .and_then(|id| devices_lock.get(id));

    let details_text = match selected_device {
        Some(d) => format!(
            "Device ID:     {}\n\
             IP Address:    {}\n\
             Vendor:        {} (ID: {})\n\
             Max APDU:      {}\n\
             Segmentation:  {}\n\
             Last Seen:     {}s ago\n\n\
             Press 'Enter' to view objects.",
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
        None => "Press 'd' to scan for devices.\nSelect a device to view details.".to_string(),
    };

    let details = Paragraph::new(details_text)
        .block(Block::default().borders(Borders::ALL).title("Device Details"));
    f.render_widget(details, chunks[1]);
}

fn render_object_list(f: &mut Frame, area: ratatui::layout::Rect, app: &mut App, device_id: u32) {
    let objects_lock = app.device_objects.lock().unwrap();
    let objects = objects_lock.get(&device_id);

    match objects {
        Some(objs) => {
            let header = Row::new(vec!["ID", "Name", "Value", "Units"])
                .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
                .bottom_margin(1);
            
            let rows: Vec<Row> = objs.iter().map(|obj| {
                Row::new(vec![
                    format!("{:?}:{}", obj.id.object_type, obj.id.instance),
                    obj.name.clone(),
                    obj.present_value.clone(),
                    obj.units.clone(),
                ])
            }).collect();

            let table = Table::new(rows, [
                Constraint::Percentage(25),
                Constraint::Percentage(35),
                Constraint::Percentage(20),
                Constraint::Percentage(20),
            ])
            .header(header)
            .block(Block::default().borders(Borders::ALL).title("Objects (Points)"))
            .row_highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
            .highlight_symbol(">> ");

            f.render_stateful_widget(table, area, &mut app.object_table_state);
        }
        None => {
            let msg = "No points discovered yet.\nPress 'd' to discover points for this device.";
            let p = Paragraph::new(msg)
                .block(Block::default().borders(Borders::ALL).title("Objects"))
                .style(Style::default().fg(Color::Gray));
            f.render_widget(p, area);
        }
    }
}
