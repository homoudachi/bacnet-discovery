use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use ratatui::widgets::ListState;
use crate::bacnet::DiscoveredDevice;

pub struct App {
    /// Discovered devices indexed by their Device ID
    pub devices: Arc<Mutex<HashMap<u32, DiscoveredDevice>>>,
    /// State for the UI list widget
    pub list_state: ListState,
    /// Current status bar message
    pub status_message: String,
}

impl App {
    pub fn new() -> Self {
        Self {
            devices: Arc::new(Mutex::new(HashMap::new())),
            list_state: ListState::default(),
            status_message: "Press 'r' to refresh, 'q' to quit".to_string(),
        }
    }

    /// Selects the next item in the device list
    pub fn next(&mut self) {
        let devices = self.devices.lock().unwrap();
        if devices.is_empty() { return; }
        
        let i = match self.list_state.selected() {
            Some(i) => if i >= devices.len() - 1 { 0 } else { i + 1 },
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    /// Selects the previous item in the device list
    pub fn previous(&mut self) {
        let devices = self.devices.lock().unwrap();
        if devices.is_empty() { return; }
        
        let i = match self.list_state.selected() {
            Some(i) => if i == 0 { devices.len() - 1 } else { i - 1 },
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    /// Clears the discovered devices list
    pub fn clear(&mut self) {
        let mut devices = self.devices.lock().unwrap();
        devices.clear();
        self.list_state.select(None);
        self.status_message = "Refreshing...".to_string();
    }
}
