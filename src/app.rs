use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use ratatui::widgets::{ListState, TableState};
use crate::bacnet::DiscoveredDevice;
use bacnet_rs::object::ObjectIdentifier;
use std::time::Instant;
use if_addrs::Interface;

#[derive(Debug, Clone)]
pub struct BacnetObject {
    pub id: ObjectIdentifier,
    pub name: String,
    pub present_value: String,
    pub units: String,
    pub last_updated: Instant,
}

pub enum ViewState {
    InterfaceSelect,
    DeviceList,
    ObjectList(u32), // Selected Device ID
}

pub struct App {
    /// Available network interfaces
    pub interfaces: Vec<Interface>,
    /// State for the interface list widget
    pub interface_list_state: ListState,
    /// Selected interface index
    pub selected_interface_index: Option<usize>,
    
    /// Discovered devices indexed by their Device ID
    pub devices: Arc<Mutex<HashMap<u32, DiscoveredDevice>>>,
    /// Objects for each device
    pub device_objects: Arc<Mutex<HashMap<u32, Vec<BacnetObject>>>>,
    /// State for the UI list widget
    pub list_state: ListState,
    /// State for the object table widget
    pub object_table_state: TableState,
    /// Current status bar message
    pub status_message: String,
    /// Current view state
    pub view_state: ViewState,
    /// Is a discovery scan currently active?
    pub is_scanning: bool,
}

impl App {
    pub fn new() -> Self {
        let interfaces = if_addrs::get_if_addrs().unwrap_or_default();
        let mut interface_list_state = ListState::default();
        if !interfaces.is_empty() {
            interface_list_state.select(Some(0));
        }

        Self {
            interfaces,
            interface_list_state,
            selected_interface_index: None,
            devices: Arc::new(Mutex::new(HashMap::new())),
            device_objects: Arc::new(Mutex::new(HashMap::new())),
            list_state: ListState::default(),
            object_table_state: TableState::default(),
            status_message: "Select an interface and press 'Enter'".to_string(),
            view_state: ViewState::InterfaceSelect,
            is_scanning: false,
        }
    }

    pub fn next(&mut self) {
        match self.view_state {
            ViewState::InterfaceSelect => {
                if self.interfaces.is_empty() { return; }
                let i = match self.interface_list_state.selected() {
                    Some(i) => if i >= self.interfaces.len() - 1 { 0 } else { i + 1 },
                    None => 0,
                };
                self.interface_list_state.select(Some(i));
            }
            ViewState::DeviceList => {
                let devices = self.devices.lock().unwrap();
                if devices.is_empty() { return; }
                let i = match self.list_state.selected() {
                    Some(i) => if i >= devices.len() - 1 { 0 } else { i + 1 },
                    None => 0,
                };
                self.list_state.select(Some(i));
            }
            ViewState::ObjectList(device_id) => {
                let objects = self.device_objects.lock().unwrap();
                if let Some(device_objs) = objects.get(&device_id) {
                    if device_objs.is_empty() { return; }
                    let i = match self.object_table_state.selected() {
                        Some(i) => if i >= device_objs.len() - 1 { 0 } else { i + 1 },
                        None => 0,
                    };
                    self.object_table_state.select(Some(i));
                }
            }
        }
    }

    pub fn previous(&mut self) {
        match self.view_state {
            ViewState::InterfaceSelect => {
                if self.interfaces.is_empty() { return; }
                let i = match self.interface_list_state.selected() {
                    Some(i) => if i == 0 { self.interfaces.len() - 1 } else { i - 1 },
                    None => 0,
                };
                self.interface_list_state.select(Some(i));
            }
            ViewState::DeviceList => {
                let devices = self.devices.lock().unwrap();
                if devices.is_empty() { return; }
                let i = match self.list_state.selected() {
                    Some(i) => if i == 0 { devices.len() - 1 } else { i - 1 },
                    None => 0,
                };
                self.list_state.select(Some(i));
            }
            ViewState::ObjectList(device_id) => {
                let objects = self.device_objects.lock().unwrap();
                if let Some(device_objs) = objects.get(&device_id) {
                    if device_objs.is_empty() { return; }
                    let i = match self.object_table_state.selected() {
                        Some(i) => if i == 0 { device_objs.len() - 1 } else { i - 1 },
                        None => 0,
                    };
                    self.object_table_state.select(Some(i));
                }
            }
        }
    }

    pub fn clear(&mut self) {
        let mut devices = self.devices.lock().unwrap();
        devices.clear();
        let mut objects = self.device_objects.lock().unwrap();
        objects.clear();
        self.list_state.select(None);
        self.object_table_state.select(None);
        self.status_message = "Scanning for devices...".to_string();
        self.is_scanning = true;
    }

    pub fn select_interface(&mut self) {
        if let Some(i) = self.interface_list_state.selected() {
            self.selected_interface_index = Some(i);
            self.view_state = ViewState::DeviceList;
            self.status_message = format!("Interface {} selected. Press 'd' to discover.", self.interfaces[i].name);
        }
    }

    pub fn enter_device(&mut self) {
        if let ViewState::DeviceList = self.view_state {
            let devices = self.devices.lock().unwrap();
            let mut device_ids: Vec<_> = devices.keys().cloned().collect();
            device_ids.sort();
            
            if let Some(index) = self.list_state.selected() {
                if let Some(id) = device_ids.get(index) {
                    self.view_state = ViewState::ObjectList(*id);
                    self.object_table_state.select(Some(0));
                    self.status_message = format!("Viewing device {}. Press 'Esc' to go back, 'd' to discover points", id);
                }
            }
        }
    }

    pub fn exit_view(&mut self) {
        match self.view_state {
            ViewState::ObjectList(_) => {
                self.view_state = ViewState::DeviceList;
                self.status_message = "Press 'd' to discover devices, 'Enter' to view points, 'q' to quit".to_string();
            }
            ViewState::DeviceList => {
                self.view_state = ViewState::InterfaceSelect;
                self.status_message = "Select an interface and press 'Enter'".to_string();
            }
            ViewState::InterfaceSelect => {}
        }
    }
}
