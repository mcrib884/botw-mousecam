
use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};
use log::info;
use winapi::um::winuser;
use crate::i18n::Language;

fn default_magnesis_sensitivity() -> f32 {
    0.5  // Default sensitivity for magnesis control
}

fn default_camera_sensitivity_pct() -> f32 {
    // 0-100 scale where 50.0 corresponds to the current default camera sensitivity
    50.0
}

fn default_sprint_toggle_enabled() -> bool {
    true
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MouseButtonConfig {
    pub left_click: u8,      // VK code for left mouse button action
    pub right_click: u8,     // VK code for right mouse button action  
    pub mouse4: u8,          // VK code for mouse button 4 action
    pub mouse5: u8,          // VK code for mouse button 5 action
}

impl Default for MouseButtonConfig {
    fn default() -> Self {
        Self {
            left_click: 0x4B,   // 'K' key (Y button)
            right_click: 0x4C,  // 'L' key (ZR shoulder)
            mouse4: winuser::VK_LEFT as u8,     // Left Arrow (D-Pad Left)
            mouse5: winuser::VK_RIGHT as u8,    // Right Arrow (D-Pad Right)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MouseAxisConfig {
    pub left: u8,   // VK code for mouse left movement
    pub right: u8,  // VK code for mouse right movement
    pub up: u8,     // VK code for mouse up movement
    pub down: u8,   // VK code for mouse down movement
}

impl Default for MouseAxisConfig {
    fn default() -> Self {
        Self {
            left: winuser::VK_LEFT as u8,
            right: winuser::VK_RIGHT as u8,
            up: winuser::VK_UP as u8,
            down: winuser::VK_DOWN as u8,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CameraPatchConfig {
    // Main camera detour - this is the primary hook that intercepts camera data
    pub camera_detour_enabled: bool,  // Main camera function hook - MOST LIKELY CULPRIT

    // Input system hooks - these handle mouse/gamepad input
    pub xinput_detour_enabled: bool,   // XInput controller hook
    pub mouse_hook_enabled: bool,      // Mouse input hook

    // Camera position and focus writers - these control camera movement
    pub camera_pos_writer_1: bool,  // offset +0x17 - Primary position writer
    pub camera_pos_writer_2: bool,  // offset +0x55 - Secondary position writer
    pub camera_pos_writer_3: bool,  // offset +0xC2 - Tertiary position writer
    pub camera_pos_writer_4: bool,  // offset +0xD9 - Focus point writer 1
    pub camera_pos_writer_5: bool,  // offset +0x117 - Focus point writer 2
    pub camera_pos_writer_6: bool,  // offset +0x12E - Focus point writer 3
    pub camera_pos_writer_7: bool,  // offset +0x15D - Camera height writer
    pub camera_pos_writer_8: bool,  // offset +0x174 - Camera depth writer
    pub camera_pos_writer_9: bool,  // offset +0x22A - Final position writer

    // Rotation operations - these control camera rotation
    pub rotation_writer_1: bool,    // rotation_vec1 - Primary rotation
    pub rotation_writer_2: bool,    // rotation_vec1 + 0x14 - Secondary rotation
    pub rotation_writer_3: bool,    // rotation_vec1 + 0x28 - Tertiary rotation
}

impl Default for CameraPatchConfig {
    fn default() -> Self {
        Self {
            // All enabled by default to match current behavior
            camera_detour_enabled: true,
            xinput_detour_enabled: true,
            mouse_hook_enabled: true,
            camera_pos_writer_1: true,
            camera_pos_writer_2: true,
            camera_pos_writer_3: true,
            camera_pos_writer_4: true,
            camera_pos_writer_5: true,
            camera_pos_writer_6: true,
            camera_pos_writer_7: true,
            camera_pos_writer_8: true,
            camera_pos_writer_9: true,
            rotation_writer_1: true,
            rotation_writer_2: true,
            rotation_writer_3: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub version: u32,
    pub mouse_buttons: MouseButtonConfig,
    #[serde(default)]
    pub mouse_axes: MouseAxisConfig,
    pub hide_cursor_when_active: bool,  // Hide cursor when mod is active (and Cemu is focused)
    pub confine_cursor_to_window: bool,  // Confine cursor to Cemu window when active (prevents cursor from leaving window)
    pub first_run_done: bool,  // Replaces the root flag file
    pub camera_patches: CameraPatchConfig,  // Individual camera patch toggles
    #[serde(default = "default_magnesis_sensitivity")]
    pub magnesis_sensitivity: f32,  // Mouse sensitivity for magnesis control
    
    // Camera orbit sensitivity (0-100). 50.0 equals the legacy default speed.
    #[serde(default = "default_camera_sensitivity_pct")]
    pub camera_sensitivity_pct: f32,

    // Sprint key (VK) to hold for sprint toggle (bind the same key you use for sprint in Cemu)
    #[serde(default)]
    pub sprint_key: u8,

    // UI language (affects menu and init banner only)
    #[serde(default)]
    pub language: Language,

    // Enable/disable sprint toggle feature
    #[serde(default = "default_sprint_toggle_enabled")]
    pub sprint_toggle_enabled: bool,

}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 5,  // bumped for sprint toggle
            mouse_buttons: MouseButtonConfig::default(),
            mouse_axes: MouseAxisConfig::default(),
            hide_cursor_when_active: true,
            confine_cursor_to_window: false,  // Set to true to prevent cursor from leaving Cemu window
            first_run_done: false,
            camera_patches: CameraPatchConfig::default(),
            magnesis_sensitivity: 0.5,
            camera_sensitivity_pct: default_camera_sensitivity_pct(),
            sprint_key: winuser::VK_LSHIFT as u8, // Default to Left Shift
            language: Language::default(),
            sprint_toggle_enabled: default_sprint_toggle_enabled(),
        }
    }
}

impl Config {
    pub fn load_or_create(config_path: &str) -> Self {
        if Path::new(config_path).exists() {
            match fs::read_to_string(config_path) {
                Ok(content) => {
                    match toml::from_str::<Config>(&content) {
                        Ok(config) => {
                            info!("[CONFIG] ✓ Loaded configuration from {}", config_path);
                            return config;
                        }
                        Err(e) => {
                            info!("[CONFIG] ✗ Failed to parse config: {}", e);
                        }
                    }
                }
                Err(e) => {
                    info!("[CONFIG] ✗ Failed to read config file: {}", e);
                }
            }
        }
        
        // Create default config
        let config = Config::default();
        if let Err(e) = config.save(config_path) {
            info!("[CONFIG] ✗ Failed to save default config: {}", e);
        } else {
            info!("[CONFIG] ✓ Created default configuration at {}", config_path);
        }
        config
    }
    
    pub fn save(&self, config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let toml_string = toml::to_string_pretty(self)?;
        fs::write(config_path, toml_string)?;
        Ok(())
    }
}

// Key name mapping for user-friendly display
pub fn vk_to_name(vk: u8) -> String {
    match vk {
        0x08 => "Backspace".to_string(),
        0x09 => "Tab".to_string(),
        0x0D => "Enter".to_string(),
        0x10 => "Shift".to_string(),
        0x11 => "Ctrl".to_string(),
        0x12 => "Alt".to_string(),
        0xA0 => "Left Shift".to_string(),
        0xA1 => "Right Shift".to_string(),
        0xA2 => "Left Ctrl".to_string(),
        0xA3 => "Right Ctrl".to_string(),
        0xA4 => "Left Alt".to_string(),
        0xA5 => "Right Alt".to_string(),
        0x20 => "Space".to_string(),
        0x21 => "Page Up".to_string(),
        0x22 => "Page Down".to_string(),
        0x23 => "End".to_string(),
        0x24 => "Home".to_string(),
        0x25 => "Left Arrow".to_string(),
        0x26 => "Up Arrow".to_string(),
        0x27 => "Right Arrow".to_string(),
        0x28 => "Down Arrow".to_string(),
        0x30..=0x39 => format!("{}", (vk - 0x30) as char), // 0-9
        0x41..=0x5A => format!("{}", (vk as char)), // A-Z
        0x70..=0x87 => format!("F{}", vk - 0x6F), // F1-F24
        _ => format!("Key(0x{:02X})", vk),
    }
}

// Get VK code from user input
pub fn name_to_vk(name: &str) -> Option<u8> {
    let name_upper = name.to_uppercase();
    match name_upper.as_str() {
        "BACKSPACE" => Some(0x08),
        "TAB" => Some(0x09),
        "ENTER" => Some(0x0D),
        "SHIFT" => Some(0x10),
        "CTRL" => Some(0x11),
        "ALT" => Some(0x12),
        "SPACE" => Some(0x20),
        "PAGEUP" | "PAGE UP" => Some(0x21),
        "PAGEDOWN" | "PAGE DOWN" => Some(0x22),
        "END" => Some(0x23),
        "HOME" => Some(0x24),
        "LEFT" | "LEFTARROW" | "LEFT ARROW" => Some(0x25),
        "UP" | "UPARROW" | "UP ARROW" => Some(0x26),
        "RIGHT" | "RIGHTARROW" | "RIGHT ARROW" => Some(0x27),
        "DOWN" | "DOWNARROW" | "DOWN ARROW" => Some(0x28),
        _ => {
            // Single character A-Z, 0-9
            if name_upper.len() == 1 {
                let ch = name_upper.chars().next().unwrap();
                if ch.is_ascii_alphabetic() {
                    return Some(ch as u8);
                } else if ch.is_ascii_digit() {
                    return Some(0x30 + (ch as u8 - b'0'));
                }
            }
            // F keys
            if name_upper.starts_with('F') && name_upper.len() <= 3 {
                if let Ok(num) = name_upper[1..].parse::<u8>() {
                    if num >= 1 && num <= 24 {
                        return Some(0x6F + num);
                    }
                }
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vk_conversions() {
        assert_eq!(vk_to_name(0x4B), "K");
        assert_eq!(vk_to_name(0x25), "Left Arrow");
        assert_eq!(name_to_vk("K"), Some(0x4B));
        assert_eq!(name_to_vk("LEFT ARROW"), Some(0x25));
        assert_eq!(name_to_vk("F1"), Some(0x70));
    }
}
