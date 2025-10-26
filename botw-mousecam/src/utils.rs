use crate::globals::*;
use crate::config::{Config, vk_to_name};
use crate::i18n::Language;
use crate::focus::{is_cemu_focused, setup_cursor_control, cleanup_cursor_control, set_cursor_hidden};
use std::ffi::CString;
use std::collections::HashMap;
use winapi::um::{winuser, xinput};
use winapi::shared::windef::POINT;
use winapi::shared::minwindef::WORD;
use log::{info, debug};
use std::sync::atomic::{Ordering, AtomicBool};

// Determine if a virtual key is an extended key (requires KEYEVENTF_EXTENDEDKEY)
fn is_extended_key(vk: u8) -> bool {
    match vk as i32 {
        // Arrow keys and navigation keys are extended
        x if x == winuser::VK_LEFT
            || x == winuser::VK_RIGHT
            || x == winuser::VK_UP
            || x == winuser::VK_DOWN
            || x == winuser::VK_INSERT
            || x == winuser::VK_DELETE
            || x == winuser::VK_HOME
            || x == winuser::VK_END
            || x == winuser::VK_PRIOR // Page Up
            || x == winuser::VK_NEXT  // Page Down
            || x == winuser::VK_DIVIDE // Numpad /
            || x == winuser::VK_NUMLOCK => true,
        _ => false,
    }
}

// Modern keyboard emulation using SendInput with scan codes for better compatibility
pub fn send_key(mut vk: u8, pressed: bool) {
    unsafe {
        // Normalize generic SHIFT to Left Shift for reliability
        if vk as i32 == winuser::VK_SHIFT { vk = winuser::VK_LSHIFT as u8; }

        let sc = winuser::MapVirtualKeyA(vk as u32, winuser::MAPVK_VK_TO_VSC) as WORD;

        let use_scancode = sc != 0;
        let extended = is_extended_key(vk);

        let mut input = winuser::INPUT { type_: winuser::INPUT_KEYBOARD, u: std::mem::zeroed() };
        let flags = if use_scancode { winuser::KEYEVENTF_SCANCODE } else { 0 }
            | if !pressed { winuser::KEYEVENTF_KEYUP } else { 0 }
            | if extended { winuser::KEYEVENTF_EXTENDEDKEY } else { 0 };

        *input.u.ki_mut() = winuser::KEYBDINPUT {
            wVk: if use_scancode { 0 } else { vk as WORD },
            wScan: if use_scancode { sc } else { 0 },
            dwFlags: flags,
            time: 0,
            dwExtraInfo: 0,
        };

        winuser::SendInput(1, &mut input, std::mem::size_of::<winuser::INPUT>() as i32);

        // Small delay to ensure registration
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

// Public wrapper for key send (for use in other modules)
pub fn send_vk(vk: u8, pressed: bool) {
    // Debug logging for sprint key specifically
    if vk != 0 {
        debug!("[KEY_SEND] VK 0x{:02X} ({}) -> {}", vk, crate::config::vk_to_name(vk), if pressed { "DOWN" } else { "UP" });
    }
    send_key(vk, pressed);
}

pub fn init_global_config(config: Config) {
    unsafe {
        info!("[CONFIG] Initializing global configuration. experimental_magnesis_fps_camera: {}", config.experimental_magnesis_fps_camera);
        GLOBAL_CONFIG = Some(config);
        info!("[CONFIG] Global configuration initialized");
    }
}

static DEFAULT_CONFIG: Config = Config {
    version: 5,
    mouse_buttons: crate::config::MouseButtonConfig {
        left_click: 0x4B,   // 'K' key (Y button)
        right_click: 0x4C,  // 'L' key (ZR shoulder)
        mouse4: winuser::VK_LEFT as u8,     // Left Arrow (D-Pad Left)
        mouse5: winuser::VK_RIGHT as u8,    // Right Arrow (D-Pad Right)
    },
    mouse_axes: crate::config::MouseAxisConfig {
        left: winuser::VK_LEFT as u8,
        right: winuser::VK_RIGHT as u8,
        up: winuser::VK_UP as u8,
        down: winuser::VK_DOWN as u8,
    },
    hide_cursor_when_active: true,
    confine_cursor_to_window: false,
    first_run_done: false,
    camera_patches: crate::config::CameraPatchConfig {
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
    },
    magnesis_sensitivity: 0.5,
    camera_sensitivity_pct: 50.0,
    language: Language::English,
    sprint_key: winuser::VK_LSHIFT as u8, // Default to Left Shift
    sprint_toggle_enabled: true,
    experimental_magnesis_fps_camera: false,
};

pub fn get_global_config() -> &'static Config {
    unsafe {
        GLOBAL_CONFIG.as_ref().unwrap_or(&DEFAULT_CONFIG)
    }
}

pub fn keyboard_emulation_tick(active: bool) {
    unsafe {
        static mut INIT_LOGGED: bool = false;
        static mut LAST_L: bool = false;
        static mut LAST_R: bool = false;
        static mut LAST_X1: bool = false;
        static mut LAST_X2: bool = false;
        // Axis key hold state
        static mut LAST_AXIS_LEFT: bool = false;
        static mut LAST_AXIS_RIGHT: bool = false;
        static mut LAST_AXIS_UP: bool = false;
        static mut LAST_AXIS_DOWN: bool = false;
        static mut DEBUG_COUNTER: u32 = 0; // retained (unused) for backward compatibility
        static mut LAST_FOCUS_WARN: Option<std::time::Instant> = None;
        static mut LAST_BUTTONS_LOG: Option<std::time::Instant> = None;

        let config = get_global_config();

        // At this point, mod is active (gated above). We still support a clean release path
        if !active {
            // On deactivate, ensure keys are released if they were held
            if LAST_L { send_key(config.mouse_buttons.left_click, false); LAST_L = false; }
            if LAST_R { send_key(config.mouse_buttons.right_click, false); LAST_R = false; }
            if LAST_X1 { send_key(config.mouse_buttons.mouse4, false); LAST_X1 = false; }
            if LAST_X2 { send_key(config.mouse_buttons.mouse5, false); LAST_X2 = false; }
            if LAST_AXIS_LEFT { send_key(config.mouse_axes.left, false); LAST_AXIS_LEFT = false; }
            if LAST_AXIS_RIGHT { send_key(config.mouse_axes.right, false); LAST_AXIS_RIGHT = false; }
            if LAST_AXIS_UP { send_key(config.mouse_axes.up, false); LAST_AXIS_UP = false; }
            if LAST_AXIS_DOWN { send_key(config.mouse_axes.down, false); LAST_AXIS_DOWN = false; }
            INIT_LOGGED = false;
            DEBUG_COUNTER = 0;
            return;
        }

        DEBUG_COUNTER += 1;

        if !INIT_LOGGED {
            info!("[KEYBOARD] ✓ Custom keyboard emulation ACTIVE");
            info!("[KEYBOARD] ✓ Your key bindings:");
            info!("[KEYBOARD]   - Left Click → {} (Y Button)", vk_to_name(config.mouse_buttons.left_click));
            info!("[KEYBOARD]   - Right Click → {} (ZR Shoulder)", vk_to_name(config.mouse_buttons.right_click));
            info!("[KEYBOARD]   - Mouse 4 → {} (D-Pad Left)", vk_to_name(config.mouse_buttons.mouse4));
            info!("[KEYBOARD]   - Mouse 5 → {} (D-Pad Right)", vk_to_name(config.mouse_buttons.mouse5));
            info!("[KEYBOARD]   - Focus Required: YES");
            info!("[KEYBOARD] ✓ Map these keys in CEMU's keyboard controller settings");
            INIT_LOGGED = true;
        }

        // Always require CEMU focus
        if !is_cemu_focused() {
            // Warn once every 5 seconds if focus is lost
            let now = std::time::Instant::now();
            let should_warn = match LAST_FOCUS_WARN {
                Some(last_warn) => now.duration_since(last_warn) > std::time::Duration::from_secs(5),
                None => true,
            };
            
            if should_warn {
                info!("[KEYBOARD] CEMU not focused - mouse buttons disabled");
                LAST_FOCUS_WARN = Some(now);
            }
            
            // Release all keys if focus is lost
            if LAST_L { send_key(config.mouse_buttons.left_click, false); LAST_L = false; }
            if LAST_R { send_key(config.mouse_buttons.right_click, false); LAST_R = false; }
            if LAST_X1 { send_key(config.mouse_buttons.mouse4, false); LAST_X1 = false; }
            if LAST_X2 { send_key(config.mouse_buttons.mouse5, false); LAST_X2 = false; }
            if LAST_AXIS_LEFT { send_key(config.mouse_axes.left, false); LAST_AXIS_LEFT = false; }
            if LAST_AXIS_RIGHT { send_key(config.mouse_axes.right, false); LAST_AXIS_RIGHT = false; }
            if LAST_AXIS_UP { send_key(config.mouse_axes.up, false); LAST_AXIS_UP = false; }
            if LAST_AXIS_DOWN { send_key(config.mouse_axes.down, false); LAST_AXIS_DOWN = false; }
            return;
        }

        let l = check_key_press(winuser::VK_LBUTTON);
        let r = check_key_press(winuser::VK_RBUTTON);
        let x1 = check_key_press(winuser::VK_XBUTTON1);
        let x2 = check_key_press(winuser::VK_XBUTTON2);

        // Read last mouse axes (set in handle_mouse_input)
        let (mx, my) = {
            (LAST_MOUSE_DELTA_X, LAST_MOUSE_DELTA_Y)
        };

        // Button state summary logs: at most once every 5 seconds while any button is held
        let should_log_buttons = LAST_BUTTONS_LOG.map_or(true, |t| t.elapsed() > std::time::Duration::from_secs(5));
        if should_log_buttons && (l || r || x1 || x2) {
            debug!("[KEYBOARD] Buttons: L:{} R:{} X1:{} X2:{}", l, r, x1, x2);
            LAST_BUTTONS_LOG = Some(std::time::Instant::now());
        }

        if l != LAST_L {
            send_key(config.mouse_buttons.left_click, l);
            LAST_L = l;
        }
        if r != LAST_R {
            send_key(config.mouse_buttons.right_click, r);
            LAST_R = r;
        }
        if x1 != LAST_X1 {
            send_key(config.mouse_buttons.mouse4, x1);
            LAST_X1 = x1;
        }
        if x2 != LAST_X2 {
            send_key(config.mouse_buttons.mouse5, x2);
            LAST_X2 = x2;
        }

        // Axis-to-key mapping from accumulated mouse movement
        // Only active while an in-game menu is open
        // Use lib.rs menu detection accessor to ensure we're reading the active system
        // Fall back to legacy menu_state module if needed
        let menu_open = crate::is_menu_open_now() || crate::menu_state::is_in_menu();

        if menu_open {
            // Use higher thresholds to prevent keys being held on small movements
            const AXIS_THRESHOLD_X: i32 = 15; // Horizontal threshold (increased to prevent small movement key holding)
            const AXIS_THRESHOLD_Y: i32 = 25; // Vertical threshold (significantly increased to prevent small movement key holding)

            // Check if accumulated movement exceeds threshold
            let want_left = mx < -AXIS_THRESHOLD_X;  
            let want_right = mx > AXIS_THRESHOLD_X;  
            let want_up = my < -AXIS_THRESHOLD_Y;    
            let want_down = my > AXIS_THRESHOLD_Y;
            
            // Press/hold keys for active directions
            if want_left != LAST_AXIS_LEFT {
                send_key(config.mouse_axes.left, want_left);
                LAST_AXIS_LEFT = want_left;
            }
            if want_right != LAST_AXIS_RIGHT {
                send_key(config.mouse_axes.right, want_right);
                LAST_AXIS_RIGHT = want_right;
            }
            if want_up != LAST_AXIS_UP {
                send_key(config.mouse_axes.up, want_up);
                LAST_AXIS_UP = want_up;
            }
            if want_down != LAST_AXIS_DOWN {
                send_key(config.mouse_axes.down, want_down);
                LAST_AXIS_DOWN = want_down;
            }
            
            // Ensure exclusivity (only one direction per axis)
            if want_left && LAST_AXIS_RIGHT {
                send_key(config.mouse_axes.right, false);
                LAST_AXIS_RIGHT = false;
            }
            if want_right && LAST_AXIS_LEFT {
                send_key(config.mouse_axes.left, false);
                LAST_AXIS_LEFT = false;
            }
            if want_up && LAST_AXIS_DOWN {
                send_key(config.mouse_axes.down, false);
                LAST_AXIS_DOWN = false;
            }
            if want_down && LAST_AXIS_UP {
                send_key(config.mouse_axes.up, false);
                LAST_AXIS_UP = false;
            }
        } else {
            // If menu is not open, ensure any held axis keys are released
            if LAST_AXIS_LEFT { send_key(config.mouse_axes.left, false); LAST_AXIS_LEFT = false; }
            if LAST_AXIS_RIGHT { send_key(config.mouse_axes.right, false); LAST_AXIS_RIGHT = false; }
            if LAST_AXIS_UP { send_key(config.mouse_axes.up, false); LAST_AXIS_UP = false; }
            if LAST_AXIS_DOWN { send_key(config.mouse_axes.down, false); LAST_AXIS_DOWN = false; }
        }
    }
}

pub fn get_updated_instructions() -> String {
    let config = get_global_config();
    format!(r#"------------------------------
BOTW MOUSE CAMERA MOD:
F3                  Camera mode on/off
F4                  Open configuration menu
Mouse movement      Rotate the camera (and emits axis keys)
Mouse wheel         Zoom in/out (disabled during PhoneCamera mode)
Middle mouse click  Reset zoom to default (no rotation)

AXIS KEY BINDINGS (mouse → keys):
Left (←)           {}
Right (→)          {}
Up (↑)             {}
Down (↓)           {}

CUSTOM MOUSE BUTTON BINDINGS:
Left click          {} (Y Button)
Right click         {} (ZR Shoulder)
Mouse 4             {} (D-Pad Left)
Mouse 5             {} (D-Pad Right)

Focus Required:     Mouse lock only works when CEMU window is focused
                    (cursor moves freely when CEMU loses focus)
HOME                Exit mod
------------------------------"#,
        vk_to_name(config.mouse_axes.left),
        vk_to_name(config.mouse_axes.right),
        vk_to_name(config.mouse_axes.up),
        vk_to_name(config.mouse_axes.down),
        vk_to_name(config.mouse_buttons.left_click),
        vk_to_name(config.mouse_buttons.right_click),
        vk_to_name(config.mouse_buttons.mouse4),
        vk_to_name(config.mouse_buttons.mouse5)
    )
}

pub fn check_key_press(key: i32) -> bool {
    (unsafe { winuser::GetAsyncKeyState(key) } as u32) & 0x8000 != 0
}

// Enhanced key checking that filters out key combinations
pub fn check_hotkey_press(key: i32) -> bool {
    unsafe {
        // First check if the target key is pressed
        let key_state = winuser::GetAsyncKeyState(key);
        let is_pressed = (key_state as u32) & 0x8000 != 0;
        
        if !is_pressed {
            return false;
        }
        
        // Check if any modifier keys are pressed (we want pure single key presses)
        let ctrl_pressed = (winuser::GetAsyncKeyState(winuser::VK_CONTROL) as u32) & 0x8000 != 0;
        let alt_pressed = (winuser::GetAsyncKeyState(winuser::VK_MENU) as u32) & 0x8000 != 0;
        let shift_pressed = (winuser::GetAsyncKeyState(winuser::VK_SHIFT) as u32) & 0x8000 != 0;
        let win_pressed = (winuser::GetAsyncKeyState(winuser::VK_LWIN) as u32) & 0x8000 != 0 || 
                         (winuser::GetAsyncKeyState(winuser::VK_RWIN) as u32) & 0x8000 != 0;
        
        // Only return true if no modifier keys are pressed (pure single key press)
        is_pressed && !ctrl_pressed && !alt_pressed && !shift_pressed && !win_pressed
    }
}

// Debounced key checking to prevent rapid-fire detection
pub fn check_hotkey_press_debounced(key: i32, debounce_ms: u64) -> bool {
    use std::collections::HashMap;
    use std::time::{Duration, Instant};
    
    // Track last time a key fired and last down state to ensure edge-triggered behavior
    static mut LAST_PRESS_TIMES: Option<HashMap<i32, Instant>> = None;
    static mut LAST_DOWN_STATE: Option<HashMap<i32, bool>> = None;
    
    unsafe {
        // Initialize maps if they don't exist
        if LAST_PRESS_TIMES.is_none() {
            LAST_PRESS_TIMES = Some(HashMap::new());
        }
        if LAST_DOWN_STATE.is_none() {
            LAST_DOWN_STATE = Some(HashMap::new());
        }
        
        let press_times = LAST_PRESS_TIMES.as_mut().unwrap();
        let down_state = LAST_DOWN_STATE.as_mut().unwrap();
        let now = Instant::now();
        
        let is_down = check_hotkey_press(key);
        let was_down = *down_state.get(&key).unwrap_or(&false);
        
        // Update stored state
        down_state.insert(key, is_down);
        
        // Only trigger on rising edge (was up, now down)
        if !is_down || was_down {
            return false;
        }
        
        // Debounce: ensure enough time since last accepted press
        if let Some(last_press) = press_times.get(&key) {
            if now.duration_since(*last_press) < Duration::from_millis(debounce_ms) {
                return false; // Still in debounce period
            }
        }
        
        // Record this press time and return true
        press_times.insert(key, now);
        true
    }
}

#[derive(Default, Debug)]
pub struct MouseInput {
    pub orbit_x: f32,
    pub orbit_y: f32,
    pub zoom: f32,
    pub reset_zoom: bool,
    pub reset_camera: bool,
    pub change_active: bool,
    pub show_config_menu: bool,
    pub is_active: bool,
    pub deattach: bool,
    pub distance: f32,
    
    // Mouse button tracking for gamepad mapping (now always active with camera mode)
    pub mouse_buttons: HashMap<u32, bool>, // button_id -> pressed state
    pub button_mappings: HashMap<u32, u16>, // mouse_button -> xinput_button
}

impl MouseInput {
    pub fn new() -> Self {
        let mut button_mappings = HashMap::new();
        
        // Default mouse button mappings
        button_mappings.insert(winuser::VK_LBUTTON as u32, xinput::XINPUT_GAMEPAD_Y);
        button_mappings.insert(winuser::VK_RBUTTON as u32, xinput::XINPUT_GAMEPAD_RIGHT_SHOULDER);
        // Middle button reserved for zoom reset functionality
        button_mappings.insert(winuser::VK_XBUTTON1 as u32, xinput::XINPUT_GAMEPAD_DPAD_LEFT);
        button_mappings.insert(winuser::VK_XBUTTON2 as u32, xinput::XINPUT_GAMEPAD_DPAD_RIGHT);
        
        Self {
            distance: 5.0,
            zoom: 0.0,
            mouse_buttons: HashMap::new(),
            button_mappings,
            ..Default::default()
        }
    }

    pub fn reset(&mut self) {
        self.orbit_x = 0.0;
        self.orbit_y = 0.0;
        self.zoom = 0.0;
        self.reset_camera = false;
        self.reset_zoom = false;
        self.change_active = false;
        self.show_config_menu = false;

        #[cfg(debug_assertions)]
        {
            self.deattach = false;
        }
    }

    pub fn sanitize(&mut self) {
        // Clamp distance to reasonable values
        if self.distance < 1.0 {
            self.distance = 1.0;
        }
        if self.distance > 50.0 {
            self.distance = 50.0;
        }
    }
    
    // Mouse button handling methods
    pub fn set_mouse_button(&mut self, button: u32, pressed: bool) {
        self.mouse_buttons.insert(button, pressed);
    }
    
    pub fn is_mouse_button_pressed(&self, button: u32) -> bool {
        self.mouse_buttons.get(&button).copied().unwrap_or(false)
    }
    
    pub fn get_gamepad_buttons(&self) -> u16 {
        let mut gamepad_buttons = 0u16;

        // Gamepad buttons are now always active when camera mode is active
        if !self.is_active {
            return gamepad_buttons;
        }

        for (mouse_button, &pressed) in &self.mouse_buttons {
            if pressed {
                if let Some(&gamepad_button) = self.button_mappings.get(mouse_button) {
                    gamepad_buttons |= gamepad_button;
                }
            }
        }

        gamepad_buttons
    }
}

static RESET_MOUSE_FIRST_FRAME: AtomicBool = AtomicBool::new(false);

pub fn prepare_for_camera_activation() {
    // Signal the mouse handler to recenter and skip one frame right after activation
    RESET_MOUSE_FIRST_FRAME.store(true, Ordering::SeqCst);
}

pub fn handle_mouse_input(input: &mut MouseInput) {
    // Handle F3 toggle - exclusive key for camera mode (use debounced detection)
    if check_hotkey_press_debounced(winuser::VK_F3, 300) {
        input.change_active = true;
        info!("[INPUT] F3 pressed - Toggling camera mode");
    }

    // Handle F4 key - show configuration menu (use debounced detection)
    if check_hotkey_press_debounced(winuser::VK_F4, 300) {
        input.show_config_menu = true;
        info!("[INPUT] F4 pressed - Opening configuration menu");
    }


    // Handle HOME key - exit mod (use debounced detection with longer timeout)
    if check_hotkey_press_debounced(winuser::VK_HOME, 500) {
        unsafe {
            crate::g_mod_should_exit = true;
            info!("[INPUT] HOME pressed - Exiting mod");
        }
    }

    unsafe {
        // OPTIMIZED GetCursorPos approach - center within Cemu window
        static mut WINDOW_CENTER_X: i32 = 960;  // Default center
        static mut WINDOW_CENTER_Y: i32 = 540;  // Default center  
        static mut FIRST_FRAME: bool = true;
        static mut LAST_WINDOW_CHECK: Option<std::time::Instant> = None;
        static mut CURSOR_CONTROL_SETUP: bool = false;
        static mut LAST_FOCUS_STATE: bool = true;
        static mut LAST_ACTIVE_STATE: bool = false;
        
        // Handle camera active/inactive state changes
        if input.is_active != LAST_ACTIVE_STATE {
            LAST_ACTIVE_STATE = input.is_active;
            if !input.is_active {
                // Camera became inactive - always restore cursor and cleanup
                set_cursor_hidden(false);
                cleanup_cursor_control();
                winuser::ClipCursor(std::ptr::null());
                CURSOR_CONTROL_SETUP = false;
                info!("[INPUT] Camera deactivated - cursor restored");
                return;
            }
        } else if !input.is_active {
            // Camera is inactive and state hasn't changed - just return
            return;
        }
        
        // Check if Cemu window is currently focused
        let cemu_focused = is_cemu_focused();
        
        // Handle focus state changes
        if cemu_focused != LAST_FOCUS_STATE {
            LAST_FOCUS_STATE = cemu_focused;
            if cemu_focused {
                info!("[INPUT] Cemu gained focus - enabling mouse lock");
                // Re-enter first frame mode to recenter cursor smoothly
                FIRST_FRAME = true;
            } else {
                info!("[INPUT] Cemu lost focus - disabling mouse lock");
                // Restore cursor when focus is lost
                set_cursor_hidden(false);
                // Stop any cursor confinement
                winuser::ClipCursor(std::ptr::null());
            }
        }
        
        // If Cemu is not focused, allow free cursor movement but still process other inputs
        if !cemu_focused {
            // Process non-mouse inputs (keyboard shortcuts, etc.) but don't lock mouse
            return;
        }

        // Update window center periodically (every 500ms) or on first frame
        let should_update_window = FIRST_FRAME || 
            LAST_WINDOW_CHECK.map_or(true, |t| t.elapsed() > std::time::Duration::from_millis(500));
        
        if should_update_window {
            // Try to find Cemu window
            let cemu_window = winuser::FindWindowA(
                std::ptr::null(), 
                std::ffi::CString::new("Cemu").unwrap_or_else(|_| std::ffi::CString::new("").unwrap()).as_ptr()
            );
            
            // If we can't find by title, get the foreground window (likely Cemu if mod is active)
            let target_window = if cemu_window != std::ptr::null_mut() {
                cemu_window
            } else {
                winuser::GetForegroundWindow()
            };
            
            if target_window != std::ptr::null_mut() {
                let mut window_rect: winapi::shared::windef::RECT = std::mem::zeroed();
                if winuser::GetClientRect(target_window, &mut window_rect) != 0 {
                    // Get window position in screen coordinates
                    let mut top_left = POINT { x: 0, y: 0 };
                    if winuser::ClientToScreen(target_window, &mut top_left) != 0 {
                        // Calculate center of the client area
                        let window_width = window_rect.right - window_rect.left;
                        let window_height = window_rect.bottom - window_rect.top;
                        WINDOW_CENTER_X = top_left.x + window_width / 2;
                        WINDOW_CENTER_Y = top_left.y + window_height / 2;
                    }
                }
            } else {
                // Fallback to screen center if no window found
                let screen_width = winuser::GetSystemMetrics(winuser::SM_CXSCREEN);
                let screen_height = winuser::GetSystemMetrics(winuser::SM_CYSCREEN);
                WINDOW_CENTER_X = screen_width / 2;
                WINDOW_CENTER_Y = screen_height / 2;
            }
            
            LAST_WINDOW_CHECK = Some(std::time::Instant::now());
        }

        // If activation requested a recenter, treat next frame as first frame
        if RESET_MOUSE_FIRST_FRAME.swap(false, Ordering::SeqCst) {
            FIRST_FRAME = true;
            MOVEMENT_ACCUMULATOR_X = 0.0;
            MOVEMENT_ACCUMULATOR_Y = 0.0;
            LAST_MOUSE_DELTA_X = 0;
            LAST_MOUSE_DELTA_Y = 0;
            LAST_MOVEMENT_TIME = None;
        }

        // Set up cursor control system if not already done
        if cemu_focused && !CURSOR_CONTROL_SETUP {
            if setup_cursor_control() {
                CURSOR_CONTROL_SETUP = true;
                info!("[INPUT] Cursor control system initialized");
            } else {
                info!("[INPUT] Failed to initialize cursor control system, falling back to ShowCursor");
            }
        }
        
        if FIRST_FRAME {
            FIRST_FRAME = false;
            // Hide cursor and center it immediately (only when Cemu is focused)
            if cemu_focused {
                if CURSOR_CONTROL_SETUP {
                    set_cursor_hidden(true);
                } else {
                    // Fallback to direct ShowCursor if window procedure hook failed
                    winuser::ShowCursor(0);
                }
                winuser::SetCursorPos(WINDOW_CENTER_X, WINDOW_CENTER_Y);
                
                // Optionally confine cursor to window if enabled in config
                let config = get_global_config();
                if config.confine_cursor_to_window {
                    // Get Cemu window bounds for cursor confinement
                    let cemu_window = winuser::FindWindowA(
                        std::ptr::null(), 
                        std::ffi::CString::new("Cemu").unwrap_or_else(|_| std::ffi::CString::new("").unwrap()).as_ptr()
                    );
                    
                    if cemu_window != std::ptr::null_mut() {
                        let mut window_rect: winapi::shared::windef::RECT = std::mem::zeroed();
                        if winuser::GetClientRect(cemu_window, &mut window_rect) != 0 {
                            // Convert client rect to screen coordinates
                            let mut top_left = POINT { x: window_rect.left, y: window_rect.top };
                            let mut bottom_right = POINT { x: window_rect.right, y: window_rect.bottom };
                            
                            if winuser::ClientToScreen(cemu_window, &mut top_left) != 0 &&
                               winuser::ClientToScreen(cemu_window, &mut bottom_right) != 0 {
                                let clip_rect = winapi::shared::windef::RECT {
                                    left: top_left.x,
                                    top: top_left.y,
                                    right: bottom_right.x,
                                    bottom: bottom_right.y,
                                };
                                winuser::ClipCursor(&clip_rect);
                                info!("[INPUT] Cursor confined to Cemu window");
                            }
                        }
                    }
                }
            }
            return; // Skip first frame to let cursor settle
        }

        // Get current mouse position
        let mut cursor_pos = POINT { x: 0, y: 0 };
        winuser::GetCursorPos(&mut cursor_pos);

        // Calculate movement delta from window center
        let delta_x = cursor_pos.x - WINDOW_CENTER_X;
        let delta_y = cursor_pos.y - WINDOW_CENTER_Y;

        // Check if magnesis is active - if so, disable camera mouse control but allow keyboard emulation
        let magnesis_is_active = crate::should_magnesis_control_mouse();
        
        // Check if PhoneCamera is active - wheel input is allowed during PhoneCamera
        let phonecamera_active = unsafe { crate::g_last_phonecamera_open_state };
        
        // Always calculate camera controls but only apply when magnesis is NOT active
        // Map 0-100 user scale so that 50.0 equals legacy default 0.003
        let cfg = get_global_config();
        let pct = cfg.camera_sensitivity_pct.clamp(0.0, 100.0);
        let camera_sensitivity = (pct / 50.0) * 0.003; // 0 => 0x, 50 => 1x, 100 => 2x legacy speed
        
        // Always process mouse movement for potential use
        let camera_orbit_x = delta_x as f32 * camera_sensitivity;
        let camera_orbit_y = delta_y as f32 * camera_sensitivity;
        
        if !magnesis_is_active {
            // Normal mode - apply camera controls (wheel handled in main loop via check_mouse_wheel)
            input.orbit_x = camera_orbit_x;
            input.orbit_y = camera_orbit_y;
            input.zoom = 0.0; // leave wheel delta to be processed centrally
        } else {
            // Experimental magnesis always ON: pass mouse deltas to magnesis module
            input.orbit_x = camera_orbit_x;
            input.orbit_y = camera_orbit_y;
            input.zoom = 0.0; // camera zoom disabled; wheel handled by experimental module
        }
        
        // Accumulate movement for persistent axis key handling

        // Accumulate movement for persistent axis key handling
        const AXIS_SENSITIVITY_X: f32 = 5.0; // X-axis sensitivity multiplier for right stick (increased for more horizontal responsiveness)
        const AXIS_SENSITIVITY_Y: f32 = 1.5; // Y-axis sensitivity multiplier for right stick (reduced for less vertical movement)
        const MOVEMENT_DECAY: f32 = 0.85; // How much movement decays each frame (85% retained)
        const MOVEMENT_THRESHOLD: f32 = 0.5; // Minimum accumulated movement to trigger keys
        
        let now = std::time::Instant::now();
        
        // Add current frame's movement to accumulator
        MOVEMENT_ACCUMULATOR_X += delta_x as f32 * AXIS_SENSITIVITY_X;
        MOVEMENT_ACCUMULATOR_Y += delta_y as f32 * AXIS_SENSITIVITY_Y;
        
        // Decay accumulated movement over time to prevent infinite holding
        if let Some(last_time) = LAST_MOVEMENT_TIME {
            let dt = now.duration_since(last_time).as_secs_f32();
            let decay_factor = MOVEMENT_DECAY.powf(dt * 60.0); // 60fps reference
            MOVEMENT_ACCUMULATOR_X *= decay_factor;
            MOVEMENT_ACCUMULATOR_Y *= decay_factor;
        }
        LAST_MOVEMENT_TIME = Some(now);
        
        // Use accumulated movement for axis keys (this persists across frames)
        LAST_MOUSE_DELTA_X = MOVEMENT_ACCUMULATOR_X as i32;
        LAST_MOUSE_DELTA_Y = MOVEMENT_ACCUMULATOR_Y as i32;

        // Wheel input is handled above - forwarded in all modes (PhoneCamera consumes it separately)
        
        // Mouse input to magnesis is no longer needed - game handles it directly when active
        
        // Middle mouse button to reset camera/photo zoom (edge-triggered; no repeat while held)
        if check_hotkey_press_debounced(winuser::VK_MBUTTON, 200) {
            input.reset_camera = true;
        }
        
        // Wheel zoom is allowed during PhoneCamera mode (used to control photo FOV)

        // Reset mouse to window center position for next frame (only when focused)
        if cemu_focused {
            winuser::SetCursorPos(WINDOW_CENTER_X, WINDOW_CENTER_Y);
        }
    }
}

pub fn cleanup_mouse_input() {
    unsafe {
        set_cursor_hidden(false); // Show cursor when done
        cleanup_cursor_control(); // Clean up window procedure hook
        winuser::ClipCursor(std::ptr::null()); // Remove cursor confinement when done
    }
}

pub fn error_message(message: &str) {
    let title = CString::new("Mouse Camera Error").unwrap();
    let message = CString::new(message).unwrap();

    unsafe {
        winuser::MessageBoxA(
            std::ptr::null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            0x10,
        );
    }
}

// Global state for gamepad mode and configuration
static mut GAMEPAD_MODE_ACTIVE: bool = false;
static mut MOUSE_BUTTON_STATES: [bool; 5] = [false; 5]; // L, R, M, X1, X2
static mut GLOBAL_CONFIG: Option<Config> = None;

// Movement accumulation for axis key emulation
static mut MOVEMENT_ACCUMULATOR_X: f32 = 0.0;
static mut MOVEMENT_ACCUMULATOR_Y: f32 = 0.0;
static mut LAST_MOVEMENT_TIME: Option<std::time::Instant> = None;

// Shared mouse delta for axis key emulation (pixels per tick)
static mut LAST_MOUSE_DELTA_X: i32 = 0;
static mut LAST_MOUSE_DELTA_Y: i32 = 0;

pub fn set_global_gamepad_state(active: bool) {
    unsafe {
        GAMEPAD_MODE_ACTIVE = active;
    }
}

pub fn set_global_mouse_button(button_index: usize, pressed: bool) {
    unsafe {
        if button_index < MOUSE_BUTTON_STATES.len() {
            MOUSE_BUTTON_STATES[button_index] = pressed;
        }
    }
}

// VPAD detour removed - redundant with keyboard input system

// Get XInput button flags from mouse state for dummy_xinput injection
pub fn get_xinput_mouse_buttons() -> u16 {
    unsafe {
        static mut LAST_XINPUT: u16 = 0;
        // 🚨 CRITICAL FIX - Check camera active state for true dormancy
        if g_camera_active == 0 || !GAMEPAD_MODE_ACTIVE {
            if LAST_XINPUT != 0 {
                LAST_XINPUT = 0;
            }
            return 0;
        }

        let mut buttons: u16 = 0;
        // Left click -> Y
        if check_key_press(winuser::VK_LBUTTON) { buttons |= xinput::XINPUT_GAMEPAD_Y; }
        // Right click -> Right shoulder
        if check_key_press(winuser::VK_RBUTTON) { buttons |= xinput::XINPUT_GAMEPAD_RIGHT_SHOULDER; }
        // XBUTTON1 -> DPAD_LEFT, XBUTTON2 -> DPAD_RIGHT
        if check_key_press(winuser::VK_XBUTTON1) { buttons |= xinput::XINPUT_GAMEPAD_DPAD_LEFT; }
        if check_key_press(winuser::VK_XBUTTON2) { buttons |= xinput::XINPUT_GAMEPAD_DPAD_RIGHT; }

        if buttons != LAST_XINPUT {
            if buttons != 0 {
                // logging disabled
            }
            LAST_XINPUT = buttons;
        }

        buttons
    }
}

// WPAD detour removed - redundant with keyboard input system

#[no_mangle]
pub unsafe extern "system" fn dummy_xinput(a: u32, b: &mut xinput::XINPUT_STATE) -> u32 {
    // No XInput synthesis; rely on keyboard emulation only.
    xinput::XInputGetState(a, b)
}
