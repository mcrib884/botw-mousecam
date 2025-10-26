use crate::config::{Config, vk_to_name};
use crate::i18n::{self, Language, strings, language_name};
use std::io::{self, Write};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

use std::time::Duration;
use std::thread;

pub struct ConfigMenu {
    pub config: Config,
    pub config_path: String,
}

impl ConfigMenu {
    pub fn new(config: Config, config_path: String) -> Self {
        Self { config, config_path }
    }

    fn t(&self) -> &'static i18n::Strings {
        strings(self.config.language)
    }

fn auto_save(&self) -> Result<(), std::io::Error> {
        if let Err(e) = self.config.save(&self.config_path) {
            self.write_colored(Color::Red, &format!("✗ Auto-save failed: {}\n", e))?;
        } else {
            self.write_colored(Color::Green, &format!("✓ Configuration auto-saved. experimental_magnesis_fps_camera: {}\n", self.config.experimental_magnesis_fps_camera))?;
        }
        Ok(())
    }
    
    fn write_colored(&self, color: Color, text: &str) -> io::Result<()> {
        let mut stdout = StandardStream::stdout(ColorChoice::Always);
        stdout.set_color(ColorSpec::new().set_fg(Some(color)))?;
        write!(&mut stdout, "{}", text)?;
        stdout.reset()?;
        Ok(())
    }
    
fn write_header(&self) -> io::Result<()> {
        let t = self.t();
        self.write_colored(Color::Cyan, "\n╔══════════════════════════════════════════════════════════════╗\n")?;
        self.write_colored(Color::Cyan, &format!("║{:^62}║\n", t.header_title))?;
        self.write_colored(Color::Cyan, "╚══════════════════════════════════════════════════════════════╝\n\n")?;
        self.write_colored(Color::Yellow, &format!("experimental_magnesis_fps_camera: {}\n", self.config.experimental_magnesis_fps_camera))?;
        Ok(())
    }
    
    pub fn show_main_menu(&mut self) -> io::Result<bool> {
        loop {
            self.write_header()?;
            
// Current configuration
            let t = self.t();
            self.write_colored(Color::Yellow, &format!("{}\n", t.current_key_bindings))?;
            println!("  1. {:<11} → {} ({})", t.label_left_click, vk_to_name(self.config.mouse_buttons.left_click), self.get_action_name("left"));
            println!("  2. {:<11} → {} ({})", t.label_right_click, vk_to_name(self.config.mouse_buttons.right_click), self.get_action_name("right"));
            println!("  3. {:<11} → {} ({})", t.label_mouse4, vk_to_name(self.config.mouse_buttons.mouse4), self.get_action_name("mouse4"));
            println!("  4. {:<11} → {} ({})", t.label_mouse5, vk_to_name(self.config.mouse_buttons.mouse5), self.get_action_name("mouse5"));
            println!();
            
            self.write_colored(Color::Yellow, &format!("{}\n", t.axis_key_bindings))?;
            println!("  5. {:<11} → {}", t.label_axis_left, vk_to_name(self.config.mouse_axes.left));
            println!("  6. {:<11} → {}", t.label_axis_right, vk_to_name(self.config.mouse_axes.right));
            println!("  7. {:<11} → {}", t.label_axis_up, vk_to_name(self.config.mouse_axes.up));
            println!("  8. {:<11} → {}", t.label_axis_down, vk_to_name(self.config.mouse_axes.down));
            // Sprint binding (bind the same key you use for sprint in Cemu)
            println!("  9. {:<11} → {}", "Sprint", if self.config.sprint_key == 0 { String::from("(not set)") } else { vk_to_name(self.config.sprint_key) });
            println!();
            
            // Focus setting removed; focus is always required now.
            
            // Sensitivities section
            self.write_colored(Color::Magenta, &format!("{}\n", t.sensitivities_title))?;
            println!("  • {}: {:.0} (0-100; 50 = default)", t.camera_sensitivity_label, self.config.camera_sensitivity_pct);
            println!("  • {}: {:.2}", t.magnesis_sensitivity_label, self.config.magnesis_sensitivity);
            println!();
            
            // Menu options
            self.write_colored(Color::Green, &format!("{}\n", t.options_title))?;
            println!("  {}", t.opt_change_mouse_button);
            println!("  {}", t.opt_change_axis_binding);
            println!("  {}", t.opt_change_magnesis_sens);
            println!("  {}", t.opt_change_camera_sens);
            // Sprint toggle binding (English label for now)
            let sprint_status = if self.config.sprint_toggle_enabled { t.on_str } else { t.off_str };
            let fps_status = if self.config.experimental_magnesis_fps_camera { t.on_str } else { t.off_str };
            println!("  [9]   Bind sprint key (tap while walking to toggle; auto-off on stop)");
            println!("  [G]   Sprint toggle feature: {}", sprint_status);
            println!("  [F]   Magnesis FPS camera (experimental): {}", fps_status);
            println!("  {}", t.opt_reset_defaults);
            println!("  {}", t.opt_continue_to_game);
            println!("  {} ({})", t.opt_change_language, language_name(self.config.language));
            println!();
            
            self.write_colored(Color::White, t.prompt_choice)?;
            io::stdout().flush()?;
            
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim().to_uppercase();
            
match input.as_str() {
                "1" => self.change_key_binding("left")?,
                "2" => self.change_key_binding("right")?,
                "3" => self.change_key_binding("mouse4")?,
                "4" => self.change_key_binding("mouse5")?,
                "5" => self.change_key_binding("axis_left")?,
                "6" => self.change_key_binding("axis_right")?,
                "7" => self.change_key_binding("axis_up")?,
                "8" => self.change_key_binding("axis_down")?,
                "9" => {
                    self.change_sprint_key()?;
                    self.auto_save()?;
                },
                "G" => {
                    self.config.sprint_toggle_enabled = !self.config.sprint_toggle_enabled;
                    let status = if self.config.sprint_toggle_enabled { "ON" } else { "OFF" };
                    self.write_colored(Color::Green, &format!("✓ Sprint toggle feature: {}\n", status))?;
                    // If disabling, ensure any held sprint key is released
                    if !self.config.sprint_toggle_enabled && self.config.sprint_key != 0 {
                        crate::utils::send_key(self.config.sprint_key, false);
                    }
                    self.auto_save()?;
                },
                "F" => {
                    let t = self.t();
                    self.config.experimental_magnesis_fps_camera = !self.config.experimental_magnesis_fps_camera;
                    self.write_colored(
                        Color::Green,
                        &format!(
                            "✓ Magnesis FPS camera (experimental): {}\n",
                            if self.config.experimental_magnesis_fps_camera { t.on_str } else { t.off_str }
                        ),
                    )?;
                    self.auto_save()?;
                },
                "L" => {
                    self.change_language()?;
                    self.auto_save()?;
                }
                "S" => {
                    self.change_magnesis_sensitivity()?;
                    self.auto_save()?;
                }
                "V" => {
                    self.change_camera_sensitivity()?;
                }
                "D" => {
                    self.config = Config::default();
let t = self.t();
                    self.write_colored(Color::Green, &format!("{}\n", t.opt_reset_defaults))?;
                    self.auto_save()?;
                }
                "C" => {
                    return Ok(true); // Continue to game
                }
                "" => return Ok(true), // Enter = continue
                _ => {
let t = self.t();
                    self.write_colored(Color::Red, &format!("{}\n", t.invalid_option))?;
                }
            }
            
            if !["C", ""].contains(&input.as_str()) {
let t = self.t();
                self.write_colored(Color::White, t.press_enter_to_continue)?;
                io::stdout().flush()?;
                let mut _dummy = String::new();
                io::stdin().read_line(&mut _dummy)?;
            }
        }
    }
    
    fn change_key_binding(&mut self, button: &str) -> io::Result<()> {
        let current_key = match button {
            "left" => self.config.mouse_buttons.left_click,
            "right" => self.config.mouse_buttons.right_click,
            "mouse4" => self.config.mouse_buttons.mouse4,
            "mouse5" => self.config.mouse_buttons.mouse5,
            "axis_left" => self.config.mouse_axes.left,
            "axis_right" => self.config.mouse_axes.right,
            "axis_up" => self.config.mouse_axes.up,
            "axis_down" => self.config.mouse_axes.down,
            _ => return Ok(()),
        };
        
let action_name = self.get_action_name(button);
        let t = self.t();
        
        self.write_colored(Color::Cyan, &format!("{}\n", format!("{} {} {}", t.configuring_label_fmt, button, action_name)))?;
        self.write_colored(Color::Yellow, &format!("{}\n\n", format!("{} {}", t.current_key_label_fmt, vk_to_name(current_key))))?;
        
        self.write_colored(Color::White, &format!("{}\n", t.press_new_key))?;
        self.write_colored(Color::Cyan, &format!("{}\n", t.clearing_prev_inputs))?;
        
        // Listen for key press
        if let Some(vk_code) = self.listen_for_key_press() {
            match button {
                "left" => self.config.mouse_buttons.left_click = vk_code,
                "right" => self.config.mouse_buttons.right_click = vk_code,
                "mouse4" => self.config.mouse_buttons.mouse4 = vk_code,
                "mouse5" => self.config.mouse_buttons.mouse5 = vk_code,
                "axis_left" => self.config.mouse_axes.left = vk_code,
                "axis_right" => self.config.mouse_axes.right = vk_code,
                "axis_up" => self.config.mouse_axes.up = vk_code,
                "axis_down" => self.config.mouse_axes.down = vk_code,
                _ => {}
            }
let t = self.t();
            self.write_colored(Color::Green, &format!("{}\n", format!("{} {} {}", t.mapped_success_fmt, button, vk_to_name(vk_code))))?;
            self.auto_save()?;
        } else {
let t = self.t();
            self.write_colored(Color::Yellow, &format!("{}\n", t.no_key_pressed_keep))?;
        }
        
        Ok(())
    }
    
    fn listen_for_sprint_key_press(&self) -> Option<u8> {
        use winapi::um::winuser;

        fn is_valid_sprint_binding_vk(vk: u8) -> bool {
            // Allow A-Z, 0-9, F1-F24, Arrow keys, AND modifier keys for sprint binding
            match vk {
                0x30..=0x39 => true,            // 0-9 (numeric row)
                0x60..=0x69 => true,            // Numpad 0-9
                0x41..=0x5A => true,            // A-Z
                0x70..=0x87 => true,            // F1-F24
                x if x == winuser::VK_LEFT as u8
                  || x == winuser::VK_RIGHT as u8
                  || x == winuser::VK_UP as u8
                  || x == winuser::VK_DOWN as u8 => true,
                // ALLOW modifier keys for sprint binding
                x if x == winuser::VK_SHIFT as u8
                  || x == winuser::VK_LSHIFT as u8
                  || x == winuser::VK_RSHIFT as u8
                  || x == winuser::VK_CONTROL as u8
                  || x == winuser::VK_LCONTROL as u8
                  || x == winuser::VK_RCONTROL as u8
                  || x == winuser::VK_MENU as u8
                  || x == winuser::VK_LMENU as u8
                  || x == winuser::VK_RMENU as u8 => true,
                // Allow commonly used keys for sprint
                x if x == winuser::VK_SPACE as u8
                  || x == winuser::VK_TAB as u8 => true,
                _ => false,
            }
        }
        
        // Wait for any current key presses to clear (including Enter from menu selection)
        thread::sleep(Duration::from_millis(500));
        
        // Clear any lingering key states
        unsafe {
            for vk in 0..=255u8 {
                winuser::GetAsyncKeyState(vk as i32);
            }
        }
        
        println!("Ready! Press the key you want to use for sprint toggle (including Shift, Ctrl, Alt)...");
        
        let mut last_key_state = [false; 256];
        
        // Listen for key presses for up to 10 seconds
        let start_time = std::time::Instant::now();
        let timeout = Duration::from_secs(10);
        
        while start_time.elapsed() < timeout {
            unsafe {
                for vk in 0..=255u8 {
                    let current_state = (winuser::GetAsyncKeyState(vk as i32) as u32) & 0x8000 != 0;
                    
                    // Detect key press (transition from not pressed to pressed)
                    if current_state && !last_key_state[vk as usize] {
                        // Filter out disallowed keys: mouse buttons, system/media keys, Enter/Escape/Space, Win keys
                        // BUT ALLOW modifier keys for sprint
                        let is_mouse_btn = vk == winuser::VK_LBUTTON as u8
                            || vk == winuser::VK_RBUTTON as u8
                            || vk == winuser::VK_MBUTTON as u8
                            || vk == winuser::VK_XBUTTON1 as u8
                            || vk == winuser::VK_XBUTTON2 as u8;
                        let is_win = vk == winuser::VK_LWIN as u8 || vk == winuser::VK_RWIN as u8 || vk == winuser::VK_APPS as u8;
                        let is_nav_cancel = vk == winuser::VK_RETURN as u8 || vk == winuser::VK_ESCAPE as u8;
                        // Note: Space and Tab are now allowed for sprint binding
                        // Media/system keys (volume/media/app launch)
                        let is_media = matches!(vk,
                            0xAD | 0xAE | 0xAF | // VOLUME MUTE/DOWN/UP
                            0xB0 | 0xB1 | 0xB2 | 0xB3 | // MEDIA NEXT/PREV/STOP/PLAY-PAUSE
                            0xB4 | 0xB5 | 0xB6 | 0xB7    // LAUNCH MAIL/MEDIA/APP1/APP2
                        );

                        if !is_mouse_btn && !is_win && !is_nav_cancel && !is_media && is_valid_sprint_binding_vk(vk) {
                            return Some(vk);
                        }
                    }
                    
                    last_key_state[vk as usize] = current_state;
                }
            }
            
            // Check for ESC key to cancel
            unsafe {
                if (winuser::GetAsyncKeyState(winuser::VK_ESCAPE as i32) as u32) & 0x8000 != 0 {
                    return None;
                }
            }
            
            thread::sleep(Duration::from_millis(10));
        }
        
        None // Timeout
    }

    fn listen_for_key_press(&self) -> Option<u8> {
        use winapi::um::winuser;

        fn is_valid_binding_vk(vk: u8) -> bool {
            // Allow A-Z, 0-9, F1-F24, and Arrow keys. Disallow modifiers, system/media/mouse keys, Enter/Escape/Space, Win keys, etc.
            match vk {
                0x30..=0x39 => true,            // 0-9 (numeric row)
                0x60..=0x69 => true,            // Numpad 0-9
                0x41..=0x5A => true,            // A-Z
                0x70..=0x87 => true,            // F1-F24
                x if x == winuser::VK_LEFT as u8
                  || x == winuser::VK_RIGHT as u8
                  || x == winuser::VK_UP as u8
                  || x == winuser::VK_DOWN as u8 => true,
                _ => false,
            }
        }
        
        // Wait for any current key presses to clear (including Enter from menu selection)
        thread::sleep(Duration::from_millis(500));
        
        // Clear any lingering key states
        unsafe {
            for vk in 0..=255u8 {
                winuser::GetAsyncKeyState(vk as i32);
            }
        }
        
let t = self.t();
        println!("{}", t.ready_press_key_now);
        
        let mut last_key_state = [false; 256];
        
        // Listen for key presses for up to 10 seconds
        let start_time = std::time::Instant::now();
        let timeout = Duration::from_secs(10);
        
        while start_time.elapsed() < timeout {
            unsafe {
                for vk in 0..=255u8 {
                    let current_state = (winuser::GetAsyncKeyState(vk as i32) as u32) & 0x8000 != 0;
                    
                    // Detect key press (transition from not pressed to pressed)
                    if current_state && !last_key_state[vk as usize] {
                        // Filter out disallowed keys: mouse buttons, modifiers, system/media keys, Enter/Escape/Space, Win keys
                        let is_mouse_btn = vk == winuser::VK_LBUTTON as u8
                            || vk == winuser::VK_RBUTTON as u8
                            || vk == winuser::VK_MBUTTON as u8
                            || vk == winuser::VK_XBUTTON1 as u8
                            || vk == winuser::VK_XBUTTON2 as u8;
                        let is_modifier = vk == winuser::VK_SHIFT as u8
                            || vk == winuser::VK_CONTROL as u8
                            || vk == winuser::VK_MENU as u8;
                        let is_win = vk == winuser::VK_LWIN as u8 || vk == winuser::VK_RWIN as u8 || vk == winuser::VK_APPS as u8;
                        let is_nav_cancel = vk == winuser::VK_RETURN as u8 || vk == winuser::VK_ESCAPE as u8 || vk == winuser::VK_SPACE as u8;
                        // Media/system keys (volume/media/app launch)
                        let is_media = matches!(vk,
                            0xAD | 0xAE | 0xAF | // VOLUME MUTE/DOWN/UP
                            0xB0 | 0xB1 | 0xB2 | 0xB3 | // MEDIA NEXT/PREV/STOP/PLAY-PAUSE
                            0xB4 | 0xB5 | 0xB6 | 0xB7    // LAUNCH MAIL/MEDIA/APP1/APP2
                        );

                        if !is_mouse_btn && !is_modifier && !is_win && !is_nav_cancel && !is_media && is_valid_binding_vk(vk) {
                            return Some(vk);
                        }
                    }
                    
                    last_key_state[vk as usize] = current_state;
                }
            }
            
            // Check for ESC key to cancel
            unsafe {
                if (winuser::GetAsyncKeyState(winuser::VK_ESCAPE as i32) as u32) & 0x8000 != 0 {
                    return None;
                }
            }
            
            thread::sleep(Duration::from_millis(10));
        }
        
        None // Timeout
    }
    
fn get_action_name(&self, button: &str) -> &'static str {
        let t = self.t();
        match button {
            "left" => t.action_y_button,
            "right" => t.action_zr_shoulder,
            "mouse4" => t.action_dpad_left,
            "mouse5" => t.action_dpad_right,
            "axis_left" => t.label_axis_left,
            "axis_right" => t.label_axis_right,
            "axis_up" => t.label_axis_up,
            "axis_down" => t.label_axis_down,
            _ => "Unknown"
        }
    }
    
fn change_sprint_key(&mut self) -> io::Result<()> {
        // Configure which VK we should hold for sprint (bind the same key you use in Cemu)
        let current = self.config.sprint_key;
        let current_name = if current == 0 { String::from("(not set)") } else { vk_to_name(current) };
        self.write_colored(Color::Cyan, "\nConfigure Sprint Key (bind the key you use for sprint in Cemu)\n")?;
        self.write_colored(Color::Yellow, &format!("Current key: {}\n", current_name))?;
        let t = self.t();
        self.write_colored(Color::White, &format!("{}\n", t.press_new_key))?;
        self.write_colored(Color::Cyan, &format!("{}\n", t.clearing_prev_inputs))?;
        if let Some(vk_code) = self.listen_for_sprint_key_press() {
            self.config.sprint_key = vk_code;
            self.write_colored(Color::Green, &format!("✓ Sprint mapped to {}\n", vk_to_name(vk_code)))?;
        } else {
            self.write_colored(Color::Yellow, "No key pressed, keeping current sprint key.\n")?;
        }
        Ok(())
    }

fn change_magnesis_sensitivity(&mut self) -> io::Result<()> {
        let t = self.t();
        self.write_colored(Color::Cyan, &format!("{}\n", t.configure_magnesis_title))?;
        self.write_colored(Color::Yellow, &format!("{}\n", format!("{} {}", t.current_sensitivity_label_fmt, self.config.magnesis_sensitivity)))?;
        self.write_colored(Color::White, t.enter_new_magnesis_sens)?;
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();
        
        if input.is_empty() {
let t = self.t();
            self.write_colored(Color::Yellow, &format!("{}\n", t.keeping_current_sens))?;
            return Ok(());
        }
        
        match input.parse::<f32>() {
            Ok(value) if value >= 0.1 && value <= 5.0 => {
                self.config.magnesis_sensitivity = value;
self.write_colored(Color::Green, &format!("✓ {} {:.2}\n", t.magnesis_sensitivity_label, value))?;
                self.auto_save()?;
            }
            _ => {
let t = self.t();
                self.write_colored(Color::Red, &format!("{}\n", t.invalid_magnesis_range))?;
            }
        }
        
        Ok(())
    }

fn change_camera_sensitivity(&mut self) -> io::Result<()> {
        let t = self.t();
        self.write_colored(Color::Cyan, &format!("{}\n", t.configure_camera_title))?;
        self.write_colored(Color::Yellow, &format!("{}\n", format!("{} {}", t.current_camera_sens_label_fmt, self.config.camera_sensitivity_pct)))?;
        self.write_colored(Color::White, t.enter_new_camera_sens)?;
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();
        
        if input.is_empty() {
let t = self.t();
            self.write_colored(Color::Yellow, &format!("{}\n", t.keeping_current_camera_sens))?;
            return Ok(());
        }
        
        match input.parse::<f32>() {
            Ok(mut value) => {
                if value.is_finite() {
                    if value < 0.0 { value = 0.0; }
                    if value > 100.0 { value = 100.0; }
                    self.config.camera_sensitivity_pct = value;
let t = self.t();
                    self.write_colored(Color::Green, &format!("✓ {} {:.0}\n", t.camera_sensitivity_label, value))?;
                    self.auto_save()?;
                } else {
let t = self.t();
                    self.write_colored(Color::Red, &format!("{}\n", t.invalid_camera_value))?;
                }
            }
            _ => {
let t = self.t();
                self.write_colored(Color::Red, &format!("{}\n", t.invalid_camera_value))?;
            }
        }
        
        Ok(())
    }

pub fn show_camera_patch_menu(&mut self) -> io::Result<bool> {
        loop {
            // Clear screen and show header
            print!("\x1B[2J\x1B[1;1H");

            let t = self.t();
            self.write_colored(Color::Cyan, &format!("{}\n", t.camera_patch_settings_title))?;
            self.write_colored(Color::White, &format!("{}\n", t.camera_patch_hint_line1))?;
            self.write_colored(Color::Yellow, &format!("{}\n\n", t.camera_patch_hint_line2))?;

            // Main detours - MOST LIKELY CULPRITS
self.write_colored(Color::Red, &format!("{}\n", t.main_detours_title))?;
            println!("{} {}", t.main_camera_detour_label_fmt, if self.config.camera_patches.camera_detour_enabled { t.on_str } else { t.off_str });
            println!();

            // Input system hooks
            self.write_colored(Color::Magenta, &format!("{}\n", t.input_hooks_title))?;
            println!("{} {}", t.mouse_hook_label_fmt, if self.config.camera_patches.mouse_hook_enabled { t.on_str } else { t.off_str });
            println!();

            // Camera position writers
            self.write_colored(Color::Green, &format!("{}\n", t.cam_pos_focus_writers_title))?;
            println!("{} {}", t.primary_pos_writer_label_fmt, if self.config.camera_patches.camera_pos_writer_1 { t.on_str } else { t.off_str });
            println!("{} {}", t.secondary_pos_writer_label_fmt, if self.config.camera_patches.camera_pos_writer_2 { t.on_str } else { t.off_str });
            println!("{} {}", t.tertiary_pos_writer_label_fmt, if self.config.camera_patches.camera_pos_writer_3 { t.on_str } else { t.off_str });
            println!("{} {}", t.focus_writer_label_1_fmt, if self.config.camera_patches.camera_pos_writer_4 { t.on_str } else { t.off_str });
            println!("{} {}", t.focus_writer_label_2_fmt, if self.config.camera_patches.camera_pos_writer_5 { t.on_str } else { t.off_str });
            println!("{} {}", t.focus_writer_label_3_fmt, if self.config.camera_patches.camera_pos_writer_6 { t.on_str } else { t.off_str });
            println!("{} {}", t.camera_height_writer_label_fmt, if self.config.camera_patches.camera_pos_writer_7 { t.on_str } else { t.off_str });
            println!("{} {}", t.camera_depth_writer_label_fmt, if self.config.camera_patches.camera_pos_writer_8 { t.on_str } else { t.off_str });
            println!("{} {}", t.final_pos_writer_label_fmt, if self.config.camera_patches.camera_pos_writer_9 { t.on_str } else { t.off_str });
            println!();

            // Rotation writers
            self.write_colored(Color::Green, &format!("{}\n", t.rotation_writers_title))?;
            println!("{} {}", t.primary_rotation_writer_label_fmt, if self.config.camera_patches.rotation_writer_1 { t.on_str } else { t.off_str });
            println!("{} {}", t.secondary_rotation_writer_label_fmt, if self.config.camera_patches.rotation_writer_2 { t.on_str } else { t.off_str });
            println!("{} {}", t.tertiary_rotation_writer_label_fmt, if self.config.camera_patches.rotation_writer_3 { t.on_str } else { t.off_str });
            println!();

            // Menu options
            self.write_colored(Color::Yellow, &format!("{}\n", t.cam_patch_options_title))?;
            println!("  {}", t.cam_patch_toggle_main);
            println!("  {}", t.cam_patch_toggle_mouse_hook);
            println!("  {}", t.cam_patch_toggle_pos_writers);
            println!("  {}", t.cam_patch_toggle_rot_writers);
            println!("  {}", t.cam_patch_enable_all);
            println!("  {}", t.cam_patch_disable_all);
            println!("  {}", t.cam_patch_reset_defaults);
            println!("  {}", t.cam_patch_back_to_main);
            println!();

            self.write_colored(Color::White, t.prompt_choice)?;
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim().to_uppercase();

            match input.as_str() {
                "M" => {
                    self.config.camera_patches.camera_detour_enabled = !self.config.camera_patches.camera_detour_enabled;
let t = self.t();
                    self.write_colored(Color::Red, &format!("🚨 Main camera detour: {}\n",
                        if self.config.camera_patches.camera_detour_enabled { "ON" } else { "OFF" }))?;
                    self.auto_save()?;
                }
                "H" => {
                    self.config.camera_patches.mouse_hook_enabled = !self.config.camera_patches.mouse_hook_enabled;
let t = self.t();
                    self.write_colored(Color::Green, &format!("✓ Mouse hook: {}\n",
                        if self.config.camera_patches.mouse_hook_enabled { "ON" } else { "OFF" }))?;
                    self.auto_save()?;
                }
                "1" => {
                    self.config.camera_patches.camera_pos_writer_1 = !self.config.camera_patches.camera_pos_writer_1;
let t = self.t();
                    self.write_colored(Color::Green, &format!("✓ Primary position writer: {}\n",
                        if self.config.camera_patches.camera_pos_writer_1 { "ON" } else { "OFF" }))?;
                    self.auto_save()?;
                }
                "2" => {
                    self.config.camera_patches.camera_pos_writer_2 = !self.config.camera_patches.camera_pos_writer_2;
let t = self.t();
                    self.write_colored(Color::Green, &format!("✓ Secondary position writer: {}\n",
                        if self.config.camera_patches.camera_pos_writer_2 { "ON" } else { "OFF" }))?;
                    self.auto_save()?;
                }
                "3" => {
                    self.config.camera_patches.camera_pos_writer_3 = !self.config.camera_patches.camera_pos_writer_3;
let t = self.t();
                    self.write_colored(Color::Green, &format!("✓ Tertiary position writer: {}\n",
                        if self.config.camera_patches.camera_pos_writer_3 { "ON" } else { "OFF" }))?;
                    self.auto_save()?;
                }
                "4" => {
                    self.config.camera_patches.camera_pos_writer_4 = !self.config.camera_patches.camera_pos_writer_4;
let t = self.t();
                    self.write_colored(Color::Green, &format!("✓ Focus point writer 1: {}\n",
                        if self.config.camera_patches.camera_pos_writer_4 { "ON" } else { "OFF" }))?;
                    self.auto_save()?;
                }
                "5" => {
                    self.config.camera_patches.camera_pos_writer_5 = !self.config.camera_patches.camera_pos_writer_5;
let t = self.t();
                    self.write_colored(Color::Green, &format!("✓ Focus point writer 2: {}\n",
                        if self.config.camera_patches.camera_pos_writer_5 { "ON" } else { "OFF" }))?;
                    self.auto_save()?;
                }
                "6" => {
                    self.config.camera_patches.camera_pos_writer_6 = !self.config.camera_patches.camera_pos_writer_6;
let t = self.t();
                    self.write_colored(Color::Green, &format!("✓ Focus point writer 3: {}\n",
                        if self.config.camera_patches.camera_pos_writer_6 { "ON" } else { "OFF" }))?;
                    self.auto_save()?;
                }
                "7" => {
                    self.config.camera_patches.camera_pos_writer_7 = !self.config.camera_patches.camera_pos_writer_7;
let t = self.t();
                    self.write_colored(Color::Green, &format!("✓ Camera height writer: {}\n",
                        if self.config.camera_patches.camera_pos_writer_7 { "ON" } else { "OFF" }))?;
                    self.auto_save()?;
                }
                "8" => {
                    self.config.camera_patches.camera_pos_writer_8 = !self.config.camera_patches.camera_pos_writer_8;
let t = self.t();
                    self.write_colored(Color::Green, &format!("✓ Camera depth writer: {}\n",
                        if self.config.camera_patches.camera_pos_writer_8 { "ON" } else { "OFF" }))?;
                    self.auto_save()?;
                }
                "9" => {
                    self.config.camera_patches.camera_pos_writer_9 = !self.config.camera_patches.camera_pos_writer_9;
let t = self.t();
                    self.write_colored(Color::Green, &format!("✓ Final position writer: {}\n",
                        if self.config.camera_patches.camera_pos_writer_9 { "ON" } else { "OFF" }))?;
                    self.auto_save()?;
                }
                "A" => {
                    self.config.camera_patches.rotation_writer_1 = !self.config.camera_patches.rotation_writer_1;
let t = self.t();
                    self.write_colored(Color::Green, &format!("✓ Primary rotation writer: {}\n",
                        if self.config.camera_patches.rotation_writer_1 { "ON" } else { "OFF" }))?;
                    self.auto_save()?;
                }
                "S" => {
                    self.config.camera_patches.rotation_writer_2 = !self.config.camera_patches.rotation_writer_2;
let t = self.t();
                    self.write_colored(Color::Green, &format!("✓ Secondary rotation writer: {}\n",
                        if self.config.camera_patches.rotation_writer_2 { "ON" } else { "OFF" }))?;
                    self.auto_save()?;
                }
                "T" => {
                    self.config.camera_patches.rotation_writer_3 = !self.config.camera_patches.rotation_writer_3;
let t = self.t();
                    self.write_colored(Color::Green, &format!("✓ Tertiary rotation writer: {}\n",
                        if self.config.camera_patches.rotation_writer_3 { "ON" } else { "OFF" }))?;
                    self.auto_save()?;
                }
                "B" => {
                    return Ok(true); // Back to main menu
                }
                "E" => {
                    // Enable all detours and hooks
                    self.config.camera_patches.camera_detour_enabled = true;
                    self.config.camera_patches.xinput_detour_enabled = true;
                    self.config.camera_patches.mouse_hook_enabled = true;
                    // Enable all memory patches
                    self.config.camera_patches.camera_pos_writer_1 = true;
                    self.config.camera_patches.camera_pos_writer_2 = true;
                    self.config.camera_patches.camera_pos_writer_3 = true;
                    self.config.camera_patches.camera_pos_writer_4 = true;
                    self.config.camera_patches.camera_pos_writer_5 = true;
                    self.config.camera_patches.camera_pos_writer_6 = true;
                    self.config.camera_patches.camera_pos_writer_7 = true;
                    self.config.camera_patches.camera_pos_writer_8 = true;
                    self.config.camera_patches.camera_pos_writer_9 = true;
                    self.config.camera_patches.rotation_writer_1 = true;
                    self.config.camera_patches.rotation_writer_2 = true;
                    self.config.camera_patches.rotation_writer_3 = true;
let t = self.t();
                    self.write_colored(Color::Green, &format!("{}\n", t.all_patches_enabled))?;
                    self.auto_save()?;
                }
                "D" => {
                    // Disable all detours and hooks
                    self.config.camera_patches.camera_detour_enabled = false;
                    self.config.camera_patches.xinput_detour_enabled = false;
                    self.config.camera_patches.mouse_hook_enabled = false;
                    // Disable all memory patches
                    self.config.camera_patches.camera_pos_writer_1 = false;
                    self.config.camera_patches.camera_pos_writer_2 = false;
                    self.config.camera_patches.camera_pos_writer_3 = false;
                    self.config.camera_patches.camera_pos_writer_4 = false;
                    self.config.camera_patches.camera_pos_writer_5 = false;
                    self.config.camera_patches.camera_pos_writer_6 = false;
                    self.config.camera_patches.camera_pos_writer_7 = false;
                    self.config.camera_patches.camera_pos_writer_8 = false;
                    self.config.camera_patches.camera_pos_writer_9 = false;
                    self.config.camera_patches.rotation_writer_1 = false;
                    self.config.camera_patches.rotation_writer_2 = false;
                    self.config.camera_patches.rotation_writer_3 = false;
let t = self.t();
                    self.write_colored(Color::Yellow, &format!("{}\n", t.all_patches_disabled))?;
                    self.auto_save()?;
                }
                "R" => {
                    use crate::config::CameraPatchConfig;
                    self.config.camera_patches = CameraPatchConfig::default();
let t = self.t();
                    self.write_colored(Color::Green, &format!("{}\n", t.camera_patches_reset))?;
                    self.auto_save()?;
                }
                "" => return Ok(true), // Enter = back
                _ => {
                    let t = self.t();
                    self.write_colored(Color::Red, &format!("{}\n", t.invalid_option))?;
                }
            }

            if !["B", ""].contains(&input.as_str()) {
                let t = self.t();
                self.write_colored(Color::White, t.press_enter_to_continue)?;
                let mut _pause = String::new();
                io::stdin().read_line(&mut _pause)?;
            }
        }
    }

    fn change_language(&mut self) -> io::Result<()> {
        let t = self.t();
        self.write_colored(Color::Cyan, &format!("{}\n", t.language_menu_title))?;
        // Dynamically list supported languages
        let mut parts: Vec<String> = Vec::new();
        for &lang in crate::i18n::supported_languages() {
            parts.push(format!("[{}] {}", crate::i18n::language_code(lang), crate::i18n::language_name(lang)));
        }
        let list = parts.join(" | ");
        self.write_colored(Color::White, &format!("{}\n", list))?;
        self.write_colored(Color::White, t.prompt_choice)?;
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let sel = input.trim();
        if let Some(new_lang) = crate::i18n::find_language_by_code(sel) {
            let name = crate::i18n::language_name(new_lang);
            self.config.language = new_lang;
            self.write_colored(Color::Green, &format!("{}\n", t.language_set_to_fmt.replace("{}", name)))?;
        } else {
            self.write_colored(Color::Red, &format!("{}\n", t.invalid_option))?;
        }
        Ok(())
    }
}
