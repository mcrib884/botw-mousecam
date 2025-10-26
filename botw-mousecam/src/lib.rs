use memory_rs::internal::{
    injections::{Detour, Inject, Injection},
    memory::resolve_module_path,
    process_info::ProcessInfo,
};
use std::ffi::CString;
use winapi::um::consoleapi::{AllocConsole, GetConsoleMode, SetConsoleMode};
use winapi::um::libloaderapi::{FreeLibraryAndExitThread, GetModuleHandleA, DisableThreadLibraryCalls};
use winapi::um::wincon::{FreeConsole, SetConsoleTitleA};
use winapi::um::processenv::GetStdHandle;
use winapi::um::winbase::STD_INPUT_HANDLE;
use winapi::um::winuser;
use winapi::um::libloaderapi::GetProcAddress;
use winapi::um::processthreadsapi::{CreateProcessA, TerminateProcess, STARTUPINFOA, PROCESS_INFORMATION, GetCurrentProcess, OpenProcess};
use winapi::um::errhandlingapi::{GetLastError, RemoveVectoredExceptionHandler, AddVectoredExceptionHandler};
use winapi::um::handleapi::{CloseHandle};
use winapi::um::memoryapi::{MapViewOfFile, UnmapViewOfFile, FILE_MAP_ALL_ACCESS, VirtualProtect, WriteProcessMemory, VirtualQuery, ReadProcessMemory};
use winapi::um::winbase::{CREATE_NO_WINDOW, OpenFileMappingA};
use winapi::um::winnt::{HANDLE, PAGE_EXECUTE_READWRITE, PROCESS_TERMINATE, MEMORY_BASIC_INFORMATION, MEM_COMMIT, DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS};
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use winapi::shared::minwindef::{WPARAM, LPARAM, LRESULT, DWORD, BOOL, TRUE};
use std::fs;
use std::path::Path;


use log::*;
use simplelog::*;
use std::io::{self, Write};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use std::time::{Duration, Instant};

mod camera;
mod utils;
mod config;
mod menu;
mod focus;
mod menu_state;
mod magnesis_experimental;
mod globals;
mod i18n;

use camera::*;
use crate::globals::*;
use utils::{error_message, handle_mouse_input, MouseInput};
use config::Config as MouseConfig;
use menu::ConfigMenu;
use focus::{init_focus_detector};
use menu_state::{cleanup_menu_state_detection, check_menu_transition};

// Shared memory bit flags (keep in sync with PositionFinder)
const READY_POS: u32 = 1 << 0;
const READY_MOVZX: u32 = 1 << 1;
const READY_MENU_MOVBE: u32 = 1 << 2;
const READY_MAGNESIS_NORMAL: u32 = 1 << 3;
const READY_MAGNESIS_EXP: u32 = 1 << 4;
const READY_PHONECAMERA: u32 = 1 << 5;

const REQ_POS: u32 = READY_POS;
const REQ_MOVZX: u32 = READY_MOVZX;
const REQ_MENU_MOVBE: u32 = READY_MENU_MOVBE;
const REQ_MAGNESIS_NORMAL: u32 = READY_MAGNESIS_NORMAL;
const REQ_MAGNESIS_EXP: u32 = READY_MAGNESIS_EXP;
const REQ_PHONECAMERA: u32 = READY_PHONECAMERA;

// Import Cemu types for proper typing


#[repr(C)]
struct VPADStatus_t {
    hold: u32,
    trig: u32,
    release: u32,
    // ... other fields we don't need to modify
}

#[repr(C)]
struct WPADStatus_t {
    button: u32,
    // ... other fields we don't need to modify
}

#[repr(C)]
struct BtnRepeat {
    delay: i32,
    pulse: i32,
}

use nalgebra_glm as glm;





// Shared memory structure for communicating with external position finder
// Must match the structure in position_finder Program.cs
#[repr(C, packed)]
struct SharedPositionData {
    position_address: u64,              // 0-7
    last_update: u64,                   // 8-15
    is_valid: u32,                      // 16-19
    player_state_address: u64,          // 20-27 (no padding - matches C# Pack=1)
    player_state_value: u32,            // 28-31
    player_state_valid: u32,            // 32-35
    movzx_instruction_address: u64,     // 36-43 (matches C# location!)
    movzx_instruction_valid: u32,       // 44-47 (matches C# location!)
    menu_movbe_address: u64,            // 48-55 (address of menu MOVBE instruction)
    menu_movbe_valid: u32,              // 56-59
    // Normal magnesis MOVBE addresses (X, Y, Z) - for detection only
    magnesis_instruction_address: u64,  // 60-67 (X coordinate MOVBE)
    magnesis_instruction_valid: u32,    // 68-71
    magnesis_y_instruction_address: u64, // 72-79 (Y coordinate MOVBE)
    magnesis_y_instruction_valid: u32,  // 80-83
    magnesis_z_instruction_address: u64, // 84-91 (Z coordinate MOVBE)
    magnesis_z_instruction_valid: u32,  // 92-95
    // Experimental magnesis MOVBE addresses (X, Y, Z) - for mouse control override
    exp_magnesis_x_address: u64,        // 96-103 (Experimental X coordinate MOVBE)
    exp_magnesis_x_valid: u32,          // 104-107
    exp_magnesis_y_address: u64,        // 108-115 (Experimental Y coordinate MOVBE)
    exp_magnesis_y_valid: u32,          // 116-119
    exp_magnesis_z_address: u64,        // 120-127 (Experimental Z coordinate MOVBE)
    exp_magnesis_z_valid: u32,          // 128-131
    // Camera lock cmpxchg instruction address - for camera open detection
    camera_cmpxchg_address: u64,        // 132-139 (Camera lock cmpxchg instruction)
    camera_cmpxchg_valid: u32,          // 140-143
    // Synchronization and control fields
    shm_version: u32,                   // 144-147 (protocol version)
    shm_seq: u32,                       // 148-151 (monotonic sequence incremented by position_finder)
    ready_flags: u32,                   // 152-155 (bitmask of READY_*)
    request_flags: u32,                 // 156-159 (bitmask of REQ_*)
}

// Global pointer to shared memory and process handle
static mut g_shared_position_data: *mut SharedPositionData = std::ptr::null_mut();
static mut g_shared_mapping_handle: HANDLE = std::ptr::null_mut();
static mut g_position_finder_process: HANDLE = std::ptr::null_mut();

// Player state detection globals
static mut g_player_state_address: usize = 0;
static mut g_last_player_state: u8 = 255; // Initialize to invalid state
static mut g_original_player_state_function: usize = 0;
static mut g_movzx_hook_detour: Option<Detour> = None;
static mut g_runtime_player_state_addr: usize = 0;
static mut g_runtime_player_state_value: u8 = 255;
static mut g_aim_blend: f32 = 0.0;
static mut g_movzx_breakpoint_addr: usize = 0;
static mut g_original_movzx_byte: u8 = 0;
static mut g_exception_handler: *mut winapi::ctypes::c_void = std::ptr::null_mut();

// Menu state detection globals
static mut g_movbe_breakpoint_addr: usize = 0;
static mut g_original_movbe_byte: u8 = 0;
static mut g_movbe_exception_handler: *mut winapi::ctypes::c_void = std::ptr::null_mut();
static mut g_menu_state_address: usize = 0;
static mut g_last_menu_state: u8 = 255; // Track previous menu state for transition detection


// Magnesis update tracking globals
static mut g_magnesis_last_update_time: Option<std::time::Instant> = None;
static mut g_magnesis_session_start_time: Option<std::time::Instant> = None;
static mut g_magnesis_enabled_state: bool = false;
static mut g_magnesis_update_count: u32 = 0;
static mut g_magnesis_last_log_time: Option<std::time::Instant> = None;
static mut g_magnesis_just_enabled: bool = false; // set in handler, logged in main loop
static mut g_magnesis_address_logged: bool = false; // log address once in main loop
const MAGNESIS_UPDATE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(300); // 300ms without updates = disabled (after 2s invincibility window)
const MAGNESIS_INVINCIBILITY_SECS: u64 = 2; // 2-second invincibility window after first activation


// Movzx re-breakpointing globals
static mut g_movzx_recheck_breakpoint_addr: usize = 0;
static mut g_original_movzx_recheck_byte: u8 = 0;
static mut g_movzx_recheck_exception_handler: *mut winapi::ctypes::c_void = std::ptr::null_mut();
static mut g_stored_player_state_address: usize = 0; // Store the original player state address for comparison

// PhoneCamera (in-game photo mode) cmpxchg breakpoint globals
static mut g_phonecamera_cmpxchg_breakpoint_addr: usize = 0;
static mut g_original_phonecamera_cmpxchg_byte: u8 = 0;
static mut g_phonecamera_cmpxchg_exception_handler: *mut winapi::ctypes::c_void = std::ptr::null_mut();
static mut g_phonecamera_flag_addr: usize = 0; // Computed from R13 + RDX + 0x0C (confirmed)

// PhoneCamera open state tracking
static mut g_last_phonecamera_open_state: bool = false;

// PhoneCamera FOV handling
static mut g_phonecamera_fov_saved: bool = false; // Whether we've saved the original FOV upon entering photo mode
static mut g_phonecamera_original_fov: f32 = NORMAL_FOV; // Original FOV to restore when exiting photo mode
static mut g_phonecamera_current_target_fov: f32 = PHONECAMERA_BASE_FOV; // Current photo-mode FOV target (wheel-adjustable)

// PhoneCamera logging state (toggled by F5)
static mut g_phonecamera_logging_enabled: bool = false;

// Track last phonecamera value for change detection logging
static mut g_last_phonecamera_value: u32 = 255; // Initialize to invalid value

// Mod exit flag
static mut g_mod_should_exit: bool = false;

// Player state tracking for camera adjustments
static mut g_previous_player_state: u8 = 0;

// Global detours for safe activation/deactivation
static mut g_vpad_detour: Option<Detour> = None;
static mut g_wpad_detour: Option<Detour> = None;

// Menu detection globals
static mut g_user_requested_active: bool = false; // User's intended mod state
static mut g_menu_just_closed: bool = false; // Flag for menu->game transition
static mut g_last_menu_closed_time: Option<std::time::Instant> = None; // Timestamp of last menu close for phonecamera suppression

// Camera update detection
static mut ORIGINAL_CAMERA_FUNC: usize = 0;

// Camera update wrapper simplified - menu detection removed
extern "C" fn camera_update_wrapper() {
    unsafe {
        // Call the original assembly hook directly
        let asm_func: extern "C" fn() = std::mem::transmute(&asm_get_camera_data as *const u8);
        asm_func();
    }
}

// Helper function for menu state module to set the menu closed flag
pub fn set_menu_just_closed(closed: bool) {
    unsafe {
        g_menu_just_closed = closed;
    }
}

// Expose raw phonecamera flag check for menu_state logic to disambiguate menu vs photo overlay
pub fn is_phonecamera_flag_active_raw() -> bool {
    unsafe {
        if g_phonecamera_flag_addr == 0 { return false; }
        match read_u32_safe(g_phonecamera_flag_addr) {
            Some(v) => v == 1,
            None => false,
        }
    }
}

// Simple precision mode - continuous application (no state tracking needed)

fn write_red(msg: &str) -> io::Result<()> {
    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)))?;
    writeln!(&mut stdout, "{}", msg)?;
    stdout.reset()?;
    
    // Also log to file
    error!("{}", msg);
    Ok(())
}

// Unified logging functions that output to both console and file
fn log_info(msg: &str) {
    println!("[INFO] {}", msg);
    info!("{}", msg);
}

fn log_warn(msg: &str) {
    println!("[WARN] {}", msg);
    warn!("{}", msg);
}

fn log_error(msg: &str) {
    println!("[ERROR] {}", msg);
    error!("{}", msg);
}

// Convenience macros to mirror console messages into the file logger
macro_rules! log_infof {
    ($($arg:tt)*) => {{
        let s = format!($($arg)*);
        log_info(&s);
    }};
}
macro_rules! log_warnf {
    ($($arg:tt)*) => {{
        let s = format!($($arg)*);
        log_warn(&s);
    }};
}
macro_rules! log_errorf {
    ($($arg:tt)*) => {{
        let s = format!($($arg)*);
        log_error(&s);
    }};
}

// Player state detection moved to position finder module

// Assembly code removed - player state detection moved to position finder

unsafe extern "system" fn wrapper(lib: *mut std::ffi::c_void) -> u32 {
    AllocConsole();

    // Disable Quick Edit mode so console selections don't pause the app
    disable_console_quick_edit();

    // IMMEDIATE CONSOLE OUTPUT - This should be visible right away
    log_infof!("=== BOTW MOUSECAM MOD LOADED ===");
    log_infof!("Initializing BOTW Mouse Camera Mod...");
    
    // Set up panic hook for emergency cleanup
    std::panic::set_hook(Box::new(|panic_info| {
        println!("RUST DLL: PANIC occurred - performing emergency cleanup!");
        eprintln!("Panic: {}", panic_info);
        
        // Emergency cleanup of all breakpoints
        unsafe {
            cleanup_all_breakpoints();
            cleanup_external_position_finder();
        }
    }));

    {
        // Robust logger initialization: ensure we log somewhere writable
        let mut base_path = resolve_module_path(lib as *const std::ffi::c_void)
            .unwrap_or_else(|_| std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")));
        if base_path.is_file() {
            base_path.pop();
        }
        let primary_log_path = base_path.join("botw-mousecam.log");

        // Clean up any existing log files first
        let _ = std::fs::remove_file(&primary_log_path); // Ignore errors
        let _ = std::fs::remove_file(std::env::temp_dir().join("botw-mousecam.log")); // Ignore errors
        let _ = std::fs::remove_file("botw-mousecam.log"); // Ignore errors
        let _ = std::fs::remove_file("botw_mousecam.log"); // Ignore errors
        
        // Try primary location, fall back to temp dir, then CWD
        let (log_file, final_log_path) = match std::fs::File::create(&primary_log_path) {
            Ok(f) => {
                log_infof!("Log file created at: {:?}", primary_log_path);
                (f, primary_log_path.clone())
            },
            Err(_) => {
                let fallback = std::env::temp_dir().join("botw-mousecam.log");
                match std::fs::File::create(&fallback) {
                    Ok(f) => {
                        log_infof!("Log file created at: {:?}", fallback);
                        (f, fallback)
                    },
                    Err(_) => {
                        let cwd_fallback = std::path::PathBuf::from("botw-mousecam.log");
                        let f = std::fs::File::create(&cwd_fallback)
                            .unwrap_or_else(|_| std::fs::File::create("botw_mousecam.log").expect("failed to create any log file"));
                        let path = if cwd_fallback.exists() { cwd_fallback } else { std::path::PathBuf::from("botw_mousecam.log") };
                        log_infof!("Log file created at: {:?}", path);
                        (f, path)
                    }
                }
            }
        };

        // Configure logging with local time
        let config = simplelog::ConfigBuilder::new()
            .set_time_to_local(true)
            .build();
            
        CombinedLogger::init(vec![
            TermLogger::new(
                log::LevelFilter::Info,
                config.clone(),
                TerminalMode::Mixed,
            ),
            WriteLogger::new(
                log::LevelFilter::Info,
                config,
                log_file,
            ),
        ])
        .unwrap();



        match patch(lib) {
            Ok(_) => (),
            Err(e) => {
                let msg = format!("Something went wrong:\n{}", e);
                error!("{}", msg);
                error_message(&msg);
            }
        }
    }

    FreeConsole();
    FreeLibraryAndExitThread(lib as _, 0);
    0
}

#[derive(Debug)]
struct CameraOffsets {
    camera: usize,
    rotation_vec1: usize,
}


// Global Link position pointer
static mut g_link_position_addr: usize = 0;

// Sprint toggle state
static mut SPRINT_TOGGLE_ACTIVE: bool = false;      // logical toggle state
static mut SPRINT_HELD_BY_MOD: bool = false;        // whether we are currently holding the key down
static mut LAST_LINK_POS_XZ: Option<(f32, f32)> = None;
static mut LAST_LINK_SAMPLE_TIME: Option<Instant> = None;
static mut LAST_HORIZ_SPEED: f32 = 0.0;             // meters/sec (approx.)
static mut STOPPED_SINCE: Option<Instant> = None;   // when speed fell below stop threshold
// Post-release hold helpers
static mut SPRINT_PHYSICAL_DOWN: bool = false;      // physical key is currently down
static mut SPRINT_ARMED_FROM_PHYSICAL: bool = false; // set on real physical press; only then engage on release
// Track when post-release hold engaged to provide grace period before auto-off
static mut SPRINT_ENGAGED_AT: Option<Instant> = None;

fn get_camera_function() -> Result<CameraOffsets, Box<dyn std::error::Error>> {
    let function_name = CString::new("PPCRecompiler_getJumpTableBase").unwrap();
    let proc_handle = unsafe { GetModuleHandleA(std::ptr::null_mut()) };
    let func = unsafe { GetProcAddress(proc_handle, function_name.as_ptr()) };

    if (func as usize) == 0x0 {
        return Err("Func returned was empty".into());
    }
    let func: extern "C" fn() -> usize = unsafe { std::mem::transmute(func) };

    let addr = (func)();

    if addr == 0x0 {
        return Err(
            "Jump table was empty, Check you're running the game and using recompiler profile"
                .into(),
        );
    }

    let array = unsafe { std::slice::from_raw_parts(addr as *const usize, 0x8800000 / 0x8) };
    let original_bytes = [
        0x45_u8, 0x0F, 0x38, 0xF1, 0xB4, 0x15, 0x54, 0x06, 0x00, 0x00,
    ];

    let dummy_pointer = array[0];
    let camera_offset = loop {
        let function_start = array[0x2C085FC / 4];

        if dummy_pointer != function_start {
            break function_start + 0x7E;
        }
        std::thread::sleep(std::time::Duration::from_secs(1))
    };

    let camera_bytes = unsafe { std::slice::from_raw_parts((camera_offset) as *const u8, 10) };
    if camera_bytes != original_bytes {
        return Err(format!(
            "Function signature doesn't match:\n\
            * You may be using a cheat that requires a 'master cheat' to be activated\n\
            * You may be using a pre 2016 CPU (your cpu doesn't support `movbe`)\n\
            * You may not be using the correct game version\n\
            {:x?} != {:x?}",
            camera_bytes, original_bytes
        )
        .into());
    }

    let rotation_vec1 = array[0x2e57fdc / 4] + 0x57;

    Ok(CameraOffsets {
        camera: camera_offset,
        rotation_vec1,
    })
}

fn find_vpad_read_os_api(proc_inf: &ProcessInfo) -> Result<usize, Box<dyn std::error::Error>> {
    // Find vpad::VPADRead OS API function (the one games actually call)
    // Look for the function signature: sint32 VPADRead(sint32 channel, VPADStatus* status, uint32 length, sint32be* error)
    let function_addr = proc_inf
        .region
        .scan_aob(&memory_rs::generate_aob_pattern![
            0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x30
        ])?
        .ok_or("vpad::VPADRead OS API not found")?;
    Ok(function_addr)
}

fn find_wpad_read_os_api(proc_inf: &ProcessInfo) -> Result<usize, Box<dyn std::error::Error>> {
    // Find padscoreExport_WPADRead OS API function
    let function_addr = proc_inf
        .region
        .scan_aob(&memory_rs::generate_aob_pattern![
            0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xFA
        ])?
        .ok_or("padscoreExport_WPADRead OS API not found")?;
    Ok(function_addr)
}


















// VPAD and WPAD detour hooks removed - redundant with keyboard input system

fn find_link_position(_proc_inf: &ProcessInfo) -> Result<usize, Box<dyn std::error::Error>> {
    // Start the external position finder if not already running
    start_external_position_finder();

    // Initialize shared memory connection
    init_shared_memory();

    // Strict handshake: request POS and wait until delivered (no coordinate verification here)
    unsafe {
        if !g_shared_position_data.is_null() {
            let ptr = core::ptr::addr_of_mut!((*g_shared_position_data).request_flags);
            let curr = core::ptr::read_unaligned(ptr as *const u32);
            core::ptr::write_unaligned(ptr, curr | REQ_POS);
        }
    }

    log_infof!("RUST DLL: Handshake - requesting Link position address (POS)...");

    let mut last_log = std::time::Instant::now();
    loop {
        std::thread::sleep(std::time::Duration::from_millis(50));
        init_shared_memory();
        unsafe {
            if g_shared_position_data.is_null() { continue; }
            let base = g_shared_position_data;
            let ready_flags: u32 = core::ptr::read_unaligned(core::ptr::addr_of!((*base).ready_flags));
            let is_valid: u32 = core::ptr::read_unaligned(core::ptr::addr_of!((*base).is_valid));
            let pos_addr: u64 = core::ptr::read_unaligned(core::ptr::addr_of!((*base).position_address));
            if ((ready_flags & READY_POS) != 0 || is_valid != 0) && pos_addr != 0 {
                log_infof!("RUST DLL: SUCCESS! Received Link position address 0x{:x}", pos_addr);
                return Ok(pos_addr as usize);
            }
            if last_log.elapsed() > std::time::Duration::from_secs(1) {
                last_log = std::time::Instant::now();
                log_infof!("RUST DLL: Waiting for POS... (ready=0x{:x}, is_valid={}, addr=0x{:x})", ready_flags, is_valid, pos_addr);
                let ptr = core::ptr::addr_of_mut!((*g_shared_position_data).request_flags);
                let curr = core::ptr::read_unaligned(ptr as *const u32);
                core::ptr::write_unaligned(ptr, curr | REQ_POS);
            }
        }
    }
}

// Kill any stray position finder processes that might be running
fn kill_stray_position_finder_processes() {
    unsafe {
        
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return;
        }
        
        let mut pe32: PROCESSENTRY32 = std::mem::zeroed();
        pe32.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;
        
        if Process32First(snapshot, &mut pe32) != 0 {
            loop {
                let process_name = std::ffi::CStr::from_ptr(pe32.szExeFile.as_ptr());
                if let Ok(name_str) = process_name.to_str() {
                    if name_str.to_lowercase().contains("position_finder") {
                        let process_handle = OpenProcess(PROCESS_TERMINATE, 0, pe32.th32ProcessID);
                        if !process_handle.is_null() {
                            log_infof!("RUST DLL: Terminating stray position_finder process (PID: {})", pe32.th32ProcessID);
                            TerminateProcess(process_handle, 0);
                            CloseHandle(process_handle);
                        }
                    }
                }
                
                if Process32Next(snapshot, &mut pe32) == 0 {
                    break;
                }
            }
        }
        
        CloseHandle(snapshot);
    }
}

fn start_external_position_finder() {
    unsafe {
        // Don't start if already running
        if !g_position_finder_process.is_null() {
            return;
        }
        
        // Kill any stray position finder processes first
        kill_stray_position_finder_processes();

        // Enhanced search for position finder in various locations
        let possible_paths = [
            "position_finder.exe",
            "position_finder/bin/Release/net6.0/position_finder.exe",
            "position_finder/bin/Release/net6.0/win-x64/publish/position_finder.exe",
            "target/release/position_finder.exe",
            "./position_finder.exe"
        ];

        let mut exe_path = None;
        for path in &possible_paths {
            if std::path::Path::new(path).exists() {
                exe_path = Some(CString::new(*path).unwrap());
                break;
            }
        }

        let exe_path = exe_path.unwrap_or_else(|| {
            warn!("position_finder.exe not found in expected locations, using default path");
            CString::new("position_finder.exe").unwrap()
        });

        let mut startup_info: STARTUPINFOA = std::mem::zeroed();
        startup_info.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
        startup_info.dwFlags = 0x00000001; // STARTF_USESHOWWINDOW
        startup_info.wShowWindow = 0; // SW_HIDE - completely hidden
        let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

        // Create command line with --auto flag to prevent console prompts and make it silent
        let cmd_line = CString::new("position_finder.exe --auto").unwrap();

        let result = CreateProcessA(
            exe_path.as_ptr(),
            cmd_line.as_ptr() as *mut i8,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            CREATE_NO_WINDOW, // Run invisibly without console window
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut startup_info,
            &mut process_info,
        );

        if result != 0 {
            // Keep process handle for cleanup, close thread handle
            g_position_finder_process = process_info.hProcess;
            CloseHandle(process_info.hThread);

            // Give it a moment to initialize
            std::thread::sleep(std::time::Duration::from_millis(50));
        } else {
            let error_code = GetLastError();
            warn!("Failed to start external position finder (error code: {})", error_code);
        }
    }
}

fn cleanup_external_position_finder() {
    unsafe {
        if !g_position_finder_process.is_null() {
            TerminateProcess(g_position_finder_process, 0);
            CloseHandle(g_position_finder_process);
            g_position_finder_process = std::ptr::null_mut();
        }

        // Cleanup shared memory
        if !g_shared_position_data.is_null() {
            UnmapViewOfFile(g_shared_position_data as *const _);
            g_shared_position_data = std::ptr::null_mut();
        }
        if !g_shared_mapping_handle.is_null() {
            CloseHandle(g_shared_mapping_handle);
            g_shared_mapping_handle = std::ptr::null_mut();
        }
    }
}

// CRITICAL: Clean up all breakpoints on DLL exit to restore original code
fn cleanup_all_breakpoints() {
    unsafe {

        println!("RUST DLL: Cleaning up all breakpoints to restore original code...");

        // 1. Restore movzx breakpoint
        if g_movzx_breakpoint_addr != 0 && g_original_movzx_byte != 0 {
            println!("RUST DLL: Restoring movzx instruction at 0x{:x} (0xCC -> 0x{:02X})", 
                     g_movzx_breakpoint_addr, g_original_movzx_byte);
            
            let mut old_protect = 0u32;
            if VirtualProtect(g_movzx_breakpoint_addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect) != 0 {
                let mut bytes_written = 0usize;
                WriteProcessMemory(
                    GetCurrentProcess(),
                    g_movzx_breakpoint_addr as *mut _,
                    &g_original_movzx_byte as *const _ as *const _,
                    1,
                    &mut bytes_written
                );
                VirtualProtect(g_movzx_breakpoint_addr as *mut _, 1, old_protect, &mut old_protect);
                println!("RUST DLL: Movzx breakpoint restored successfully");
            } else {
                println!("RUST DLL: Failed to restore movzx breakpoint (VirtualProtect failed)");
            }
            
            if !g_exception_handler.is_null() {
                RemoveVectoredExceptionHandler(g_exception_handler);
                g_exception_handler = std::ptr::null_mut();
            }
            
            g_movzx_breakpoint_addr = 0;
            g_original_movzx_byte = 0;
        }

        // 2. Restore menu MOVBE breakpoint
        if g_movbe_breakpoint_addr != 0 && g_original_movbe_byte != 0 {
            println!("RUST DLL: Restoring menu MOVBE instruction at 0x{:x} (0xCC -> 0x{:02X})", 
                     g_movbe_breakpoint_addr, g_original_movbe_byte);
            
            let mut old_protect = 0u32;
            if VirtualProtect(g_movbe_breakpoint_addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect) != 0 {
                let mut bytes_written = 0usize;
                WriteProcessMemory(
                    GetCurrentProcess(),
                    g_movbe_breakpoint_addr as *mut _,
                    &g_original_movbe_byte as *const _ as *const _,
                    1,
                    &mut bytes_written
                );
                VirtualProtect(g_movbe_breakpoint_addr as *mut _, 1, old_protect, &mut old_protect);
                println!("RUST DLL: Menu MOVBE breakpoint restored successfully");
            } else {
                println!("RUST DLL: Failed to restore menu MOVBE breakpoint (VirtualProtect failed)");
            }
            
            if !g_movbe_exception_handler.is_null() {
                RemoveVectoredExceptionHandler(g_movbe_exception_handler);
                g_movbe_exception_handler = std::ptr::null_mut();
            }
            
            g_movbe_breakpoint_addr = 0;
            g_original_movbe_byte = 0;
        }


        // 3. Restore magnesis X coordinate breakpoint
        if g_magnesis_breakpoint_addr != 0 && g_original_magnesis_byte != 0 {
            println!("RUST DLL: Restoring magnesis X instruction at 0x{:x} (0xCC -> 0x{:02X})", 
                     g_magnesis_breakpoint_addr, g_original_magnesis_byte);
            
            let mut old_protect = 0u32;
            if VirtualProtect(g_magnesis_breakpoint_addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect) != 0 {
                let mut bytes_written = 0usize;
                WriteProcessMemory(
                    GetCurrentProcess(),
                    g_magnesis_breakpoint_addr as *mut _,
                    &g_original_magnesis_byte as *const _ as *const _,
                    1,
                    &mut bytes_written
                );
                VirtualProtect(g_magnesis_breakpoint_addr as *mut _, 1, old_protect, &mut old_protect);
                println!("RUST DLL: Magnesis X breakpoint restored successfully");
            } else {
                println!("RUST DLL: Failed to restore magnesis X breakpoint (VirtualProtect failed)");
            }
            
            if !g_magnesis_exception_handler.is_null() {
                RemoveVectoredExceptionHandler(g_magnesis_exception_handler);
                g_magnesis_exception_handler = std::ptr::null_mut();
            }
            
            g_magnesis_breakpoint_addr = 0;
            g_original_magnesis_byte = 0;
        }

        // 4. Restore movzx re-check breakpoint
        if g_movzx_recheck_breakpoint_addr != 0 && g_original_movzx_recheck_byte != 0 {
            println!("RUST DLL: Restoring movzx recheck instruction at 0x{:x} (0xCC -> 0x{:02X})", 
                     g_movzx_recheck_breakpoint_addr, g_original_movzx_recheck_byte);
            
            let mut old_protect = 0u32;
            if VirtualProtect(g_movzx_recheck_breakpoint_addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect) != 0 {
                let mut bytes_written = 0usize;
                WriteProcessMemory(
                    GetCurrentProcess(),
                    g_movzx_recheck_breakpoint_addr as *mut _,
                    &g_original_movzx_recheck_byte as *const _ as *const _,
                    1,
                    &mut bytes_written
                );
                VirtualProtect(g_movzx_recheck_breakpoint_addr as *mut _, 1, old_protect, &mut old_protect);
                println!("RUST DLL: Movzx recheck breakpoint restored successfully");
            } else {
                println!("RUST DLL: Failed to restore movzx recheck breakpoint (VirtualProtect failed)");
            }
            
            if !g_movzx_recheck_exception_handler.is_null() {
                RemoveVectoredExceptionHandler(g_movzx_recheck_exception_handler);
                g_movzx_recheck_exception_handler = std::ptr::null_mut();
            }
            
            g_movzx_recheck_breakpoint_addr = 0;
            g_original_movzx_recheck_byte = 0;
        }

        // 5. Restore phonecamera cmpxchg breakpoint
        if g_phonecamera_cmpxchg_breakpoint_addr != 0 && g_original_phonecamera_cmpxchg_byte != 0 {
            println!("RUST DLL: Restoring phonecamera cmpxchg instruction at 0x{:x} (0xCC -> 0x{:02X})", 
                     g_phonecamera_cmpxchg_breakpoint_addr, g_original_phonecamera_cmpxchg_byte);
            
            let mut old_protect = 0u32;
            if VirtualProtect(g_phonecamera_cmpxchg_breakpoint_addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect) != 0 {
                let mut bytes_written = 0usize;
                WriteProcessMemory(
                    GetCurrentProcess(),
                    g_phonecamera_cmpxchg_breakpoint_addr as *mut _,
                    &g_original_phonecamera_cmpxchg_byte as *const _ as *const _,
                    1,
                    &mut bytes_written
                );
                VirtualProtect(g_phonecamera_cmpxchg_breakpoint_addr as *mut _, 1, old_protect, &mut old_protect);
                println!("RUST DLL: Phonecamera cmpxchg breakpoint restored successfully");
            } else {
                println!("RUST DLL: Failed to restore phonecamera cmpxchg breakpoint (VirtualProtect failed)");
            }
            
            if !g_phonecamera_cmpxchg_exception_handler.is_null() {
                RemoveVectoredExceptionHandler(g_phonecamera_cmpxchg_exception_handler);
                g_phonecamera_cmpxchg_exception_handler = std::ptr::null_mut();
            }
            
            g_phonecamera_cmpxchg_breakpoint_addr = 0;
            g_original_phonecamera_cmpxchg_byte = 0;
        }

        println!("RUST DLL: All breakpoints cleaned up successfully");
    }
}

fn init_shared_memory() {
    unsafe {
        if !g_shared_position_data.is_null() {
            return; // Already initialized
        }

        let mapping_name = CString::new("Local\\BotwPositionData").unwrap();
        let mut mapping_handle = OpenFileMappingA(
            FILE_MAP_ALL_ACCESS,
            0,
            mapping_name.as_ptr(),
        );

        if mapping_handle.is_null() {
            // If not present, create it so position_finder can open it later
            use winapi::um::memoryapi::CreateFileMappingW;
            use winapi::um::handleapi::INVALID_HANDLE_VALUE;
            use winapi::um::winnt::PAGE_READWRITE;
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;
            let wide: Vec<u16> = OsStr::new("Local\\BotwPositionData").encode_wide().chain(std::iter::once(0)).collect();
            mapping_handle = CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                std::ptr::null_mut(),
                PAGE_READWRITE,
                0,
                std::mem::size_of::<SharedPositionData>() as u32,
                wide.as_ptr(),
            );
            if mapping_handle.is_null() {
                let error_code = GetLastError();
                warn!("Could not open or create shared memory mapping (error: {})", error_code);
                return;
            }
            log_infof!("RUST DLL: Created shared memory mapping (waiting for position_finder)");
        } else {
            log_infof!("RUST DLL: Successfully opened shared memory mapping");
        }

        g_shared_position_data = MapViewOfFile(
            mapping_handle,
            FILE_MAP_ALL_ACCESS,
            0,
            0,
            std::mem::size_of::<SharedPositionData>(),
        ) as *mut SharedPositionData;

        if g_shared_position_data.is_null() {
            let error_code = GetLastError();
            warn!("Failed to map view of file - error: {}", error_code);
            // Close failed mapping handle
            CloseHandle(mapping_handle);
        } else {
            // Keep the mapping handle open globally so the named mapping remains accessible
            g_shared_mapping_handle = mapping_handle;
            log_infof!("RUST DLL: Successfully mapped shared memory at {:p}", g_shared_position_data);
            info!("[SHARED_MEMORY] Successfully mapped shared memory at {:p}", g_shared_position_data);
        }
    }
}

fn get_position_from_shared_memory() -> Option<usize> {
    unsafe {
        if g_shared_position_data.is_null() {
            return None;
        }

        let base = g_shared_position_data;
        let is_valid = core::ptr::read_unaligned(core::ptr::addr_of!((*base).is_valid));
        let pos_addr = core::ptr::read_unaligned(core::ptr::addr_of!((*base).position_address));
        if is_valid != 0 && pos_addr != 0 {
            Some(pos_addr as usize)
        } else {
            None
        }
    }
}

fn get_menu_movbe_from_shared_memory() -> Option<usize> {
    unsafe {
        if g_shared_position_data.is_null() {
            return None;
        }
        let base = g_shared_position_data;
        let ready_flags = core::ptr::read_unaligned(core::ptr::addr_of!((*base).ready_flags));
        let valid = core::ptr::read_unaligned(core::ptr::addr_of!((*base).menu_movbe_valid));
        let addr = core::ptr::read_unaligned(core::ptr::addr_of!((*base).menu_movbe_address));
        let ready = (ready_flags & READY_MENU_MOVBE) != 0;
        if (valid != 0 || ready) && addr != 0 {
            Some(addr as usize)
        } else {
            None
        }
    }
}

fn get_phonecamera_lock_cmpxchg_from_shared_memory() -> Option<usize> {
    unsafe {
        if g_shared_position_data.is_null() {
            return None;
        }
        let base = g_shared_position_data;
        let ready_flags = core::ptr::read_unaligned(core::ptr::addr_of!((*base).ready_flags));
        let valid = core::ptr::read_unaligned(core::ptr::addr_of!((*base).camera_cmpxchg_valid));
        let addr = core::ptr::read_unaligned(core::ptr::addr_of!((*base).camera_cmpxchg_address));
        let ready = (ready_flags & READY_PHONECAMERA) != 0;
        if (valid != 0 || ready) && addr != 0 {
            Some(addr as usize)
        } else {
            None
        }
    }
}



fn get_player_state_from_shared_memory() -> Option<(usize, u32)> {
    unsafe {
        if g_shared_position_data.is_null() {
            return None;
        }

        let base = g_shared_position_data;

        // Read using unaligned access to avoid UB with packed struct
        let movzx_valid: u32 = core::ptr::read_unaligned(core::ptr::addr_of!((*base).movzx_instruction_valid));
        let movzx_addr: u64 = core::ptr::read_unaligned(core::ptr::addr_of!((*base).movzx_instruction_address));
        let player_state_valid: u32 = core::ptr::read_unaligned(core::ptr::addr_of!((*base).player_state_valid));
        let player_state_addr: u64 = core::ptr::read_unaligned(core::ptr::addr_of!((*base).player_state_address));
        let ready_flags: u32 = core::ptr::read_unaligned(core::ptr::addr_of!((*base).ready_flags));
        let req_flags: u32 = core::ptr::read_unaligned(core::ptr::addr_of!((*base).request_flags));
        
        // Debug logging every few calls to see what position finder provides
        static mut LAST_DEBUG_LOG: Option<std::time::Instant> = None;
        let should_debug = LAST_DEBUG_LOG.map_or(true, |t| t.elapsed() > std::time::Duration::from_secs(5));
        if should_debug {
            LAST_DEBUG_LOG = Some(std::time::Instant::now());
            info!("[PLAYER_STATE] Position finder data: movzx_valid={}, movzx_addr=0x{:x}, player_state_valid={}, player_state_addr=0x{:x}",
                  movzx_valid, movzx_addr, player_state_valid, player_state_addr);
            info!("[SHARED_MEMORY] Flags: ready=0x{:x}, request=0x{:x}", ready_flags, req_flags);
        }

        // First check if we already have valid runtime data from previous breakpoint
        if g_runtime_player_state_addr != 0 {
            let player_state_value = g_runtime_player_state_value as u32;
            return Some((g_runtime_player_state_addr, player_state_value));
        }

        // Only try to set up breakpoint if we don't have data and have movzx address
        if (movzx_valid != 0 || (ready_flags & READY_MOVZX) != 0) && movzx_addr != 0 {
            info!("[PLAYER_STATE] Attempting to set up breakpoint at movzx address: 0x{:x}", movzx_addr);
            
            // Use runtime hook to capture r13 value when movzx instruction executes
            if setup_movzx_runtime_hook(movzx_addr as usize) {
                info!("[PLAYER_STATE] Breakpoint setup succeeded, waiting for trigger...");
                
                // Give the breakpoint some time to trigger (but don't block too long)
                std::thread::sleep(std::time::Duration::from_millis(50));

                // Check if we have captured runtime data
                if g_runtime_player_state_addr != 0 {
                    let player_state_value = g_runtime_player_state_value as u32;
                    info!("[PLAYER_STATE] SUCCESS! Runtime hook captured player state: {} from address 0x{:x}",
                          player_state_value, g_runtime_player_state_addr);
                    return Some((g_runtime_player_state_addr, player_state_value));
                } else {
                    info!("[PLAYER_STATE] Breakpoint was set but no data captured within 50ms timeout");
                }
                // If no data captured yet, continue to fallback methods
            } else {
                info!("[PLAYER_STATE] Failed to set up breakpoint at 0x{:x}", movzx_addr);
            }
        } else {
            info!("[PLAYER_STATE] No movzx address available (valid={}, addr=0x{:x})", movzx_valid, movzx_addr);
        }

        // Fallback: Check if player state data is valid (old method)
        // 🚨 CRITICAL FIX - Don't read player state when camera is inactive
        // This prevents memory access during save/load/death sequences
        if g_camera_active == 0 {
            return None;
        }

        if player_state_valid == 0 {
            return None;
        }

        // Check if we have a valid player state address and value
        if player_state_addr != 0 {
            let player_state_value: u32 = core::ptr::read_unaligned(core::ptr::addr_of!((*base).player_state_value));
            info!("[PLAYER_STATE] Rust DLL: Using fallback player state from position finder");
            Some((player_state_addr as usize, player_state_value))
        } else {
            None
        }
    }
}

// Safer memory reading function using ReadProcessMemory
fn read_memory_safe(addr: usize) -> Option<u8> {
    unsafe {
        
        let mut value: u8 = 0;
        let mut bytes_read: usize = 0;
        
        let result = ReadProcessMemory(
            GetCurrentProcess(),
            addr as *const _,
            &mut value as *mut _ as *mut _,
            1,
            &mut bytes_read
        );
        
        if result != 0 && bytes_read == 1 {
            Some(value)
        } else {
            let error_code = winapi::um::errhandlingapi::GetLastError();
            if error_code != 0 {
                info!("[PLAYER_STATE] ReadProcessMemory failed at 0x{:x}: error {}", addr, error_code);
            }
            None
        }
    }
}

// Read f32 value from memory safely
fn read_f32_from_memory(addr: usize) -> Option<f32> {
    unsafe {
        let mut value: [u8; 4] = [0; 4];
        let mut bytes_read: usize = 0;
        
        let result = ReadProcessMemory(
            GetCurrentProcess(),
            addr as *const _,
            value.as_mut_ptr() as *mut _,
            4,
            &mut bytes_read
        );
        
        if result != 0 && bytes_read == 4 {
            // Convert bytes to f32 (assuming little-endian)
            let float_val = f32::from_le_bytes(value);
            
            // Basic sanity check - magnesis coordinates should be reasonable values
            if float_val.is_finite() && float_val.abs() < 10000.0 {
                Some(float_val)
            } else {
                None
            }
        } else {
            None
        }
    }
}

// Check if a memory region is accessible
fn is_memory_region_accessible(addr: usize) -> bool {
    unsafe {
        
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        let result = VirtualQuery(
            addr as *const _,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>()
        );
        
        if result == 0 {
            return false;
        }
        
        // Check if memory is committed and readable
        (mbi.State & MEM_COMMIT) != 0
    }
}

// Software breakpoint approach for movzx instruction to capture r13 register
fn setup_movzx_runtime_hook(movzx_addr: usize) -> bool {
    unsafe {
        // Check if breakpoint is already set up
        if g_movzx_breakpoint_addr != 0 {
            info!("[PLAYER_STATE] Software breakpoint already set up");
            return true;
        }

        info!("[PLAYER_STATE] Setting up software breakpoint at movzx instruction: 0x{:x}", movzx_addr);

        // Read and save the original first byte
        if let Ok(original_byte) = std::panic::catch_unwind(|| {
            *(movzx_addr as *const u8)
        }) {
            g_original_movzx_byte = original_byte;
            g_movzx_breakpoint_addr = movzx_addr;

            // Set up vectored exception handler first
            let handler = AddVectoredExceptionHandler(1, Some(movzx_breakpoint_handler));
            if handler.is_null() {
                info!("[PLAYER_STATE] Failed to install exception handler");
                return false;
            }
            g_exception_handler = handler;

            // Make memory writable
            use winapi::um::memoryapi::VirtualProtect;
            use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
            let mut old_protect = 0u32;
            if VirtualProtect(movzx_addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect) == 0 {
                info!("[PLAYER_STATE] Failed to make memory writable");
                return false;
            }

            // Install software breakpoint (INT 3 = 0xCC)
            use winapi::um::memoryapi::WriteProcessMemory;
            use winapi::um::processthreadsapi::GetCurrentProcess;
            let breakpoint_byte = 0xCCu8;
            let mut bytes_written = 0usize;

            if WriteProcessMemory(
                GetCurrentProcess(),
                movzx_addr as *mut _,
                &breakpoint_byte as *const _ as *const _,
                1,
                &mut bytes_written
            ) != 0 && bytes_written == 1 {
                info!("[PLAYER_STATE] Software breakpoint installed successfully");

                // Restore original memory protection
                VirtualProtect(movzx_addr as *mut _, 1, old_protect, &mut old_protect);
                return true;
            } else {
                info!("[PLAYER_STATE] Failed to write breakpoint byte");
                // Restore original protection
                VirtualProtect(movzx_addr as *mut _, 1, old_protect, &mut old_protect);
            }
        } else {
            info!("[PLAYER_STATE] Failed to read original instruction byte");
        }

        false
    }
}

// Runtime hook function that executes when the movzx instruction is called
extern "C" fn movzx_runtime_hook() {
    unsafe {
        // Safety check: don't execute during early initialization
        if g_runtime_player_state_addr == 0 && g_movzx_breakpoint_addr == 0 {
            warn!("[PLAYER_STATE] Runtime hook called during initialization - this should not happen");
            return;
        }
        
        static mut HOOK_CALL_COUNT: u32 = 0;
        HOOK_CALL_COUNT += 1;

        // Only log every 60 calls to avoid spam (since this executes constantly)
        let should_log = HOOK_CALL_COUNT % 60 == 1;

        if should_log {
            info!("[PLAYER_STATE] Runtime hook called #{} times", HOOK_CALL_COUNT);
        }

        // Safely capture both r13 and rdx register values using inline assembly
        let r13_value: u64;
        let rdx_value: u64;
        core::arch::asm!(
            "mov {}, r13",
            "mov {}, rdx",
            out(reg) r13_value,
            out(reg) rdx_value,
            options(nostack, preserves_flags)
        );

        // Calculate final player state address using actual RDX value
        let final_addr = r13_value.wrapping_add(rdx_value).wrapping_add(0x770) as usize;

        // Try to read the player state value using ReadProcessMemory for safer access
        let state_value = read_memory_safe(final_addr).unwrap_or_else(|| {
            // Fallback to direct pointer access if ReadProcessMemory fails
            std::panic::catch_unwind(|| unsafe { *(final_addr as *const u8) })
                .unwrap_or(255u8)
        });

        // Store the results globally
        g_runtime_player_state_addr = final_addr;
        g_runtime_player_state_value = state_value;

        if should_log {
            info!("[PLAYER_STATE] Runtime hook: r13=0x{:x}, rdx=0x{:x}, offset=0x770, final_addr=0x{:x}, value={}",
                  r13_value, rdx_value, final_addr, state_value);
            info!("[PLAYER_STATE] Calculation: 0x{:x} + 0x{:x} + 0x770 = 0x{:x}",
                  r13_value, rdx_value, final_addr);
            
            // Check if memory is accessible
            if state_value == 255 {
                info!("[PLAYER_STATE] WARNING: Got default value 255, possible memory read failure at 0x{:x}", final_addr);
                // Try to check if the memory region is valid
                if is_memory_region_accessible(final_addr) {
                    info!("[PLAYER_STATE] Memory region appears accessible, read may have failed for other reasons");
                } else {
                    info!("[PLAYER_STATE] Memory region is not accessible");
                }
            }
        }

        // Note: With software breakpoints, the original instruction is restored in the exception handler
        // and execution continues naturally. No need to call a trampoline here.
    }
}

// Exception handler for software breakpoint
unsafe extern "system" fn movzx_breakpoint_handler(
    exception_info: *mut winapi::um::winnt::EXCEPTION_POINTERS
) -> i32 {
    use winapi::shared::minwindef::DWORD;
    use winapi::um::memoryapi::{VirtualProtect, WriteProcessMemory};
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

    const EXCEPTION_BREAKPOINT: DWORD = 0x80000003;
    const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
    const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

    if (*(*exception_info).ExceptionRecord).ExceptionCode == EXCEPTION_BREAKPOINT {
        let context = &mut *(*exception_info).ContextRecord;
        let exception_addr = context.Rip as usize;
        
        // Check if this is our breakpoint FIRST, before logging
        if exception_addr == g_movzx_breakpoint_addr {
            info!("[PLAYER_STATE] This is our breakpoint! Capturing R13 and RDX...");

            // Capture R13 and RDX register values from CPU context
            let r13_value = context.R13;
            let rdx_value = context.Rdx;

            // Calculate final address using actual R13 + RDX + offset
            let final_addr = r13_value.wrapping_add(rdx_value).wrapping_add(0x770) as usize;

            // Try to read player state value using safer method
            let state_value = read_memory_safe(final_addr).unwrap_or_else(|| {
                std::panic::catch_unwind(|| *(final_addr as *const u8)).unwrap_or(255u8)
            });

            // Store results globally
            g_runtime_player_state_addr = final_addr;
            g_runtime_player_state_value = state_value;

            info!("[PLAYER_STATE] Captured R13=0x{:x}, RDX=0x{:x}, calculated final_addr=0x{:x}, player_state={}",
                  r13_value, rdx_value, final_addr, state_value);

            // Restore original instruction byte
            let mut old_protect = 0u32;
            VirtualProtect(g_movzx_breakpoint_addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect);

            let mut bytes_written = 0usize;
            WriteProcessMemory(
                GetCurrentProcess(),
                g_movzx_breakpoint_addr as *mut _,
                &g_original_movzx_byte as *const _ as *const _,
                1,
                &mut bytes_written
            );

            VirtualProtect(g_movzx_breakpoint_addr as *mut _, 1, old_protect, &mut old_protect);

            info!("[PLAYER_STATE] Original instruction restored, continuing execution");

            // Reset breakpoint tracking so it can be set up again if needed
            g_movzx_breakpoint_addr = 0;

            // Continue execution from the same address (now with original instruction)
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    EXCEPTION_CONTINUE_SEARCH
}

// Call original movzx so game semantics continue
unsafe fn call_original_movzx() {
    // This function is currently not used in the software breakpoint approach
    // The original instruction is restored and execution continues naturally
    // Leaving this as a placeholder for future detour-based approaches
    warn!("[PLAYER_STATE] call_original_movzx called - this should not happen with software breakpoints");
}

// Software breakpoint approach for movbe instruction to capture r13 and rbx registers
fn setup_movbe_breakpoint(movbe_addr: usize) -> bool {
    unsafe {
        // Check if breakpoint is already set up
        if g_movbe_breakpoint_addr != 0 {
            return true;
        }

        // Read and save the original first byte
        if let Ok(original_byte) = std::panic::catch_unwind(|| {
            *(movbe_addr as *const u8)
        }) {
            g_original_movbe_byte = original_byte;
            g_movbe_breakpoint_addr = movbe_addr;

            // Set up vectored exception handler
            use winapi::um::errhandlingapi::AddVectoredExceptionHandler;
            let handler = AddVectoredExceptionHandler(1, Some(movbe_breakpoint_handler));
            if handler.is_null() {
                return false;
            }
            g_movbe_exception_handler = handler;

            // Make memory writable
            use winapi::um::memoryapi::VirtualProtect;
            use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
            let mut old_protect = 0u32;
            if VirtualProtect(movbe_addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect) == 0 {
                return false;
            }

            // Install software breakpoint (INT 3 = 0xCC)
            use winapi::um::memoryapi::WriteProcessMemory;
            use winapi::um::processthreadsapi::GetCurrentProcess;
            let breakpoint_byte = 0xCCu8;
            let mut bytes_written = 0usize;

            if WriteProcessMemory(
                GetCurrentProcess(),
                movbe_addr as *mut _,
                &breakpoint_byte as *const _ as *const _,
                1,
                &mut bytes_written
            ) != 0 && bytes_written == 1 {
                // Restore original memory protection
                VirtualProtect(movbe_addr as *mut _, 1, old_protect, &mut old_protect);
                return true;
            } else {
                // Restore original protection
                VirtualProtect(movbe_addr as *mut _, 1, old_protect, &mut old_protect);
            }
        }

        false
    }
}

// Exception handler for MOVBE breakpoint
unsafe extern "system" fn movbe_breakpoint_handler(
    exception_info: *mut winapi::um::winnt::EXCEPTION_POINTERS
) -> i32 {
    use winapi::shared::minwindef::DWORD;
    use winapi::um::memoryapi::{VirtualProtect, WriteProcessMemory};
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

    const EXCEPTION_BREAKPOINT: DWORD = 0x80000003;
    const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
    const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

    if (*(*exception_info).ExceptionRecord).ExceptionCode == EXCEPTION_BREAKPOINT {
        let context = &mut *(*exception_info).ContextRecord;
        let exception_addr = context.Rip as usize;
        
        // Check if this is our MOVBE breakpoint
        if exception_addr == g_movbe_breakpoint_addr {
            // Capture R13 and RBX register values from CPU context
            let r13_value = context.R13;
            let rbx_value = context.Rbx;
            
            // Calculate menu state address: R13 + RBX
            let menu_state_addr = r13_value.wrapping_add(rbx_value) as usize;
            
            // Store the result globally
            g_menu_state_address = menu_state_addr;
            
            println!("RUST DLL: MOVBE breakpoint hit! r13=0x{:x}, rbx=0x{:x}, menu_state_address=0x{:x}", 
                     r13_value, rbx_value, menu_state_addr);

            // Restore original instruction byte
            let mut old_protect = 0u32;
            VirtualProtect(g_movbe_breakpoint_addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect);

            let mut bytes_written = 0usize;
            WriteProcessMemory(
                GetCurrentProcess(),
                g_movbe_breakpoint_addr as *mut _,
                &g_original_movbe_byte as *const _ as *const _,
                1,
                &mut bytes_written
            );

            VirtualProtect(g_movbe_breakpoint_addr as *mut _, 1, old_protect, &mut old_protect);

            // Reset breakpoint tracking - menu only needs to be detected once
            g_movbe_breakpoint_addr = 0;

            // Continue execution from the same address (now with original instruction)
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    EXCEPTION_CONTINUE_SEARCH
}

// Magnesis breakpoint globals
static mut g_magnesis_breakpoint_addr: usize = 0;
static mut g_original_magnesis_byte: u8 = 0;
static mut g_magnesis_exception_handler: *mut winapi::ctypes::c_void = std::ptr::null_mut();

// When true, original magnesis detection is disabled in favor of experimental mode
static DISABLE_ORIGINAL_MAGNESIS: AtomicBool = AtomicBool::new(false);

/// Public API for experimental module to disable original magnesis detection completely
pub fn disable_original_magnesis_detection(disabled: bool) {
    DISABLE_ORIGINAL_MAGNESIS.store(disabled, Ordering::SeqCst);
    unsafe {
        // If disabling and an original breakpoint is currently active, restore it immediately
        if disabled && g_magnesis_breakpoint_addr != 0 && g_original_magnesis_byte != 0 {
            let mut old_protect = 0u32;
            if VirtualProtect(g_magnesis_breakpoint_addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect) != 0 {
                let mut bytes_written = 0usize;
                WriteProcessMemory(
                    GetCurrentProcess(),
                    g_magnesis_breakpoint_addr as *mut _,
                    &g_original_magnesis_byte as *const _ as *const _,
                    1,
                    &mut bytes_written
                );
                VirtualProtect(g_magnesis_breakpoint_addr as *mut _, 1, old_protect, &mut old_protect);
                info!("[MAGNESIS] Original breakpoint restored due to experimental mode");
            }
            if !g_magnesis_exception_handler.is_null() {
                RemoveVectoredExceptionHandler(g_magnesis_exception_handler);
                g_magnesis_exception_handler = std::ptr::null_mut();
            }
            g_magnesis_breakpoint_addr = 0;
            g_original_magnesis_byte = 0;
        }
    }
}

// Software breakpoint approach for magnesis X coordinate MOVBE instruction
fn setup_magnesis_x_breakpoint(magnesis_x_addr: usize) -> bool {
    // If experimental mode has disabled the original magnesis system, skip entirely
    if DISABLE_ORIGINAL_MAGNESIS.load(Ordering::SeqCst) {
        info!("[MAGNESIS] Original detection disabled by experimental mode - skipping original breakpoint setup");
        return false;
    }

    // Throttle noisy setup logs
    static mut LAST_MAGNESIS_SETUP_LOG: Option<std::time::Instant> = None;
    let mut should_log = true;
    unsafe {
        if let Some(t) = LAST_MAGNESIS_SETUP_LOG {
            if t.elapsed() < std::time::Duration::from_millis(1500) {
                should_log = false;
            }
        }
    }

    unsafe {
        // If we have an existing breakpoint, clean it up first
        if g_magnesis_breakpoint_addr != 0 {
            // Restore the original instruction before setting up new breakpoint
            let mut old_protect = 0u32;
            if VirtualProtect(g_magnesis_breakpoint_addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect) != 0 {
                let mut bytes_written = 0usize;
                WriteProcessMemory(
                    GetCurrentProcess(),
                    g_magnesis_breakpoint_addr as *mut _,
                    &g_original_magnesis_byte as *const _ as *const _,
                    1,
                    &mut bytes_written
                );
                VirtualProtect(g_magnesis_breakpoint_addr as *mut _, 1, old_protect, &mut old_protect);
            }
            
            // Remove the exception handler
            if !g_magnesis_exception_handler.is_null() {
                RemoveVectoredExceptionHandler(g_magnesis_exception_handler);
                g_magnesis_exception_handler = std::ptr::null_mut();
            }
            
            // Reset tracking variables
            g_magnesis_breakpoint_addr = 0;
            g_original_magnesis_byte = 0;
        }

        if should_log { info!("[MAGNESIS] Setting up breakpoint at X coordinate MOVBE: 0x{:x}", magnesis_x_addr); }

        // Read and save the original first byte
        if let Ok(original_byte) = std::panic::catch_unwind(|| {
            *(magnesis_x_addr as *const u8)
        }) {
            g_original_magnesis_byte = original_byte;
            g_magnesis_breakpoint_addr = magnesis_x_addr;

            // Set up vectored exception handler
            use winapi::um::errhandlingapi::AddVectoredExceptionHandler;
            let handler = AddVectoredExceptionHandler(1, Some(magnesis_breakpoint_handler));
            if handler.is_null() {
                info!("[MAGNESIS] Failed to install exception handler");
                return false;
            }
            g_magnesis_exception_handler = handler;

            // Make memory writable
            use winapi::um::memoryapi::VirtualProtect;
            use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
            let mut old_protect = 0u32;
            if VirtualProtect(magnesis_x_addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect) == 0 {
                info!("[MAGNESIS] Failed to make memory writable");
                return false;
            }

            // Install software breakpoint (INT 3 = 0xCC)
            use winapi::um::memoryapi::WriteProcessMemory;
            use winapi::um::processthreadsapi::GetCurrentProcess;
            let breakpoint_byte = 0xCCu8;
            let mut bytes_written = 0usize;

            if WriteProcessMemory(
                GetCurrentProcess(),
                magnesis_x_addr as *mut _,
                &breakpoint_byte as *const _ as *const _,
                1,
                &mut bytes_written
            ) != 0 && bytes_written == 1 {
                // Restore original memory protection
                VirtualProtect(magnesis_x_addr as *mut _, 1, old_protect, &mut old_protect);
                // Log rarely to avoid spam
                // Reduce log spam for working breakpoint installations
                // if should_log { info!("[MAGNESIS] Breakpoint installed successfully"); }
                unsafe { LAST_MAGNESIS_SETUP_LOG = Some(std::time::Instant::now()); }
                return true;
            } else {
                info!("[MAGNESIS] Failed to write breakpoint byte");
                // Restore original protection
                VirtualProtect(magnesis_x_addr as *mut _, 1, old_protect, &mut old_protect);
            }
        } else {
            info!("[MAGNESIS] Failed to read original instruction byte");
        }

        false
    }
}

// Exception handler for magnesis X coordinate breakpoint
unsafe extern "system" fn magnesis_breakpoint_handler(
    exception_info: *mut winapi::um::winnt::EXCEPTION_POINTERS
) -> i32 {
    use winapi::shared::minwindef::DWORD;
    use winapi::um::memoryapi::{VirtualProtect, WriteProcessMemory};
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

    const EXCEPTION_BREAKPOINT: DWORD = 0x80000003;
    const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
    const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

    if (*(*exception_info).ExceptionRecord).ExceptionCode == EXCEPTION_BREAKPOINT {
        let context = &mut *(*exception_info).ContextRecord;
        let exception_addr = context.Rip as usize;
        
        // Check if this is our magnesis breakpoint
        if exception_addr == g_magnesis_breakpoint_addr {
            // Magnesis X coordinate is being updated - magnesis is active!
            track_magnesis_update();
            
            // Log magnesis detection (throttled but informative)
            static mut LAST_MAGNESIS_LOG: Option<std::time::Instant> = None;
            static mut UPDATE_COUNT: u32 = 0;
            UPDATE_COUNT += 1;
            
            let should_log = LAST_MAGNESIS_LOG.map_or(true, |t| t.elapsed() > std::time::Duration::from_millis(500));
            if should_log {
                if let Some(session_start) = g_magnesis_session_start_time {
                    let session_time = session_start.elapsed().as_millis();
                    if session_time < 2000 {
                        info!("[MAGNESIS] Update #{} detected - INVINCIBILITY ACTIVE ({}ms elapsed)", UPDATE_COUNT, session_time);
                    } else {
                        // Reduce spam for post-invincibility updates - only log every 30th update
                        if UPDATE_COUNT % 30 == 0 {
                            info!("[MAGNESIS] Update #{} detected - magnesis ACTIVE (post-invincibility)", UPDATE_COUNT);
                        }
                    }
                } else {
                    info!("[MAGNESIS] Update #{} detected - magnesis is ACTIVE", UPDATE_COUNT);
                }
                LAST_MAGNESIS_LOG = Some(std::time::Instant::now());
            }
            
            // Restore original instruction byte temporarily
            let mut old_protect = 0u32;
            VirtualProtect(g_magnesis_breakpoint_addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect);

            let mut bytes_written = 0usize;
            WriteProcessMemory(
                GetCurrentProcess(),
                g_magnesis_breakpoint_addr as *mut _,
                &g_original_magnesis_byte as *const _ as *const _,
                1,
                &mut bytes_written
            );

            VirtualProtect(g_magnesis_breakpoint_addr as *mut _, 1, old_protect, &mut old_protect);

            // Execute the original instruction by continuing
            context.Rip = g_magnesis_breakpoint_addr as u64;
            
            // Reset breakpoint tracking so it can be re-established by main loop
            g_magnesis_breakpoint_addr = 0;
            
            // Continue execution from the same address (now with original instruction)
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    EXCEPTION_CONTINUE_SEARCH
}

// Simple magnesis detection - track updates for detection only
fn track_magnesis_update() {
    unsafe {
        let now = std::time::Instant::now();
        g_magnesis_update_count += 1;
        g_magnesis_last_update_time = Some(now);
        
        if !g_magnesis_enabled_state {
            g_magnesis_enabled_state = true;
            g_magnesis_session_start_time = Some(now);
            g_magnesis_just_enabled = true;
        }
    }
}

// Simple timeout check for magnesis detection
fn check_magnesis_timeout() {
    unsafe {
        if !g_magnesis_enabled_state {
            return;
        }

        // Do not disable during the post-enable invincibility window
        if let Some(start) = g_magnesis_session_start_time {
            if start.elapsed() < std::time::Duration::from_secs(MAGNESIS_INVINCIBILITY_SECS) {
                return;
            }
        }

        // After the window ends, only disable if we miss updates for the configured timeout
        match g_magnesis_last_update_time {
            Some(last) => {
                if last.elapsed() > MAGNESIS_UPDATE_TIMEOUT {
                    g_magnesis_enabled_state = false;
                    g_magnesis_session_start_time = None;
                    info!(
                        "[MAGNESIS] DISABLED - No updates for {}ms (post-window)",
                        MAGNESIS_UPDATE_TIMEOUT.as_millis()
                    );
                }
            }
            None => {
                // Shouldn't happen while enabled, but be safe post-window
                g_magnesis_enabled_state = false;
                g_magnesis_session_start_time = None;
                info!("[MAGNESIS] DISABLED - No update timestamp available (post-window)");
            }
        }
    }
}

// Simple magnesis detection monitoring
fn update_magnesis_monitoring() {
    unsafe {
        // Logging when magnesis is first detected
        if g_magnesis_just_enabled {
            info!("[MAGNESIS] ENABLED - Rune detected");
            println!("MAGNESIS ACTIVE: Rune is active, camera control disabled");
            g_magnesis_just_enabled = false;
        }
        
        check_magnesis_timeout();
    }
}

// Simple magnesis detection function
pub fn should_magnesis_control_mouse() -> bool {
    unsafe {
        g_magnesis_enabled_state
    }
}

// Stub functions for compatibility (no longer used)
pub fn apply_magnesis_mouse_control(_delta_x: f32, _delta_y: f32, _wheel_delta: f32) {
    // No longer needed - mouse control stays with game when magnesis is active
}

// Reset camera completely (like re-enabling the mod)
fn reset_camera_completely() {
    unsafe {
        println!("RUST DLL: Performing complete camera reset...");
        
        // Reset orbit camera by clearing global instance
        let mut orbit_guard = camera::ORBIT_CAMERA.lock().unwrap();
        *orbit_guard = None;
        drop(orbit_guard); // Release the lock
        
        // Reset aim blend and offsets
        g_aim_blend = 0.0;
        g_aim_offset_x = 0.0;
        g_aim_offset_y = 0.0;
        g_aim_offset_z = 0.0;
        
        // Reset player state tracking
        g_last_aim_state = 0;
        g_previous_player_state = 0;
        
        println!("RUST DLL: Camera reset complete - camera state cleared");
    }
}

// Read 4-byte big-endian menu state from calculated address
fn read_menu_state() -> Option<u32> {
    unsafe {
        if g_menu_state_address == 0 {
            return None;
        }

        if let Ok(bytes) = std::panic::catch_unwind(|| {
            let ptr = g_menu_state_address as *const u8;
            std::slice::from_raw_parts(ptr, 4)
        }) {
            // Read as big-endian 4-byte value
            let menu_state = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            Some(menu_state)
        } else {
            None
        }
    }
}

// Public accessor for current menu open state (derived from lib.rs menu detection)
pub fn is_menu_open_now() -> bool {
    matches!(read_menu_state(), Some(3))
}

// Monitor menu state transitions and trigger movzx re-check on menu close (3->2)
fn check_menu_state_transitions() {
    if let Some(current_state) = read_menu_state() {
        unsafe {
            // Check for menu close transition (3 -> 2)
            if g_last_menu_state == 3 && current_state == 2 {
                println!("RUST DLL: Menu closed detected (3->2), re-checking movzx R13+RDX values...");
                
                // Get movzx address from shared memory
                if let Some((movzx_addr, _)) = get_player_state_from_shared_memory() {
                    if let Some(movzx_instruction_addr) = get_movzx_address_from_shared_memory() {
                        println!("RUST DLL: Setting up movzx re-check breakpoint at 0x{:x}", movzx_instruction_addr);
                        
                        if setup_movzx_recheck_breakpoint(movzx_instruction_addr) {
                            println!("RUST DLL: Movzx re-check breakpoint set up successfully");
                        } else {
                            println!("RUST DLL: Failed to set up movzx re-check breakpoint");
                        }
                    }
                }
            }
            
            // Update last state for next comparison
            g_last_menu_state = current_state as u8;
        }
    }
}

// Get magnesis X instruction address from shared memory
fn get_magnesis_x_address_from_shared_memory() -> Option<usize> {
    unsafe {
        if g_shared_position_data.is_null() {
            return None;
        }
        
        let shared_data = &*g_shared_position_data;
        if shared_data.magnesis_instruction_valid != 0 && shared_data.magnesis_instruction_address != 0 {
            Some(shared_data.magnesis_instruction_address as usize)
        } else {
            None
        }
    }
}

// Get movzx instruction address from shared memory
fn get_movzx_address_from_shared_memory() -> Option<usize> {
    unsafe {
        if g_shared_position_data.is_null() {
            return None;
        }
        
        let shared_data = &*g_shared_position_data;
        let ready = (shared_data.ready_flags & READY_MOVZX) != 0;
        if (shared_data.movzx_instruction_valid != 0 || ready) && shared_data.movzx_instruction_address != 0 {
            Some(shared_data.movzx_instruction_address as usize)
        } else {
            None
        }
    }
}

// Set up breakpoint for movzx re-check (similar to original movzx breakpoint)
fn setup_movzx_recheck_breakpoint(movzx_addr: usize) -> bool {
    unsafe {
        // Check if breakpoint is already set up
        if g_movzx_recheck_breakpoint_addr != 0 {
            return true;
        }

        // Read and save the original first byte
        if let Ok(original_byte) = std::panic::catch_unwind(|| {
            *(movzx_addr as *const u8)
        }) {
            g_original_movzx_recheck_byte = original_byte;
            g_movzx_recheck_breakpoint_addr = movzx_addr;

            // Set up vectored exception handler
            use winapi::um::errhandlingapi::AddVectoredExceptionHandler;
            let handler = AddVectoredExceptionHandler(1, Some(movzx_recheck_breakpoint_handler));
            if handler.is_null() {
                return false;
            }
            g_movzx_recheck_exception_handler = handler;

            // Make memory writable
            use winapi::um::memoryapi::VirtualProtect;
            use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
            let mut old_protect = 0u32;
            if VirtualProtect(movzx_addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect) == 0 {
                return false;
            }

            // Install software breakpoint (INT 3 = 0xCC)
            use winapi::um::memoryapi::WriteProcessMemory;
            use winapi::um::processthreadsapi::GetCurrentProcess;
            let breakpoint_byte = 0xCCu8;
            let mut bytes_written = 0usize;

            if WriteProcessMemory(
                GetCurrentProcess(),
                movzx_addr as *mut _,
                &breakpoint_byte as *const _ as *const _,
                1,
                &mut bytes_written
            ) != 0 && bytes_written == 1 {
                // Restore original memory protection
                VirtualProtect(movzx_addr as *mut _, 1, old_protect, &mut old_protect);
                return true;
            } else {
                // Restore original protection
                VirtualProtect(movzx_addr as *mut _, 1, old_protect, &mut old_protect);
            }
        }

        false
    }
}

// Exception handler for movzx re-check breakpoint
unsafe extern "system" fn movzx_recheck_breakpoint_handler(
    exception_info: *mut winapi::um::winnt::EXCEPTION_POINTERS
) -> i32 {
    use winapi::shared::minwindef::DWORD;
    use winapi::um::memoryapi::{VirtualProtect, WriteProcessMemory};
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

    const EXCEPTION_BREAKPOINT: DWORD = 0x80000003;
    const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
    const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

    if (*(*exception_info).ExceptionRecord).ExceptionCode == EXCEPTION_BREAKPOINT {
        let context = &mut *(*exception_info).ContextRecord;
        let exception_addr = context.Rip as usize;
        
        // Check if this is our movzx re-check breakpoint
        if exception_addr == g_movzx_recheck_breakpoint_addr {
            // Capture R13 and RDX register values from CPU context
            let r13_value = context.R13;
            let rdx_value = context.Rdx;
            
            // Calculate new player state address (R13 + RDX + 0x770)
            let new_player_state_addr = r13_value.wrapping_add(rdx_value).wrapping_add(0x770) as usize;
            
            println!("RUST DLL: Movzx re-check breakpoint hit! r13=0x{:x}, rdx=0x{:x}", 
                     r13_value, rdx_value);
            println!("RUST DLL: New calculated player state address: 0x{:x}", new_player_state_addr);
            
            // Check if player state address changed
            if g_stored_player_state_address != 0 && g_stored_player_state_address != new_player_state_addr {
                println!("RUST DLL: Player state address CHANGED! Old: 0x{:x}, New: 0x{:x}", 
                         g_stored_player_state_address, new_player_state_addr);
                println!("RUST DLL: Resetting camera completely...");
                
                // Reset camera like re-enabling it
                reset_camera_completely();
                
                // Update global player state variables to use the new address
                g_runtime_player_state_addr = new_player_state_addr;
                g_player_state_address = new_player_state_addr;
                println!("RUST DLL: Updated global player state address to: 0x{:x}", new_player_state_addr);
            } else if g_stored_player_state_address == new_player_state_addr {
                println!("RUST DLL: Player state address unchanged: 0x{:x}", new_player_state_addr);
            }
            
            // Update stored address for future comparisons
            g_stored_player_state_address = new_player_state_addr;

            // Restore original instruction byte
            let mut old_protect = 0u32;
            VirtualProtect(g_movzx_recheck_breakpoint_addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect);

            let mut bytes_written = 0usize;
            WriteProcessMemory(
                GetCurrentProcess(),
                g_movzx_recheck_breakpoint_addr as *mut _,
                &g_original_movzx_recheck_byte as *const _ as *const _,
                1,
                &mut bytes_written
            );

            VirtualProtect(g_movzx_recheck_breakpoint_addr as *mut _, 1, old_protect, &mut old_protect);

            // Reset breakpoint tracking
            g_movzx_recheck_breakpoint_addr = 0;

            // Continue execution from the same address (now with original instruction)
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    EXCEPTION_CONTINUE_SEARCH
}

// Set up breakpoint on PhoneCamera (photo mode) cmpxchg instruction to capture RBX register
fn setup_phonecamera_lock_breakpoint(cmpxchg_addr: usize) -> bool {
    unsafe {
        // Check if breakpoint is already set up
        if g_phonecamera_cmpxchg_breakpoint_addr != 0 {
            return true;
        }

        info!("[PHONECAMERA] Setting up breakpoint at phonecamera cmpxchg instruction: 0x{:x}", cmpxchg_addr);

        // Read and save the original first byte
        if let Ok(original_byte) = std::panic::catch_unwind(|| {
            *(cmpxchg_addr as *const u8)
        }) {
            g_original_phonecamera_cmpxchg_byte = original_byte;
            g_phonecamera_cmpxchg_breakpoint_addr = cmpxchg_addr;

            // Set up vectored exception handler
            use winapi::um::errhandlingapi::AddVectoredExceptionHandler;
            let handler = AddVectoredExceptionHandler(1, Some(phonecamera_lock_breakpoint_handler));
            if handler.is_null() {
                info!("[PHONECAMERA] Failed to install exception handler");
                return false;
            }
            g_phonecamera_cmpxchg_exception_handler = handler;

            // Make memory writable
            use winapi::um::memoryapi::VirtualProtect;
            use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
            let mut old_protect = 0u32;
            if VirtualProtect(cmpxchg_addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect) == 0 {
                info!("[PHONECAMERA] Failed to make memory writable");
                return false;
            }

            // Install software breakpoint (INT 3 = 0xCC)
            use winapi::um::memoryapi::WriteProcessMemory;
            use winapi::um::processthreadsapi::GetCurrentProcess;
            let breakpoint_byte = 0xCCu8;
            let mut bytes_written = 0usize;

            if WriteProcessMemory(
                GetCurrentProcess(),
                cmpxchg_addr as *mut _,
                &breakpoint_byte as *const _ as *const _,
                1,
                &mut bytes_written
            ) != 0 && bytes_written == 1 {
                // Restore original memory protection
                VirtualProtect(cmpxchg_addr as *mut _, 1, old_protect, &mut old_protect);
                info!("[PHONECAMERA] Phonecamera cmpxchg breakpoint installed successfully");
                
                // Enable phonecamera logging for state changes
                g_phonecamera_logging_enabled = true;
                
                return true;
            } else {
                info!("[PHONECAMERA] Failed to write breakpoint byte");
                // Restore original protection
                VirtualProtect(cmpxchg_addr as *mut _, 1, old_protect, &mut old_protect);
            }
        } else {
            info!("[CAMERA] Failed to read original instruction byte");
        }

        false
    }
}

// Exception handler for PhoneCamera cmpxchg breakpoint
unsafe extern "system" fn phonecamera_lock_breakpoint_handler(
    exception_info: *mut winapi::um::winnt::EXCEPTION_POINTERS
) -> i32 {
    use winapi::shared::minwindef::DWORD;
    use winapi::um::memoryapi::{VirtualProtect, WriteProcessMemory};
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

    const EXCEPTION_BREAKPOINT: DWORD = 0x80000003;
    const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
    const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

    if (*(*exception_info).ExceptionRecord).ExceptionCode == EXCEPTION_BREAKPOINT {
        let context = &mut *(*exception_info).ContextRecord;
        let exception_addr = context.Rip as usize;
        
        // Check if this is our phonecamera breakpoint
        if exception_addr == g_phonecamera_cmpxchg_breakpoint_addr {
            // Capture R13 and RDX register values from CPU context
            let r13_value = context.R13;
            let rdx_value = context.Rdx;
            
            // Calculate phonecamera flag address: R13 + RDX + 0x0C (confirmed simpler flag)
            let phonecamera_flag_addr = r13_value.wrapping_add(rdx_value).wrapping_add(0x0C) as usize;
            
            // Store the address globally
            g_phonecamera_flag_addr = phonecamera_flag_addr;
            
            info!("[PHONECAMERA] Breakpoint hit! r13=0x{:x}, rdx=0x{:x}", r13_value, rdx_value);
            info!("[PHONECAMERA] Computed flag address (0x0C offset): 0x{:x}", phonecamera_flag_addr);
            println!("RUST DLL: PhoneCamera flag address computed: 0x{:x} (R13+RDX+0x0C)", 
                     phonecamera_flag_addr);

            // Restore original instruction byte
            let mut old_protect = 0u32;
            VirtualProtect(g_phonecamera_cmpxchg_breakpoint_addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect);

            let mut bytes_written = 0usize;
            WriteProcessMemory(
                GetCurrentProcess(),
                g_phonecamera_cmpxchg_breakpoint_addr as *mut _,
                &g_original_phonecamera_cmpxchg_byte as *const _ as *const _,
                1,
                &mut bytes_written
            );

            VirtualProtect(g_phonecamera_cmpxchg_breakpoint_addr as *mut _, 1, old_protect, &mut old_protect);

            // Remove exception handler
            if !g_phonecamera_cmpxchg_exception_handler.is_null() {
                use winapi::um::errhandlingapi::RemoveVectoredExceptionHandler;
                RemoveVectoredExceptionHandler(g_phonecamera_cmpxchg_exception_handler);
                g_phonecamera_cmpxchg_exception_handler = std::ptr::null_mut();
            }

            // Reset breakpoint tracking - phonecamera flag address only needs to be detected once
            g_phonecamera_cmpxchg_breakpoint_addr = 0;

            // Continue execution from the same address (now with original instruction)
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    EXCEPTION_CONTINUE_SEARCH
}


#[repr(C)]
struct MemoryRegion {
    start: usize,
    size: usize,
}

// Get actual large regions that exist, regardless of protection type
fn get_actual_large_regions() -> Vec<(usize, usize)> {
    unsafe {
        use winapi::um::memoryapi::VirtualQuery;
        use winapi::um::winnt::MEMORY_BASIC_INFORMATION;

        let mut addr = 0x10000usize;
        let max_addr = 0x7FFFFFFFusize;
        let mut large_regions = Vec::new();

        while addr < max_addr {
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let result = VirtualQuery(
                addr as *const _,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            if result == 0 {
                addr += 0x10000;
                continue;
            }

            let region_size = mbi.RegionSize as usize;
            let region_start = mbi.BaseAddress as usize;

            // Collect large regions (>100MB) regardless of protection
            if region_size > 100 * 1024 * 1024 {
                large_regions.push((region_start, region_size));
            }

            addr = region_start + region_size;
        }

        large_regions
    }
}



// Debug function to list all large memory regions
fn debug_large_regions() {
    unsafe {
        use winapi::um::memoryapi::VirtualQuery;
        use winapi::um::winnt::{MEMORY_BASIC_INFORMATION, PAGE_READWRITE, MEM_COMMIT, MEM_PRIVATE};

        info!("=== DEBUG: Scanning all large memory regions ===");
        let mut addr = 0x10000usize;
        let max_addr = 0x7FFFFFFFusize;
        let mut large_regions = Vec::new();

        while addr < max_addr {
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let result = VirtualQuery(
                addr as *const _,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            if result == 0 {
                addr += 0x10000;
                continue;
            }

            let region_size = mbi.RegionSize as usize;
            let region_start = mbi.BaseAddress as usize;

            // Log large regions (>100MB)
            if region_size > 100 * 1024 * 1024 {
                let committed = if mbi.State == MEM_COMMIT { "COMMIT" } else { "OTHER" };
                let private = if mbi.Type == MEM_PRIVATE { "PRIVATE" } else { "OTHER" };
                let protect = if mbi.Protect == PAGE_READWRITE { "RW" } else { "OTHER" };

                large_regions.push((region_start, region_size));
                info!("Large region: 0x{:x} size=0x{:x} ({:.1}GB) state={} type={} protect={}",
                      region_start, region_size, region_size as f64 / 1024.0 / 1024.0 / 1024.0,
                      committed, private, protect);
            }

            addr = region_start + region_size;
        }

        info!("Found {} large regions (>100MB)", large_regions.len());
    }
}

// Find ALL committed regions regardless of size (comprehensive search)
fn find_all_committed_regions() -> Vec<(usize, usize)> {
    unsafe {
        use winapi::um::memoryapi::VirtualQuery;
        use winapi::um::winnt::{MEMORY_BASIC_INFORMATION, MEM_COMMIT};

        let mut addr = 0x10000usize;
        let max_addr = 0x7FFFFFFFusize;
        let mut committed_regions = Vec::new();

        info!("=== Scanning for ALL committed regions ===");

        while addr < max_addr {
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let result = VirtualQuery(
                addr as *const _,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            if result == 0 {
                addr += 0x10000;
                continue;
            }

            let region_size = mbi.RegionSize as usize;
            let region_start = mbi.BaseAddress as usize;

            // Collect ALL committed regions that are at least 1MB
            if mbi.State == MEM_COMMIT && region_size >= 0x100000 {
                let protect_str = match mbi.Protect {
                    4 => "RW",      // PAGE_READWRITE
                    64 => "RWX",    // PAGE_EXECUTE_READWRITE
                    32 => "RX",     // PAGE_EXECUTE_READ
                    2 => "R",       // PAGE_READONLY
                    _ => &format!("0x{:x}", mbi.Protect)
                };

                info!("Committed region: 0x{:x} size=0x{:x} ({:.1}MB) protect={}",
                      region_start, region_size, region_size as f64 / 1024.0 / 1024.0, protect_str);

                committed_regions.push((region_start, region_size));
            }

            addr = region_start + region_size;
            if addr <= region_start {
                addr += 0x10000;
            }

            // Safety limit
            if committed_regions.len() > 100 {
                info!("Stopping search after 100 regions to avoid spam");
                break;
            }
        }

        info!("Found {} total committed regions (>=1MB)", committed_regions.len());
        committed_regions
    }
}

// Find ANY large region regardless of protection (fallback method)
fn find_any_large_region() -> Option<(usize, usize)> {
    unsafe {
        use winapi::um::memoryapi::VirtualQuery;
        use winapi::um::winnt::{MEMORY_BASIC_INFORMATION, MEM_COMMIT};

        let mut addr = 0x10000usize;
        let max_addr = 0x7FFFFFFFusize;
        let mut largest_region: Option<(usize, usize)> = None;
        let mut largest_size = 0usize;

        while addr < max_addr {
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let result = VirtualQuery(
                addr as *const _,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            if result == 0 {
                addr += 0x10000;
                continue;
            }

            let region_size = mbi.RegionSize as usize;
            let region_start = mbi.BaseAddress as usize;

            // Find the largest committed region (any protection type)
            if region_size >= 0x4000000 && // >= 64MB minimum
               mbi.State == MEM_COMMIT &&
               region_size > largest_size {
                largest_size = region_size;
                largest_region = Some((region_start, region_size));
                info!("Found large region candidate: 0x{:x} size=0x{:x} ({:.1}MB)",
                      region_start, region_size, region_size as f64 / 1024.0 / 1024.0);
            }

            addr = region_start + region_size;
            if addr <= region_start {
                addr += 0x10000;
            }
        }

        if let Some((start, size)) = largest_region {
            info!("Selected largest region: 0x{:x} size=0x{:x} ({:.1}MB)",
                  start, size, size as f64 / 1024.0 / 1024.0);
        }

        largest_region
    }
}

// Find region in Cemu's process space using botw_editor's exact criteria
fn find_cemu_region_by_size(target_size: usize) -> Option<(usize, usize)> {
    unsafe {
        use winapi::um::memoryapi::VirtualQuery;
        use winapi::um::winnt::{MEMORY_BASIC_INFORMATION, PAGE_READWRITE, MEM_COMMIT};

        let mut addr = 0x10000usize; // Start from a reasonable base
        let max_addr = 0x7FFFFFFFusize; // Don't go into kernel space

        while addr < max_addr {
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let result = VirtualQuery(
                addr as *const _,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            if result == 0 {
                addr += 0x10000; // Skip ahead if query failed
                continue;
            }

            let region_size = mbi.RegionSize as usize;
            let region_start = mbi.BaseAddress as usize;

            // botw_editor's exact criteria: exact size match, PAGE_READWRITE, MEM_COMMIT
            if region_size == target_size
                && mbi.Protect == PAGE_READWRITE
                && mbi.State == MEM_COMMIT {
                info!("Found Cemu region: start=0x{:x}, size=0x{:x} ({:.1}GB), protect=RW, state=COMMIT",
                      region_start, region_size, region_size as f64 / 1024.0 / 1024.0 / 1024.0);
                return Some((region_start, region_size));
            }

            // Skip to next region
            addr = region_start + region_size;

            // Prevent infinite loop
            if addr <= region_start {
                addr += 0x10000;
            }
        }

        None
    }
}

// Direct memory search within Cemu process (no external process access needed)
fn search_cemu_memory_direct(pattern: &[i32], start_addr: usize, region_size: usize) -> Option<usize> {
    info!("Searching Cemu memory directly at 0x{:x} (size: 0x{:x})", start_addr, region_size);

    let end_addr = start_addr + region_size;
    let mut addr = start_addr;
    let chunk_size = 1024 * 1024; // 1MB chunks for direct access

    while addr < end_addr {
        let search_size = std::cmp::min(chunk_size, end_addr - addr);

        // Direct memory access - we're in Cemu's process space
        unsafe {
            let memory_slice = std::slice::from_raw_parts(addr as *const u8, search_size);

            // Search for pattern in this chunk
            if let Some(offset) = find_pattern_in_slice(memory_slice, pattern) {
                let found_addr = addr + offset;
                info!("Found pattern in Cemu memory at 0x{:x}", found_addr);
                return Some(found_addr);
            }
        }

        addr += search_size;
    }

    None
}

// Find pattern in memory slice (direct memory access)
fn find_pattern_in_slice(memory: &[u8], pattern: &[i32]) -> Option<usize> {
    if pattern.len() > memory.len() {
        return None;
    }

    for i in 0..=(memory.len() - pattern.len()) {
        let mut matches = true;

        for (j, &pattern_byte) in pattern.iter().enumerate() {
            if pattern_byte == -1 {
                continue; // Wildcard
            }

            if memory[i + j] != pattern_byte as u8 {
                matches = false;
                break;
            }
        }

        if matches {
            return Some(i);
        }
    }

    None
}

fn get_memory_regions(_proc_inf: &ProcessInfo) -> Result<Vec<MemoryRegion>, Box<dyn std::error::Error>> {
    unsafe {
        use winapi::um::memoryapi::VirtualQuery;
        use winapi::um::winnt::{MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE, MEM_COMMIT, MEM_PRIVATE};

        let mut regions = Vec::new();
        let mut addr = 0x10000000usize; // Start from a reasonable base address
        let max_addr = 0x7FFFFFFFusize; // Don't go into kernel space

        while addr < max_addr {
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let result = VirtualQuery(
                addr as *const _,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            if result == 0 {
                addr += 0x10000; // Skip ahead
                continue;
            }

            // Check if this region is suitable for coordinates (readable, committed, private)
            let is_readable = matches!(mbi.Protect,
                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READONLY | PAGE_READWRITE);
            let is_committed = mbi.State == MEM_COMMIT;
            let is_private = mbi.Type == MEM_PRIVATE;
            let size = mbi.RegionSize as usize;

            if is_readable && is_committed && is_private && size >= 4096 && size <= 0x8000000 {
                regions.push(MemoryRegion {
                    start: mbi.BaseAddress as usize,
                    size: size,
                });
            }

            addr = mbi.BaseAddress as usize + size;
        }

        info!("Found {} readable memory regions", regions.len());
        Ok(regions)
    }
}

fn scan_for_coordinates(start_addr: usize, size: usize) -> Option<usize> {
    let end_addr = start_addr + size;
    let mut addr = start_addr;

    // Scan for 3 consecutive floats that look like coordinates
    while addr + 12 <= end_addr {
        if let Some((x, y, z)) = read_coordinates_at(addr) {
            // Check if these look like reasonable BOTW coordinates
            if is_reasonable_coordinate(x, y, z) {
                return Some(addr);
            }
        }
        addr += 4; // Move by float size for alignment
    }

    None
}

pub fn is_reasonable_coordinate(x: f32, y: f32, z: f32) -> bool {
    // BOTW world coordinates are roughly in these ranges:
    // X: -5000 to 5000
    // Y: -500 to 2000 (below ground to high mountains)
    // Z: -5000 to 5000
    let x_ok = x > -6000.0 && x < 6000.0 && x.is_finite();
    let y_ok = y > -1000.0 && y < 3000.0 && y.is_finite();
    let z_ok = z > -6000.0 && z < 6000.0 && z.is_finite();

    // All coordinates should be reasonable values, not zero/default
    let not_zero = (x.abs() > 1.0) || (y.abs() > 1.0) || (z.abs() > 1.0);

    x_ok && y_ok && z_ok && not_zero
}

fn verify_coordinate_address(addr: usize) -> bool {
    // Read coordinates multiple times to see if they change (indicating active position)
    let mut positions = Vec::new();

    for _ in 0..5 {
        if let Some(pos) = read_coordinates_at(addr) {
            positions.push(pos);
        } else {
            return false; // Can't read consistently
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    if positions.len() < 5 {
        return false;
    }

    // Check if position changed (Link is moving) OR if it's a stable reasonable position
    let first = positions[0];
    let mut changed = false;
    for pos in &positions[1..] {
        let dist = ((pos.0 - first.0).powi(2) + (pos.1 - first.1).powi(2) + (pos.2 - first.2).powi(2)).sqrt();
        if dist > 0.1 { // Position changed by more than 10cm
            changed = true;
            break;
        }
    }

    // Valid if position is stable and reasonable, or if it's moving
    let reasonable = is_reasonable_coordinate(first.0, first.1, first.2);
    reasonable && (changed || first.1 > -100.0) // Accept stable positions above ground level
}

// Exact copy of the C# editor's paged memory search
fn paged_memory_search_match(pattern: &[i32], start_address: usize, region_size: usize) -> Option<usize> {
    info!("Starting paged memory search...");

    let end_address = start_address + region_size;
    let mut current_address = start_address;

    // Use 64KB pages like Windows memory management
    let page_size = 0x10000usize;
    let mut pages_checked = 0;
    let mut pages_accessible = 0;

    while current_address < end_address {
        // Check if this page is accessible
        if is_memory_readable(current_address) {
            pages_accessible += 1;

            // Search within this page
            let search_end = std::cmp::min(current_address + page_size, end_address);

            if let Some(found_addr) = find_sequence_in_page(pattern, current_address, search_end) {
                info!("Found pattern at 0x{:x} (checked {} pages, {} accessible)",
                      found_addr, pages_checked, pages_accessible);
                return Some(found_addr);
            }
        }

        current_address += page_size;
        pages_checked += 1;

        // Progress logging every 1000 pages
        if pages_checked % 1000 == 0 {
            info!("Checked {} pages, {} accessible...", pages_checked, pages_accessible);
        }
    }

    info!("Pattern not found. Checked {} pages, {} were accessible", pages_checked, pages_accessible);
    None
}

// Find sequence within a single memory page
fn find_sequence_in_page(pattern: &[i32], start_addr: usize, end_addr: usize) -> Option<usize> {
    unsafe {
        let mut addr = start_addr;

        while addr + pattern.len() <= end_addr {
            let mut matches = true;

            // Check each byte in pattern
            for (i, &pattern_byte) in pattern.iter().enumerate() {
                if pattern_byte == -1 {
                    // Wildcard - skip
                    continue;
                }

                let memory_ptr = (addr + i) as *const u8;
                if memory_ptr.is_null() {
                    matches = false;
                    break;
                }

                // Safe read with error handling
                let memory_byte = match std::panic::catch_unwind(|| {
                    std::ptr::read_volatile(memory_ptr)
                }) {
                    Ok(byte) => byte as i32,
                    Err(_) => {
                        matches = false;
                        break;
                    }
                };

                if memory_byte != pattern_byte {
                    matches = false;
                    break;
                }
            }

            if matches {
                return Some(addr);
            }

            addr += 1;
        }

        None
    }
}

// Note: The R13 capture and player state calculation is now handled by the existing
// movzx_runtime_hook function above, which already does exactly what we need.



// Calculate player state address by testing different RDX values and offsets
fn calculate_player_state_address(r13_value: u64) -> Option<(u64, u64, u64)> {
    // Test different RDX values and offsets to find the one that gives valid player state
    let rdx_candidates = [
        0x44E54200u64,  // Original hardcoded value
        0x0,            // No RDX offset
        0x4,            // Small offsets
        0x8,
        0xC,
        0x10,
        0x14,
        0x18,
        0x1C,
        0x20,
    ];

    let offset_candidates = [
        0x700u64,  // User mentioned this might be correct
        0x770u64,  // Current value
        0x750u64,  // Try some values in between
        0x720u64,
    ];

    info!("[PLAYER_STATE] Testing R13=0x{:x} with different RDX and offset combinations", r13_value);

    for &rdx_value in &rdx_candidates {
        for &offset in &offset_candidates {
            let final_addr = r13_value.wrapping_add(rdx_value).wrapping_add(offset);

            // Test if this address contains valid player state values
            if let Some(state_value) = read_player_state_value(final_addr as usize) {
                // Valid player state should be 0, 1, or 3
                if state_value <= 3 {
                    info!("[PLAYER_STATE] Found valid player state {} at address 0x{:x} (R13+RDX+offset = 0x{:x}+0x{:x}+0x{:x})",
                          state_value, final_addr, r13_value, rdx_value, offset);
                    return Some((final_addr, rdx_value, offset));
                }
            }
        }
    }

    info!("[PLAYER_STATE] No valid player state address found for R13=0x{:x}", r13_value);
    None
}

// Find r13 value by scanning for mov r13 instructions around the movzx instruction
fn find_r13_value_around_instruction(movzx_addr: usize) -> Option<u64> {
    // Search in a context around the movzx instruction (like the C# code does)
    let context_size = 16384; // 16KB context
    let context_start = movzx_addr.saturating_sub(8192); // Start 8KB before

    info!("[PLAYER_STATE] Searching for r13 value in context 0x{:x} - 0x{:x}",
          context_start, context_start + context_size);

    unsafe {
        // Read context buffer
        if let Ok(context_buffer) = std::panic::catch_unwind(|| {
            std::slice::from_raw_parts(context_start as *const u8, context_size)
        }) {
            let mut found_candidates = Vec::new();

            // Enhanced r13 detection - look for multiple patterns and validate them
            for i in 0..context_buffer.len().saturating_sub(10) {
                // Pattern 1: mov r13, [absolute_address] (4C 8B 2C 25 xx xx xx xx)
                if context_buffer[i] == 0x4C && context_buffer[i + 1] == 0x8B &&
                   context_buffer[i + 2] == 0x2C && context_buffer[i + 3] == 0x25 {

                    let absolute_addr = u32::from_le_bytes([
                        context_buffer[i + 4], context_buffer[i + 5],
                        context_buffer[i + 6], context_buffer[i + 7]
                    ]) as usize;

                    info!("[PLAYER_STATE] Found mov r13, [0x{:x}] at 0x{:x}", absolute_addr, context_start + i);

                    if let Some(r13_value) = read_r13_value_from_address(absolute_addr) {
                        found_candidates.push(r13_value);
                    }
                }

                // Pattern 2: lea r13, [rip+offset] (4C 8D 2D xx xx xx xx)
                if context_buffer[i] == 0x4C && context_buffer[i + 1] == 0x8D &&
                   context_buffer[i + 2] == 0x2D {

                    let rip_offset = i32::from_le_bytes([
                        context_buffer[i + 3], context_buffer[i + 4],
                        context_buffer[i + 5], context_buffer[i + 6]
                    ]);

                    let instruction_addr = context_start + i + 7;
                    let target_addr = (instruction_addr as i64 + rip_offset as i64) as usize;

                    info!("[PLAYER_STATE] Found lea r13, [rip+0x{:x}] -> 0x{:x}", rip_offset, target_addr);

                    // For lea instruction, the target address IS the r13 value
                    if target_addr > 0x10000 && (target_addr as u64) < 0x7FFFFFFFFFFF {
                        found_candidates.push(target_addr as u64);
                    }
                }

                // Pattern 3: mov r13, immediate (49 BD xx xx xx xx xx xx xx xx)
                if context_buffer[i] == 0x49 && context_buffer[i + 1] == 0xBD {
                    let immediate_value = u64::from_le_bytes([
                        context_buffer[i + 2], context_buffer[i + 3], context_buffer[i + 4], context_buffer[i + 5],
                        context_buffer[i + 6], context_buffer[i + 7], context_buffer[i + 8], context_buffer[i + 9]
                    ]);

                    info!("[PLAYER_STATE] Found mov r13, 0x{:x}", immediate_value);
                    if immediate_value > 0x10000 && immediate_value < 0x7FFFFFFFFFFF {
                        found_candidates.push(immediate_value);
                    }
                }

                // Pattern 4: mov r13, [rip+offset] (4C 8B 2D xx xx xx xx)
                if context_buffer[i] == 0x4C && context_buffer[i + 1] == 0x8B &&
                   context_buffer[i + 2] == 0x2D {

                    let rip_offset = i32::from_le_bytes([
                        context_buffer[i + 3], context_buffer[i + 4],
                        context_buffer[i + 5], context_buffer[i + 6]
                    ]);

                    let instruction_addr = context_start + i + 7;
                    let target_addr = (instruction_addr as i64 + rip_offset as i64) as usize;

                    info!("[PLAYER_STATE] Found mov r13, [rip+0x{:x}] -> reading from 0x{:x}", rip_offset, target_addr);

                    if let Some(r13_value) = read_r13_value_from_address(target_addr) {
                        found_candidates.push(r13_value);
                    }
                }
            }

            // Test all found candidates to see which one produces valid player state
            info!("[PLAYER_STATE] Found {} R13 candidates, testing each one", found_candidates.len());
            for (idx, &candidate) in found_candidates.iter().enumerate() {
                info!("[PLAYER_STATE] Testing R13 candidate {}: 0x{:x}", idx + 1, candidate);

                // Quick test with common combinations
                let test_combinations = [
                    (0x44E54200u64, 0x770u64),  // Original
                    (0x0u64, 0x700u64),         // User suggested
                    (0x0u64, 0x770u64),         // No RDX, original offset
                    (0x44E54200u64, 0x700u64),  // Original RDX, user offset
                ];

                for &(rdx, offset) in &test_combinations {
                    let test_addr = candidate.wrapping_add(rdx).wrapping_add(offset);
                    if let Some(state_value) = read_player_state_value(test_addr as usize) {
                        if state_value <= 3 {
                            info!("[PLAYER_STATE] R13 candidate 0x{:x} produces valid state {} with RDX=0x{:x}, offset=0x{:x}",
                                  candidate, state_value, rdx, offset);
                            return Some(candidate);
                        }
                    }
                }
            }

            // If we found candidates but none worked, return the first one for further testing
            if !found_candidates.is_empty() {
                info!("[PLAYER_STATE] No candidates produced valid state in quick test, returning first candidate for full testing");
                return Some(found_candidates[0]);
            }

            info!("[PLAYER_STATE] No r13 setup instructions found after checking all patterns");

            // Debug: Show some bytes around the movzx instruction for analysis
            let movzx_offset = movzx_addr - context_start;
            if movzx_offset < context_buffer.len() {
                let debug_start = movzx_offset.saturating_sub(32);
                let debug_end = (movzx_offset + 32).min(context_buffer.len());
                let debug_bytes: Vec<String> = context_buffer[debug_start..debug_end]
                    .iter().map(|b| format!("{:02x}", b)).collect();
                info!("[PLAYER_STATE] Debug bytes around movzx: {}", debug_bytes.join(" "));
            }

        } else {
            info!("[PLAYER_STATE] Failed to read context buffer around movzx instruction - memory not accessible");
        }

        info!("[PLAYER_STATE] No r13 setup instructions found in context");
        None
    }
}

// Read r13 value from a memory address
fn read_r13_value_from_address(addr: usize) -> Option<u64> {
    unsafe {
        // First check if the address is reasonable
        if addr < 0x10000 || addr > 0x7FFFFFFFFFFF {
            return None;
        }

        if let Ok(value) = std::panic::catch_unwind(|| {
            let ptr = addr as *const u64;
            std::ptr::read_volatile(ptr)
        }) {
            // Validate the r13 value (same validation as C# code)
            if value > 0x10000 && value < 0x7FFFFFFFFFFF {
                info!("[PLAYER_STATE] Read valid R13 value 0x{:x} from address 0x{:x}", value, addr);
                return Some(value);
            } else {
                info!("[PLAYER_STATE] Invalid R13 value 0x{:x} from address 0x{:x} (out of range)", value, addr);
            }
        } else {
            info!("[PLAYER_STATE] Failed to read from address 0x{:x} (memory not accessible)", addr);
        }
    }
    None
}

// Read player state value from calculated address
fn read_player_state_value(addr: usize) -> Option<u32> {
    unsafe {
        if let Ok(value) = std::panic::catch_unwind(|| {
            let ptr = addr as *const u32;
            std::ptr::read_volatile(ptr)
        }) {
            // Player state should be 0, 1, or 3 typically, but allow up to 10 for safety
            if value <= 10 {
                return Some(value);
            } else {
                // Log invalid values for debugging
                if value < 1000 {  // Only log if not completely garbage
                    info!("[PLAYER_STATE] Invalid player state value {} at address 0x{:x} (expected 0-3)", value, addr);
                }
            }
        }
    }
    None
}

// Safe 32-bit memory read function
fn read_u32_safe(addr: usize) -> Option<u32> {
    unsafe {
        if addr == 0 {
            return None;
        }
        
        if let Ok(value) = std::panic::catch_unwind(|| {
            let ptr = addr as *const u32;
            std::ptr::read_volatile(ptr)
        }) {
            Some(value)
        } else {
            None
        }
    }
}

// Check if phonecamera (photo mode) is open
// PRIORITY LOGIC: Menu state takes precedence over phonecamera state
// - If both menu and phonecamera are enabled → treat as menu (return false)
// - Return true when phonecamera flag indicates active (commonly 3, sometimes 1) AND menu=false
// - Additionally: for 500ms after the menu closes, ignore phonecamera (suppression window)
// This ensures menu state always wins when both conditions are met and prevents post-menu blips
fn is_phonecamera_open() -> bool {
    unsafe {
        // Require detected flag address
        if g_phonecamera_flag_addr == 0 {
            static mut LAST_ADDR_LOG: Option<std::time::Instant> = None;
            let now = std::time::Instant::now();
            let should_log = LAST_ADDR_LOG.map_or(true, |t| now.duration_since(t) > std::time::Duration::from_secs(5));
            if should_log {
                debug!("[PHONECAMERA] Flag address not set yet; waiting for breakpoint to trigger");
                LAST_ADDR_LOG = Some(now);
            }
            return false;
        }

        // Simple flag: 0 = closed, 1 = open
        match read_u32_safe(g_phonecamera_flag_addr) {
            Some(v) => v == 1,
            None => {
                debug!("[PHONECAMERA] Failed to read flag at 0x{:x}", g_phonecamera_flag_addr);
                false
            }
        }
    }
}

// Get the current debounced phonecamera state (for use by camera system)
fn get_phonecamera_open_state() -> bool {
    unsafe {
        g_last_phonecamera_open_state
    }
}

// Update phonecamera open state immediately (no debounce)
fn update_phonecamera_open_state() {
    unsafe {
        let new_state = is_phonecamera_open();
        if new_state != g_last_phonecamera_open_state {
            if new_state {
                info!("[PHONECAMERA] ENABLED (flag active, menu closed)");
                println!("PHONECAMERA ENABLED: Photo mode active - zoom should work now");
            } else {
                info!("[PHONECAMERA] DISABLED (flag inactive or menu open)");
                println!("PHONECAMERA DISABLED: Photo mode inactive");
            }
            g_last_phonecamera_open_state = new_state;
        }
    }
}

fn read_coordinates_at(addr: usize) -> Option<(f32, f32, f32)> {
    unsafe {
        if !is_memory_readable(addr) {
            return None;
        }

        // Try to read 3 floats (X, Y, Z) as big-endian
        let ptr = addr as *const u8;
        if ptr.is_null() {
            return None;
        }

        // Read 12 bytes for 3 floats
        let bytes = std::slice::from_raw_parts(ptr, 12);

        let x = f32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let y = f32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let z = f32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);

        Some((x, y, z))
    }
}

// OPTIMIZED coordinate reading with minimal latency - trades some safety for maximum responsiveness
pub fn read_coordinates_safely(addr: usize) -> Option<(f32, f32, f32)> {
    unsafe {
        // Fast memory accessibility check
        if addr == 0 || addr as *const u8 == std::ptr::null() {
            return None;
        }

        // SINGLE-READ approach for maximum performance (no double-read validation)
        // This eliminates the spin_loop delay and reduces read time by 50%
        let result = std::panic::catch_unwind(|| {
            let ptr = addr as *const u8;

            // Single atomic read operation - much faster than double-read
            let buffer = std::slice::from_raw_parts(ptr, 12);

            // Convert from big-endian bytes to floats (BOTW memory format)
            let x = f32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
            let y = f32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
            let z = f32::from_be_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]);

            // Quick validation - only check for completely invalid values (NaN, Inf)
            if x.is_finite() && y.is_finite() && z.is_finite() {
                Some((x, y, z))
            } else {
                None
            }
        });

        match result {
            Ok(coords) => coords,
            Err(_) => None, // Memory access failed
        }
    }
}

fn search_memory_pattern(start_addr: usize, size: usize, pattern: &[Option<u8>]) -> Option<usize> {
    unsafe {
        let end_addr = start_addr + size;
        let mut addr = start_addr;
        let mut checked_regions = 0;
        let mut accessible_regions = 0;

        while addr + pattern.len() < end_addr {
            // Check memory in page-sized chunks
            if addr % 0x1000 == 0 { // New page
                checked_regions += 1;
                if !is_memory_readable(addr) {
                    addr += 0x1000; // Skip entire page
                    continue;
                }
                accessible_regions += 1;
            }

            // Check pattern match with error handling
            let mut matches = true;

            for (i, &pattern_byte) in pattern.iter().enumerate() {
                if let Some(expected) = pattern_byte {
                    let actual_ptr = (addr + i) as *const u8;

                    // Try to read byte with error handling
                    let actual = match std::panic::catch_unwind(|| {
                        std::ptr::read_volatile(actual_ptr)
                    }) {
                        Ok(val) => val,
                        Err(_) => {
                            matches = false;
                            break;
                        }
                    };

                    if actual != expected {
                        matches = false;
                        break;
                    }
                }
                // None = wildcard, always matches
            }

            if matches {
                info!("Pattern found after checking {} regions ({} accessible)", checked_regions, accessible_regions);
                return Some(addr);
            }

            addr += 1; // Try byte-by-byte for more thorough search
        }

        if checked_regions > 0 {
            info!("Checked {} regions, {} were accessible, no pattern found", checked_regions, accessible_regions);
        }
        None
    }
}

fn is_memory_readable(addr: usize) -> bool {
    unsafe {
        use winapi::um::memoryapi::VirtualQuery;
        use winapi::um::winnt::{MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE};

        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        let result = VirtualQuery(
            addr as *const _,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        );

        if result == 0 {
            return false;
        }

        // Check if memory is readable
        matches!(mbi.Protect,
            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READONLY | PAGE_READWRITE)
    }
}

// Global atomic variables for transient input values
// - Mouse wheel delta (scaled by 1000 for precision)
static MOUSE_WHEEL_DELTA: AtomicI32 = AtomicI32::new(0);

static mut MOUSE_HOOK: winapi::shared::windef::HHOOK = std::ptr::null_mut();




fn confine_cursor_to_window() {
    unsafe {
        let hwnd = focus::get_cemu_hwnd();
        if !hwnd.is_null() {
            let mut rect: winapi::shared::windef::RECT = std::mem::zeroed();
            if winuser::GetWindowRect(hwnd, &mut rect) != 0 {
                winuser::ClipCursor(&rect);
            }
        }
    }
}

fn release_cursor_clip() {
    unsafe {
        winuser::ClipCursor(std::ptr::null());
    }
}








// Low-level mouse hook procedure to capture wheel, button messages, and RAW MOVEMENT
extern "system" fn low_level_mouse_proc(n_code: i32, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
    unsafe {
        use winapi::um::winuser::*;

        if n_code >= 0 {
            // Check if CEMU has focus before processing mouse input
            if !focus::check_cemu_focus_immediate() {
                // If CEMU doesn't have focus, just pass the message through
                return CallNextHookEx(MOUSE_HOOK, n_code, w_param, l_param);
            }
            
            let msg = w_param as u32;
            let msllhook_struct = l_param as *const MSLLHOOKSTRUCT;

            if !msllhook_struct.is_null() {
                
                // Handle mouse wheel
                if msg == WM_MOUSEWHEEL {
                    let wheel_data = (*msllhook_struct).mouseData;
                    let wheel_delta = ((wheel_data >> 16) & 0xFFFF) as i16;
                    let normalized_delta = ((wheel_delta as i32) * 1000) / 120;
                    // Accumulate wheel events so rapid ticks aren’t lost between frames
                    MOUSE_WHEEL_DELTA.fetch_add(normalized_delta, Ordering::Relaxed);
                }

                // Handle mouse buttons for gamepad mapping using simple global state
                match msg {
                    WM_LBUTTONDOWN => utils::set_global_mouse_button(0, true),
                    WM_LBUTTONUP => utils::set_global_mouse_button(0, false),
                    WM_RBUTTONDOWN => utils::set_global_mouse_button(1, true),
                    WM_RBUTTONUP => utils::set_global_mouse_button(1, false),
                    WM_MBUTTONDOWN => utils::set_global_mouse_button(2, true),
                    WM_MBUTTONUP => utils::set_global_mouse_button(2, false),
                    WM_XBUTTONDOWN => {
                        let button_data = (*msllhook_struct).mouseData;
                        let button_index = if (button_data >> 16) & 0x0001 != 0 { 3 } else { 4 };
                        utils::set_global_mouse_button(button_index, true);
                    },
                    WM_XBUTTONUP => {
                        let button_data = (*msllhook_struct).mouseData;
                        let button_index = if (button_data >> 16) & 0x0001 != 0 { 3 } else { 4 };
                        utils::set_global_mouse_button(button_index, false);
                    },
                    _ => {}
                }
            }
        }

        CallNextHookEx(MOUSE_HOOK, n_code, w_param, l_param)
    }
}

fn install_mouse_hook() -> bool {
    unsafe {
        use winapi::um::winuser::*;
        use winapi::um::libloaderapi::GetModuleHandleW;

        MOUSE_HOOK = SetWindowsHookExW(
            WH_MOUSE_LL,
            Some(low_level_mouse_proc),
            GetModuleHandleW(std::ptr::null()),
            0
        );

        !MOUSE_HOOK.is_null()
    }
}

fn uninstall_mouse_hook() {
    unsafe {
        use winapi::um::winuser::UnhookWindowsHookEx;
        if !MOUSE_HOOK.is_null() {
            UnhookWindowsHookEx(MOUSE_HOOK);
            MOUSE_HOOK = std::ptr::null_mut();
        }
    }
}



fn check_mouse_wheel() -> f32 {
    unsafe {
        // Primary method: Low-level mouse hook (working perfectly)
        let delta_int = MOUSE_WHEEL_DELTA.swap(0, Ordering::Relaxed);
        let hook_delta = delta_int as f32 / 1000.0;

        if hook_delta != 0.0 {
            // Reduce per-notch scale for less twitchy zoom
            return hook_delta * 0.2;
        }

        0.0
    }
}






// First-run detection system
const FIRST_RUN_FLAG_FILE: &str = "botw_mousecam_initialized.flag";

// Disable console Quick Edit mode to prevent pauses when selecting text
fn disable_console_quick_edit() {
    unsafe {
        let h_in = GetStdHandle(STD_INPUT_HANDLE);
        if !h_in.is_null() {
            let mut mode: u32 = 0;
            if GetConsoleMode(h_in, &mut mode) != 0 {
                const ENABLE_QUICK_EDIT_MODE: u32 = 0x0040;
                const ENABLE_MOUSE_INPUT: u32 = 0x0010;
                let new_mode = mode & !ENABLE_QUICK_EDIT_MODE & !ENABLE_MOUSE_INPUT;
                let _ = SetConsoleMode(h_in, new_mode);
            }
        }
    }
}

// Pretty, colored initialization banner
fn print_init_banner() -> io::Result<()> {
    use crate::i18n::{strings, Language};
    use crate::utils::get_global_config;
    let lang = get_global_config().language;
    let t = strings(lang);

    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)).set_intense(true).set_bold(true))?;
    writeln!(&mut stdout, "")?;
    writeln!(&mut stdout, "==============================================================")?;
    writeln!(&mut stdout, "=            BOTW MouseCam: {}           =", t.init_complete_text)?;
    writeln!(&mut stdout, "==============================================================")?;
    writeln!(&mut stdout, "")?;
    stdout.reset()?;
    Ok(())
}

fn migrate_first_run_flag(config: &mut MouseConfig) -> bool {
    // Check for legacy flag file and migrate to config
    if Path::new(FIRST_RUN_FLAG_FILE).exists() {
        config.first_run_done = true;
        let _ = fs::remove_file(FIRST_RUN_FLAG_FILE); // Clean up old file
        true // Need to save config
    } else {
        false
    }
}

fn log_camera_data(camera: &GameCamera) {
    let pos: glm::Vec3 = camera.pos.into();
    let focus: glm::Vec3 = camera.focus.into();
    let rot: glm::Vec3 = camera.rot.into();
    let fov: f32 = camera.fov.into();

    unsafe {
        info!("[CAMERA_LOG] pos=({:.3}, {:.3}, {:.3}) focus=({:.3}, {:.3}, {:.3}) rot=({:.3}, {:.3}, {:.3}) fov={:.3} state {}",
              pos.x, pos.y, pos.z,
              focus.x, focus.y, focus.z,
              rot.x, rot.y, rot.z,
              fov, g_runtime_player_state_value);
    }
}

// Aiming camera constants
const NORMAL_FOV: f32 = 0.873;  // ~50 degrees
const AIM_FOV: f32 = 0.65;      // ~37 degrees - more zoomed
const BASE_RIGHT_OFFSET: f32 = 0.6;  // Reduced shoulder offset to prevent pulsation
const BASE_UP_OFFSET: f32 = 0.3;     // Reduced above offset
const FORWARD_NUDGE: f32 = 0.2;      // Reduced forward adjustment
const BLEND_SPEED: f32 = 8.0;        // Slower transition for stability

// PhoneCamera FOV targets (photo mode zoom)
// Default photo mode zoom is now 2x of previous (halve FOV)
const PHONECAMERA_BASE_FOV: f32 = 0.175;   // ~10 degrees - 2x stronger than before
const PHONECAMERA_MIN_FOV: f32 = 0.025;    // ~1.43 degrees - ultra zoom limit

// Menu detection constants removed

// Global aiming state tracking to prevent oscillation
static mut g_last_aim_state: u8 = 0;
static mut g_aim_offset_x: f32 = 0.0;
static mut g_aim_offset_y: f32 = 0.0;
static mut g_aim_offset_z: f32 = 0.0;

// Player state stabilization to handle rapid oscillations
// Simple logic: if oscillating between 0 and X, return X. If consistently 0, return 0.
fn stabilize_player_state(raw_state: u8) -> u8 {
    use std::collections::VecDeque;
    
    static mut STATE_HISTORY: Option<VecDeque<u8>> = None;
    static mut CURRENT_STABLE_STATE: u8 = 0;
    
    const HISTORY_SIZE: usize = 8; // Keep track of last 8 readings
    
    unsafe {
        // Initialize history if needed
        if STATE_HISTORY.is_none() {
            STATE_HISTORY = Some(VecDeque::with_capacity(HISTORY_SIZE));
            CURRENT_STABLE_STATE = raw_state;
        }
        
        let history = STATE_HISTORY.as_mut().unwrap();
        
        // Add current reading to history
        history.push_back(raw_state);
        
        // Remove old entries
        while history.len() > HISTORY_SIZE {
            history.pop_front();
        }
        
        // Need at least 4 samples to make a decision
        if history.len() < 4 {
            return CURRENT_STABLE_STATE;
        }
        
        // Count unique states in recent history
        let unique_states: std::collections::HashSet<u8> = history.iter().copied().collect();
        
        let new_stable_state = if unique_states.len() == 1 {
            // All values are the same - this is the stable state
            *unique_states.iter().next().unwrap()
        } else if unique_states.len() == 2 && unique_states.contains(&0) {
            // Oscillating between 0 and another value - prefer the non-zero value
            let non_zero_state = unique_states.iter().find(|&&s| s != 0).copied().unwrap_or(0);
            
            // Count occurrences
            let zero_count = history.iter().filter(|&&s| s == 0).count();
            let non_zero_count = history.iter().filter(|&&s| s == non_zero_state).count();
            
            // If we see both 0 and non-zero values, it's oscillating - return non-zero
            if zero_count > 0 && non_zero_count > 0 {
                if non_zero_state != CURRENT_STABLE_STATE {
                    info!("[STATE_STABILIZATION] Oscillation 0↔{} detected, stabilizing to {} (pattern: 0×{}, {}×{})", 
                          non_zero_state, non_zero_state, zero_count, non_zero_state, non_zero_count);
                }
                non_zero_state
            } else {
                // Should not happen with our logic above, but fallback
                CURRENT_STABLE_STATE
            }
        } else {
            // More complex pattern or different oscillation - keep current stable state
            CURRENT_STABLE_STATE
        };
        
        // Update stable state if it changed
        if new_stable_state != CURRENT_STABLE_STATE {
            if unique_states.len() == 1 {
                info!("[STATE_STABILIZATION] State consistently {} → {}", 
                      CURRENT_STABLE_STATE, new_stable_state);
            }
            CURRENT_STABLE_STATE = new_stable_state;
        }
        
        CURRENT_STABLE_STATE
    }
}

// Smooth aiming camera transition - applied AFTER orbit calculation to avoid conflicts
fn apply_precision_mode_simple(gc: &mut GameCamera, current_state: u8) {
    unsafe {
        // Check if we're in aiming state
        let is_aiming = current_state == 1 || current_state == 3;
        let target_blend = if is_aiming { 1.0 } else { 0.0 };
        
        // Debug state changes - only when logging enabled and slower
        static mut LAST_DEBUG_STATE: u8 = 255;
        static mut LAST_DEBUG_BLEND: f32 = -1.0;
        static mut LAST_AIM_LOG: Option<Instant> = None;
        let should_log_aim = LAST_AIM_LOG.map_or(true, |t| t.elapsed() > Duration::from_secs(1)); // Every 1 second max
        
        if g_phonecamera_logging_enabled && ((current_state != LAST_DEBUG_STATE) || (should_log_aim && (g_aim_blend - LAST_DEBUG_BLEND).abs() > 0.1)) {
            if current_state != LAST_DEBUG_STATE {
                info!("[AIM_MODE] State changed: {} → {} (is_aiming: {}, target_blend: {:.2})", 
                      LAST_DEBUG_STATE, current_state, is_aiming, target_blend);
            } else if should_log_aim {
                info!("[AIM_MODE] Blend update: {:.2} → {:.2} (state: {})", LAST_DEBUG_BLEND, g_aim_blend, current_state);
                LAST_AIM_LOG = Some(Instant::now());
            }
            LAST_DEBUG_STATE = current_state;
            LAST_DEBUG_BLEND = g_aim_blend;
        }
        
        // Use larger deadzone to prevent micro-oscillations
        let blend_diff = target_blend - g_aim_blend;
        if blend_diff.abs() > 0.001 {
            let delta_time = 1.0 / 1200.0; // Assume 1200Hz update rate
            let blend_change = blend_diff * BLEND_SPEED * delta_time;
            g_aim_blend = (g_aim_blend + blend_change).clamp(0.0, 1.0);
        }
        
        // Only apply offsets if we're actually aiming (not during transition out)
        if g_aim_blend > 0.01 {
            let current_pos: glm::Vec3 = gc.pos.into();
            let current_focus: glm::Vec3 = gc.focus.into();

            // Calculate camera-space vectors (right and up relative to view direction)
            let up = glm::vec3(0.0, 1.0, 0.0);
            let forward = glm::normalize(&(current_focus - current_pos));
            let right = glm::normalize(&glm::cross::<f32, glm::U3>(&forward, &up));
            let camera_up = glm::cross::<f32, glm::U3>(&right, &forward);

            // Calculate target offsets
            let distance = glm::length(&(current_focus - current_pos));
            let distance_scale = (distance / 5.0).clamp(0.5, 1.0); // Narrower range for stability
            
            let target_right_offset = BASE_RIGHT_OFFSET * distance_scale * g_aim_blend;
            let target_up_offset = BASE_UP_OFFSET * distance_scale * g_aim_blend;
            let target_forward_offset = FORWARD_NUDGE * g_aim_blend;
            
            // Smooth the offset values independently to prevent oscillation
            let offset_smoothing = 0.15; // Aggressive smoothing for offsets
            g_aim_offset_x = g_aim_offset_x * (1.0 - offset_smoothing) + target_right_offset * offset_smoothing;
            g_aim_offset_y = g_aim_offset_y * (1.0 - offset_smoothing) + target_up_offset * offset_smoothing;
            g_aim_offset_z = g_aim_offset_z * (1.0 - offset_smoothing) + target_forward_offset * offset_smoothing;
            
            // Apply smoothed offsets
            let lateral_translation = right * g_aim_offset_x + camera_up * g_aim_offset_y;
            
            // Apply the same lateral translation to both camera and focus to shift view center
            let new_pos = current_pos + lateral_translation;
            let new_focus = current_focus + lateral_translation + forward * g_aim_offset_z;

            gc.pos = new_pos.into();
            gc.focus = new_focus.into();
        } else {
            // Reset offsets when not aiming
            g_aim_offset_x = 0.0;
            g_aim_offset_y = 0.0;
            g_aim_offset_z = 0.0;
        }
        
        // Update last state
        g_last_aim_state = current_state;
        
        // Smooth FOV blending with deadzone
        let target_fov = NORMAL_FOV + (AIM_FOV - NORMAL_FOV) * g_aim_blend;
        let current_fov: f32 = gc.fov.into();
        let fov_diff = target_fov - current_fov;
        if fov_diff.abs() > 0.001 {
            let new_fov = current_fov + fov_diff * 0.1; // Smooth FOV transition
            gc.fov = new_fov.into();
        }
    }
}

fn show_config_menu(config_path: &str) -> Result<(bool, MouseConfig), Box<dyn std::error::Error>> {
    let config = MouseConfig::load_or_create(config_path);
    let mut menu = ConfigMenu::new(config, config_path.to_string());

    write_red("=== MOUSE BUTTON CONFIGURATION ===")?;
    println!("Configure your mouse button key bindings...");
    println!("Press F4 at any time during gameplay to open this menu again.");

    let continue_to_game = menu.show_main_menu()?;
    Ok((continue_to_game, menu.config))
}

fn patch(_lib: *mut std::ffi::c_void) -> Result<(), Box<dyn std::error::Error>> {
    // Set console window title
    unsafe {
        let title = CString::new("BOTW Mouse mod").unwrap();
        SetConsoleTitleA(title.as_ptr());
    }

    let config_path = "botw_mousecam_config.toml";

    // Load config and check first run
    let mut config = MouseConfig::load_or_create(config_path);
    let need_save = migrate_first_run_flag(&mut config);
    
    let config = if !config.first_run_done {
        // First run: show configuration menu automatically
        let (continue_to_game, new_config) = show_config_menu(config_path)?;
        if !continue_to_game {
            return Ok(());
        }
        let mut final_config = new_config;
        final_config.first_run_done = true;
        let _ = final_config.save(config_path);
        final_config
    } else {
        // Save config if we migrated from flag file
        if need_save {
            let _ = config.save(config_path);
        }
        config
    };

    // Initialize focus detection
    init_focus_detector();

    // Menu state detection will be initialized later when we get the address from position finder

    // Initialize global config
    utils::init_global_config(config);

    write_red("Mouse Camera Controls:")?;
    println!("{}", utils::get_updated_instructions());
    write_red("Press HOME to exit the mod.")?;

    let _proc_inf = ProcessInfo::new(None)?;
    let mut input = MouseInput::new();
    let mut active = false;

    let camera_struct = get_camera_function()?;
    let camera_pointer = camera_struct.camera;

    // Try to find Link's actual position using botw_editor's exact method
    match find_link_position(&_proc_inf) {
        Ok(addr) => {
            unsafe {
                g_link_position_addr = addr;
            }
        }
        Err(_) => {
            // Fallback to camera focus point following
        }
    }


    // VPAD/WPAD detour setup removed - redundant with keyboard input system

    // Player state detection moved to position finder module for better external memory access
    info!("[PLAYER_STATE] Player state detection delegated to position finder module");

    // Initialize shared memory for position finder communication
    println!("RUST DLL: Initializing shared memory...");
    init_shared_memory();
    
    // Initialize experimental magnesis control (always on)
    println!("RUST DLL: Initializing EXPERIMENTAL magnesis control from shared memory...");
    match magnesis_experimental::init_experimental_magnesis_from_shared_memory() {
        Ok(_) => {
            println!("RUST DLL: ✓ Experimental magnesis control initialized from position finder");
            info!("[MAGNESIS_EXP] Successfully initialized from shared memory");
        }
        Err(e) => {
            println!("RUST DLL: ✗ Failed to initialize experimental magnesis: {}", e);
            warn!("[MAGNESIS_EXP] Initialization failed: {}", e);
            println!("RUST DLL: Position finder must provide magnesis MOVBE addresses first");
        }
    }

    // CONTINUOUS MONITORING: Start parallel searches for position finder data
    log_infof!("RUST DLL: Starting parallel monitoring for position finder data...");

    use std::sync::atomic::Ordering as AtomicOrdering;
    let menu_state_initialized = Arc::new(AtomicBool::new(false));
    let phonecamera_initialized = Arc::new(AtomicBool::new(false));
    let mut magnesis_initialized = false;
    let player_state_initialized = Arc::new(AtomicBool::new(false));

    // Menu MOVBE search thread
    {
        let done = Arc::clone(&menu_state_initialized);
        std::thread::spawn(move || {
            loop {
                let result = std::panic::catch_unwind(|| {
                    if let Some(movbe_addr) = get_menu_movbe_from_shared_memory() {
                        log_infof!("RUST DLL: Got menu MOVBE address: 0x{:x}", movbe_addr);
                        if setup_movbe_breakpoint(movbe_addr) {
                            log_infof!("RUST DLL: MOVBE breakpoint set up successfully");
                            true
                        } else {
                            log_warnf!("RUST DLL: Failed to set up MOVBE breakpoint");
                            false
                        }
                    } else {
                        unsafe {
                            if !g_shared_position_data.is_null() {
                                let ptr = core::ptr::addr_of_mut!((*g_shared_position_data).request_flags);
                                let curr = core::ptr::read_unaligned(ptr as *const u32);
                                core::ptr::write_unaligned(ptr, curr | REQ_MENU_MOVBE);
                            }
                        }
                        false
                    }
                });
                match result {
                    Ok(true) => { done.store(true, AtomicOrdering::SeqCst); break; }
                    Ok(false) => {}
                    Err(_) => {
                        println!("RUST DLL: WARNING - Menu setup caused panic, continuing...");
                        warn!("[MENU_STATE] Menu breakpoint setup crashed, continuing initialization");
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        });
    }

    // PhoneCamera cmpxchg search thread
    {
        let done = Arc::clone(&phonecamera_initialized);
        std::thread::spawn(move || {
            loop {
                let result = std::panic::catch_unwind(|| {
                    unsafe {
                        if g_phonecamera_cmpxchg_breakpoint_addr == 0 && g_phonecamera_flag_addr == 0 {
                            if let Some(cmpxchg_addr) = get_phonecamera_lock_cmpxchg_from_shared_memory() {
                                log_infof!("RUST DLL: Got phonecamera cmpxchg address: 0x{:x}", cmpxchg_addr);
                                if setup_phonecamera_lock_breakpoint(cmpxchg_addr) {
                                    log_infof!("RUST DLL: PhoneCamera cmpxchg breakpoint set up successfully");
                                    info!("[PHONECAMERA] Breakpoint installed at 0x{:x} - phonecamera detection will be active once triggered", cmpxchg_addr);
                                    return true;
                                } else {
                                    log_warnf!("RUST DLL: Failed to set up phonecamera cmpxchg breakpoint");
                                }
                            } else {
                                if !g_shared_position_data.is_null() {
                                    let ptr = core::ptr::addr_of_mut!((*g_shared_position_data).request_flags);
                                    let curr = core::ptr::read_unaligned(ptr as *const u32);
                                    core::ptr::write_unaligned(ptr, curr | REQ_PHONECAMERA);
                                }
                            }
                        }
                    }
                    false
                });
                match result {
                    Ok(true) => { done.store(true, AtomicOrdering::SeqCst); break; }
                    Ok(false) => {}
                    Err(_) => {
                        println!("RUST DLL: WARNING - Phonecamera setup caused panic, continuing...");
                        warn!("[PHONECAMERA] Phonecamera breakpoint setup crashed, continuing initialization");
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        });
    }

    // MOVZX / player state search thread
    {
        let done = Arc::clone(&player_state_initialized);
        std::thread::spawn(move || {
            loop {
                let result = std::panic::catch_unwind(|| { get_player_state_from_shared_memory() });
                match result {
                    Ok(Some((player_state_addr, player_state_value))) => {
                        log_infof!("RUST DLL: SUCCESS! Found player state: {} at 0x{:x}", player_state_value, player_state_addr);
                        info!("[PLAYER_STATE] SUCCESS! Current player state: {} (from address 0x{:x})", player_state_value, player_state_addr);
                        unsafe {
                            g_stored_player_state_address = player_state_addr;
                            log_infof!("RUST DLL: Stored initial player state address: 0x{:x}", player_state_addr);
                        }
                        done.store(true, AtomicOrdering::SeqCst);
                        break;
                    }
                    Ok(None) => {
                        unsafe {
                            if !g_shared_position_data.is_null() {
                                let ptr = core::ptr::addr_of_mut!((*g_shared_position_data).request_flags);
                                let curr = core::ptr::read_unaligned(ptr as *const u32);
                                core::ptr::write_unaligned(ptr, curr | REQ_MOVZX);
                            }
                        }
                        log_infof!("RUST DLL: No movzx data yet, waiting...");
                    }
                    Err(_) => {
                        log_warnf!("RUST DLL: WARNING - Player state reading caused panic");
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        });
    }

    // Wait until all critical systems initialized
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        let menu_ok = menu_state_initialized.load(AtomicOrdering::SeqCst);
        let phone_ok = phonecamera_initialized.load(AtomicOrdering::SeqCst) || unsafe { g_phonecamera_flag_addr != 0 };
        let player_ok = player_state_initialized.load(AtomicOrdering::SeqCst);

        log_infof!("RUST DLL: Core systems status - Menu: {}, PhoneCamera: {}, Player: {}",
                 menu_ok, phone_ok, player_ok);
        if menu_ok && phone_ok && player_ok {
            log_infof!("RUST DLL: Essential systems initialized, continuing with initialization");
            break;
        }

        // Optional: Magnesis can be initialized after core systems are ready
        if let Some(magnesis_x_addr) = get_magnesis_x_address_from_shared_memory() {
            if !magnesis_initialized {
                log_infof!("RUST DLL: Got magnesis X MOVBE address: 0x{:x}", magnesis_x_addr);
                if setup_magnesis_x_breakpoint(magnesis_x_addr) {
                    magnesis_initialized = true;
                    info!("[MAGNESIS] Breakpoint installed at 0x{:x} - magnesis detection active", magnesis_x_addr);
                }
            }
        } else {
            unsafe {
                if !g_shared_position_data.is_null() {
                    let ptr = core::ptr::addr_of_mut!((*g_shared_position_data).request_flags);
                    let curr = core::ptr::read_unaligned(ptr as *const u32);
                    core::ptr::write_unaligned(ptr, curr | REQ_MAGNESIS_NORMAL);
                }
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    // Create our own wrapper function for camera updates
    unsafe {
        ORIGINAL_CAMERA_FUNC = camera_pointer;
    }
    
    let mut cam = unsafe {
        Detour::new(
            camera_pointer,
            14,
            camera_update_wrapper as *const u8 as usize,
            Some(&mut g_get_camera_data),
        )
    };


    // Build NOP injections based on configuration
    let config = utils::get_global_config();
    let mut nops: Vec<Box<dyn Inject>> = vec![];

    // Camera pos and focus writers - only add if enabled in config
    if config.camera_patches.camera_pos_writer_1 {
        nops.push(Box::new(Injection::new(camera_struct.camera + 0x17, vec![0x90; 10])));
    }
    if config.camera_patches.camera_pos_writer_2 {
        nops.push(Box::new(Injection::new(camera_struct.camera + 0x55, vec![0x90; 10])));
    }
    if config.camera_patches.camera_pos_writer_3 {
        nops.push(Box::new(Injection::new(camera_struct.camera + 0xC2, vec![0x90; 10])));
    }
    if config.camera_patches.camera_pos_writer_4 {
        nops.push(Box::new(Injection::new(camera_struct.camera + 0xD9, vec![0x90; 10])));
    }
    if config.camera_patches.camera_pos_writer_5 {
        nops.push(Box::new(Injection::new(camera_struct.camera + 0x117, vec![0x90; 10])));
    }
    if config.camera_patches.camera_pos_writer_6 {
        nops.push(Box::new(Injection::new(camera_struct.camera + 0x12E, vec![0x90; 10])));
    }
    if config.camera_patches.camera_pos_writer_7 {
        nops.push(Box::new(Injection::new(camera_struct.camera + 0x15D, vec![0x90; 10])));
    }
    if config.camera_patches.camera_pos_writer_8 {
        nops.push(Box::new(Injection::new(camera_struct.camera + 0x174, vec![0x90; 10])));
    }
    if config.camera_patches.camera_pos_writer_9 {
        nops.push(Box::new(Injection::new(camera_struct.camera + 0x22A, vec![0x90; 10])));
    }

    // Rotation writers - only add if enabled in config
    if config.camera_patches.rotation_writer_1 {
        nops.push(Box::new(Injection::new(camera_struct.rotation_vec1, vec![0x90; 7])));
    }
    if config.camera_patches.rotation_writer_2 {
        nops.push(Box::new(Injection::new(camera_struct.rotation_vec1 + 0x14, vec![0x90; 7])));
    }
    if config.camera_patches.rotation_writer_3 {
        nops.push(Box::new(Injection::new(camera_struct.rotation_vec1 + 0x28, vec![0x90; 7])));
    }

    // Don't inject camera detour immediately - it will be injected when mod is activated
    // This ensures the mod starts in a completely safe state

    // Big, colored banner for completion
    let _ = print_init_banner();
    debug!("Initialization complete - mod is ready!");
    

    loop {
        handle_mouse_input(&mut input);

        // Pump Windows messages so WH_MOUSE_LL hook callbacks are delivered (fix 3)
        unsafe {
            let mut msg: winapi::um::winuser::MSG = std::mem::zeroed();
            while winuser::PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, winuser::PM_REMOVE) != 0 {
                winuser::TranslateMessage(&msg);
                winuser::DispatchMessageW(&msg);
            }
        }

        // Handle mouse wheel and movement for experimental magnesis control (always on)
        let phonecamera_active = get_phonecamera_open_state();

        // Forward mouse input to magnesis, but only suppress camera control once
        // magnesis camera actually becomes active (post startup-capture phase)
        let magnesis_active_now = unsafe { should_magnesis_control_mouse() };
        let magnesis_camera_should_activate_now = magnesis_active_now && !magnesis_experimental::is_in_startup_capture_phase();

        if magnesis_active_now {
            // Send mouse input to magnesis control
            let wheel_delta = check_mouse_wheel();
            let config = utils::get_global_config();
            magnesis_experimental::update_magnesis_position(
                input.orbit_x,
                input.orbit_y,
                wheel_delta,
                config.magnesis_sensitivity
            );
            // Only suppress camera mouse inputs after magnesis camera takes over
            if magnesis_camera_should_activate_now {
                input.orbit_x = 0.0;
                input.orbit_y = 0.0;
                // Only clear zoom input if phone camera is not active (PhoneCamera zoom has priority)
                if !phonecamera_active {
                    input.zoom = 0.0;
                }
            }
        } else {
            // Normal camera zoom handling
            let wheel_delta = check_mouse_wheel();
            if wheel_delta != 0.0 {
                input.zoom = wheel_delta;
            }
        }

        input.sanitize();

        // Check for menu state transitions (3->2 triggers movzx re-check)
        check_menu_state_transitions();

        if input.deattach || unsafe { g_mod_should_exit } {
            // Remove all injected patches and detours before unloading
            nops.iter_mut().remove_injection();
            // Remove main camera detour to restore original function before DLL unload
            cam.remove_injection();

            // Thoroughly clean up any remaining breakpoints/handlers
            unsafe { cleanup_all_breakpoints(); }

            // CRITICAL: Always cleanup experimental magnesis NOPs before exit
            // This ensures any NOPed MOVBE instructions are restored
            magnesis_experimental::cleanup_magnesis_experimental();
            
            // Stop external helper and input hooks
            cleanup_external_position_finder();
            uninstall_mouse_hook();
            release_cursor_clip();
            cleanup_menu_state_detection();

            info!("[EXIT] All hooks, patches, and handlers removed - proceeding to unload DLL");
            break;
        }

        input.is_active = active;

        // Handle unified camera and gamepad mode toggle (F2/F3 merged functionality)
        if input.change_active {
            active = !active;

            unsafe {
                g_camera_active = active as u8;
                g_user_requested_active = active; // Track user's intended state
                

                if !active {
                    // Reset orbit camera by clearing global instance when deactivating
                    let mut orbit_guard = camera::ORBIT_CAMERA.lock().unwrap();
                    *orbit_guard = None;
                }
            }
            if active {
                input.reset();
                // 🚨 CONFIGURABLE ACTIVATION - Only inject enabled detours and patches
                let config = utils::get_global_config();

                // Main camera detour - Always inject for menu detection
                cam.inject();

                // Memory patches (NOPs)
                nops.iter_mut().inject();
                

                // Mouse hook - only install if enabled
                if config.camera_patches.mouse_hook_enabled {
                    install_mouse_hook();
                }

                // Prepare mouse input system to avoid an initial rotation/jump
                utils::prepare_for_camera_activation();

                // Bring Cemu window to foreground to ensure input routing
                focus::bring_cemu_to_foreground();

                // Cursor behavior: only confine when enabled in config (no hide/show)
                let config = utils::get_global_config();
                if config.confine_cursor_to_window {
                    confine_cursor_to_window();
                }

                log_info("RUST DLL: ✓ Mod ACTIVATED - All detours and patches injected");
                log_info("[SAFETY] Mod activated - camera, input hooks, and patches all active");
            } else {
                // 🚨 SAFE DEACTIVATION - Remove ALL hooks and patches for complete safety
                // Camera detour remains injected for menu detection
                // cam.remove_injection();  // Keep camera detour always active
                nops.iter_mut().remove_injection();
                
                // CRITICAL: Always cleanup experimental magnesis NOPs on deactivation
                // This restores any NOPed MOVBE instructions to prevent permanent breakage
                // First deactivate any active experimental magnesis control
                magnesis_experimental::deactivate_magnesis_control();
                // Then do full cleanup to restore NOPed instructions
                magnesis_experimental::cleanup_magnesis_experimental();

                // Remove ALL input detours for complete safety
                unsafe {
                    // Release sprint if we were holding it
                    let sprint_vk = utils::get_global_config().sprint_key;
                    if SPRINT_HELD_BY_MOD && sprint_vk != 0 {
                        crate::utils::send_key(sprint_vk, false);
                        SPRINT_HELD_BY_MOD = false;
                    }
                    // Remove player state runtime hook/exception handler for complete safety
                    if !g_exception_handler.is_null() {
                        use winapi::um::errhandlingapi::RemoveVectoredExceptionHandler;
                        RemoveVectoredExceptionHandler(g_exception_handler);
                        g_exception_handler = std::ptr::null_mut();
                        info!("[SAFETY] Player state exception handler removed");
                    }
                }
                
                // Cleanup when deactivating
                utils::cleanup_mouse_input();
                release_cursor_clip();

                // Uninstall mouse hook on deactivation
                uninstall_mouse_hook();
                release_cursor_clip();


                log_info("RUST DLL: ✓ Mod DEACTIVATED - ALL hooks and patches removed, game is completely safe");
                log_info("[SAFETY] Mod deactivated - camera, input hooks, and patches all removed - game is completely safe");

                // Note: Position finder continues running but addresses are cached for instant re-activation
                // This prevents the need to re-scan memory when re-enabling the mod
            }

            // Update the global gamepad state
            utils::set_global_gamepad_state(active);

            input.change_active = false;
            std::thread::sleep(std::time::Duration::from_millis(300));
        }

        // Handle F4 key - show configuration menu
        if input.show_config_menu {
            let (continue_to_game, new_config) = show_config_menu(config_path)?;
            if continue_to_game {
                // Update global config with new settings
                utils::init_global_config(new_config);
                write_red("Configuration updated! Returning to game...")?;
            } else {
                // User chose to exit - ensure experimental magnesis is cleaned up
                magnesis_experimental::cleanup_magnesis_experimental();
                cleanup_external_position_finder();
                uninstall_mouse_hook();
                cleanup_menu_state_detection();
                return Ok(());
            }
            input.show_config_menu = false;
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
        
        // F5 key removed - no manual magnesis control needed

        unsafe {
            // If we don't have the camera struct we need to skip it right away
            if g_camera_struct == 0x0 {
                continue;
            }

            let gc = (g_camera_struct as *mut GameCamera).as_mut().ok_or("GameCamera was still null")?;

            // Poll menu state for transitions
            check_menu_transition();
            
            // Check for menu state transitions
            unsafe {
                if g_menu_just_closed {
                    g_menu_just_closed = false;
                    
                    // Start a short grace period where phonecamera is ignored to avoid false positives
                    g_last_menu_closed_time = Some(Instant::now());
                    info!("[MENU_STATE] Menu closed - starting 500ms phonecamera suppression window");
                    
                    info!("[MENU_STATE] Handling menu close - snapping camera to player");
                    
                    // Get current player position
                    let link_addr = g_link_position_addr;
                    if link_addr != 0 {
                        if let Some((x, y, z)) = read_coordinates_safely(link_addr) {
                            let mut orbit_guard = camera::ORBIT_CAMERA.lock().unwrap();
                            if let Some(orbit_cam) = orbit_guard.as_mut() {
                                let player_pos = glm::vec3(x, y + 1.8, z);
                                
                                // Snap camera to player position immediately (no smooth movement)
                                orbit_cam.player_pos = player_pos;
                                orbit_cam.smooth_player_pos = player_pos;
                                
                                info!("[MENU_STATE] Camera snapped to player at ({:.2}, {:.2}, {:.2})", x, y, z);
                            }
                        } else {
                            warn!("[MENU_STATE] Failed to read player coordinates for camera snap");
                        }
                    } else {
                        warn!("[MENU_STATE] No valid link position address for camera snap");
                    }
                    
                    // Re-trigger player state scan to check if address changed
                    info!("[MENU_STATE] Re-triggering player state scan after menu close");
                    if let Some((new_player_state_addr, new_player_state_value)) = get_player_state_from_shared_memory() {
                        if new_player_state_addr != g_runtime_player_state_addr {
                            g_runtime_player_state_addr = new_player_state_addr;
                            info!("[MENU_STATE] Player state address updated: 0x{:x} -> 0x{:x}", 
                                  g_runtime_player_state_addr, new_player_state_addr);
                        }
                        g_runtime_player_state_value = new_player_state_value as u8;
                        info!("[MENU_STATE] Current player state: {}", new_player_state_value);
                    } else {
                        info!("[MENU_STATE] No player state update available yet");
                    }
                }
            }

            // On activation edge, synchronize orbit camera to the game's current camera to avoid jumps/rotations
            unsafe {
                static mut LAST_ACTIVE_STATE: u8 = 0;
                let just_activated = (g_camera_active != 0) && (LAST_ACTIVE_STATE == 0);
                if just_activated {
                    let mut orbit_guard = camera::ORBIT_CAMERA.lock().unwrap();
                    match orbit_guard.as_mut() {
                        Some(orbit_cam) => {
                            orbit_cam.sync_to_game_camera(gc);
                        }
                        None => {
                            let mut new_cam = OrbitCamera::new();
                            new_cam.sync_to_game_camera(gc);
                            new_cam.initialized = true;
                            new_cam.last_update_time = std::time::Instant::now();
                            *orbit_guard = Some(new_cam);
                        }
                    }
                    // Ensure no smoothing pulls it away immediately
                    if let Some(orbit_cam) = orbit_guard.as_mut() {
                        orbit_cam.target_theta = orbit_cam.theta;
                        orbit_cam.target_phi = orbit_cam.phi;
                        orbit_cam.target_distance = orbit_cam.distance;
                    }
                }
                LAST_ACTIVE_STATE = g_camera_active;
            }


        // Periodically check for phonecamera address if not found yet (position finder may find it later)
        static mut LAST_PHONECAMERA_CHECK: Option<Instant> = None;
        let should_check_phonecamera = LAST_PHONECAMERA_CHECK.map_or(true, |t| t.elapsed() > Duration::from_secs(3));
        
        if should_check_phonecamera && unsafe { g_phonecamera_flag_addr == 0 } {
            if let Some(cmpxchg_addr) = get_phonecamera_lock_cmpxchg_from_shared_memory() {
                println!("RUST DLL: Found phonecamera cmpxchg address during runtime: 0x{:x}", cmpxchg_addr);
                
                if setup_phonecamera_lock_breakpoint(cmpxchg_addr) {
                    info!("[PHONECAMERA] Runtime breakpoint setup successful at 0x{:x}", cmpxchg_addr);
                    println!("PHONECAMERA: Runtime detection system activated!");
                } else {
                    info!("[PHONECAMERA] Runtime breakpoint setup failed");
                }
            }
            unsafe { LAST_PHONECAMERA_CHECK = Some(Instant::now()); }
        }

        // Update phonecamera open state and log transitions (always check, even when mod is inactive)
        update_phonecamera_open_state();

        // Sprint toggle logic (bind the same key you use for sprint in Cemu)
        unsafe {
            let config = utils::get_global_config();
            let sprint_vk = config.sprint_key;

            // If feature disabled: release and clear all sprint state
            if !config.sprint_toggle_enabled {
                if SPRINT_HELD_BY_MOD && sprint_vk != 0 {
                    info!("[SPRINT] Feature disabled - releasing held key");
                    crate::utils::send_vk(sprint_vk, false);
                }
                SPRINT_HELD_BY_MOD = false;
                SPRINT_TOGGLE_ACTIVE = false;
                SPRINT_PHYSICAL_DOWN = false;
                SPRINT_ARMED_FROM_PHYSICAL = false;
                STOPPED_SINCE = None;
                SPRINT_ENGAGED_AT = None;
            } else if sprint_vk != 0 {
                // Log sprint info once
                static mut SPRINT_INIT_LOGGED: bool = false;
                if !SPRINT_INIT_LOGGED {
                    info!("[SPRINT] Sprint toggle ENABLED - Key: {} (0x{:02X})", crate::config::vk_to_name(sprint_vk), sprint_vk);
                    info!("[SPRINT] Tap sprint key while walking to toggle ON, stops automatically when you stop moving");
info!("[SPRINT] Post-release hold: ON");
                    SPRINT_INIT_LOGGED = true;
                }

                // Compute speed from Link position for auto-off logic
                let link_addr = g_link_position_addr;
                let now = Instant::now();
                if link_addr != 0 {
                    if let Some((x, _y, z)) = read_coordinates_safely(link_addr) {
                        if let Some((lx, lz)) = LAST_LINK_POS_XZ {
                            if let Some(t0) = LAST_LINK_SAMPLE_TIME {
                                let dt = now.saturating_duration_since(t0).as_secs_f32();
                                if dt > 0.000_1 {
                                    let dx = x - lx;
                                    let dz = z - lz;
                                    let speed = ((dx * dx + dz * dz).sqrt() / dt).abs();
                                    LAST_HORIZ_SPEED = speed;
                                }
                            }
                        }
                        LAST_LINK_POS_XZ = Some((x, z));
                        LAST_LINK_SAMPLE_TIME = Some(now);
                    }
                }

                // Thresholds
                const WALK_SPEED_ON: f32 = 0.35;  // unused in post-release mode (left for reference)
                const STOP_SPEED_OFF: f32 = 0.15; // original stop threshold (user-approved)
                const STOP_HOLD_MS: u64 = 200;    // original stop delay (user-approved)
                const ENGAGE_GRACE_MS: u64 = 750; // minimum time to keep hold before evaluating auto-off

                let cemu_focused = crate::focus::is_cemu_focused();
                let phys_down = crate::utils::check_key_press(sprint_vk as i32);

                // Track physical key transitions (distinct from our virtual hold)
                if phys_down && !SPRINT_PHYSICAL_DOWN {
                    // Only treat as physical press if we're not already holding via the mod
                    if !SPRINT_HELD_BY_MOD {
                        SPRINT_PHYSICAL_DOWN = true;
                        SPRINT_ARMED_FROM_PHYSICAL = true; // arm post-release

                        // If a hold is already active (rare), treat this as cancel intent
                        if SPRINT_TOGGLE_ACTIVE && SPRINT_HELD_BY_MOD {
                            crate::utils::send_vk(sprint_vk, false);
                            SPRINT_HELD_BY_MOD = false;
                            SPRINT_TOGGLE_ACTIVE = false;
                            STOPPED_SINCE = None;
                            SPRINT_ENGAGED_AT = None;
                            info!("[SPRINT] Canceled by physical press");
                        }
                    }
                } else if !phys_down && SPRINT_PHYSICAL_DOWN {
                    // Physical key was released
                    SPRINT_PHYSICAL_DOWN = false;

                    // Engage only if the press came from a real physical press (armed)
                    if SPRINT_ARMED_FROM_PHYSICAL {
                        if cemu_focused && !SPRINT_HELD_BY_MOD {
                            crate::utils::send_vk(sprint_vk, true);
                            SPRINT_HELD_BY_MOD = true;
                        }
                        SPRINT_TOGGLE_ACTIVE = true; // reuse same auto-off logic
                        STOPPED_SINCE = None;
                        SPRINT_ENGAGED_AT = Some(now);
                        info!("[SPRINT] Post-release hold engaged");
                    }

                    // Disarm after handling release
                    SPRINT_ARMED_FROM_PHYSICAL = false;
                }

                // Legacy toggle: engage when tapped while walking
                if !SPRINT_TOGGLE_ACTIVE {
                    // Legacy tap-to-toggle disabled; use post-release hold
                } else {
                    if cemu_focused {
                        if !SPRINT_HELD_BY_MOD {
                            crate::utils::send_vk(sprint_vk, true);
                            SPRINT_HELD_BY_MOD = true;
                        }
                    } else {
                        // Release while unfocused but keep logical state
                        if SPRINT_HELD_BY_MOD {
                            crate::utils::send_vk(sprint_vk, false);
                            SPRINT_HELD_BY_MOD = false;
                        }
                    }

                    // Auto-off when stopped (respect a short grace period after engagement)
                    let within_grace = SPRINT_ENGAGED_AT
                        .map(|t| (now.saturating_duration_since(t).as_millis() as u64) < ENGAGE_GRACE_MS)
                        .unwrap_or(false);

                    if !within_grace {
                        if LAST_HORIZ_SPEED <= STOP_SPEED_OFF {
                            if STOPPED_SINCE.is_none() { STOPPED_SINCE = Some(now); }
                            if let Some(ts) = STOPPED_SINCE {
                                if now.saturating_duration_since(ts).as_millis() as u64 >= STOP_HOLD_MS {
                                    if SPRINT_HELD_BY_MOD {
                                        crate::utils::send_vk(sprint_vk, false);
                                        SPRINT_HELD_BY_MOD = false;
                                    }
                                    SPRINT_TOGGLE_ACTIVE = false;
                                    STOPPED_SINCE = None;
                                    SPRINT_ENGAGED_AT = None;
                                    info!("[SPRINT] Auto-OFF (stopped)");
                                }
                            }
                        } else {
                            STOPPED_SINCE = None;
                        }
                    } else {
                        // During grace period, keep hold and reset stop timer
                        STOPPED_SINCE = None;
                    }
                }
            } else {
                // Sprint key not configured (0)
                static mut SPRINT_KEY_WARNING_LOGGED: bool = false;
                if !SPRINT_KEY_WARNING_LOGGED {
                    info!("[SPRINT] Sprint toggle is enabled but no sprint key is configured (sprint_key = 0)");
                    info!("[SPRINT] Please set 'sprint_key' in your config to the same key you use for sprint in Cemu");
                    SPRINT_KEY_WARNING_LOGGED = true;
                }
            }
        }

        // Early-out after sprint logic only if mod not active
        if !active {
            continue;
        }

            // Phase 3.1: Check if Magnesis is active for input handling
            let magnesis_is_active = should_magnesis_control_mouse();
            let config = utils::get_global_config();
            
            // Periodic retry logic for experimental magnesis initialization - only when magnesis is active
            if magnesis_is_active {
                static mut LAST_EXP_MAGNESIS_RETRY: Option<Instant> = None;
                let should_retry = LAST_EXP_MAGNESIS_RETRY.map_or(true, |t| t.elapsed() > Duration::from_millis(1250));
                
                if should_retry {
                    // Check if experimental magnesis is already initialized
                    let is_initialized = {
                        match magnesis_experimental::MAGNESIS_STATE.try_lock() {
                            Ok(state) => state.is_patched && state.is_nop_xyz_applied(),
                            Err(_) => false, // Assume not initialized if we can't get lock
                        }
                    };
                    
                    if !is_initialized {
                        debug!("[MAGNESIS_EXP] Periodic retry - attempting to initialize experimental magnesis from position finder...");
                        match magnesis_experimental::init_experimental_magnesis_from_shared_memory() {
                            Ok(_) => {
                                info!("[MAGNESIS_EXP] Successfully initialized experimental magnesis from position finder (periodic retry)");
                            }
                            Err(e) => {
                                debug!("[MAGNESIS_EXP] Periodic retry failed: {} (addresses only appear after using magnesis rune in-game)", e);
                            }
                        }
                    }
                    
                    LAST_EXP_MAGNESIS_RETRY = Some(Instant::now());
                }
            }

            // Use stabilized coordinate reading and direct camera updates
            let link_addr = g_link_position_addr;

            // Get or initialize orbit camera from global state
            let mut orbit_guard = camera::ORBIT_CAMERA.lock().unwrap();
            let orbit_cam = match orbit_guard.as_mut() {
                Some(cam) => cam,
                None => {
                    // Initialize new orbit camera
                    let mut new_cam = OrbitCamera::new();

                    // Get Link's position for initialization
                    let link_position = if link_addr != 0 {
                        match read_coordinates_safely(link_addr) {
                            Some((x, y, z)) => Some(glm::vec3(x, y, z)),
                            None => None
                        }
                    } else {
                        None
                    };

                    new_cam.initialize_from_camera(gc, link_position);
                    *orbit_guard = Some(new_cam);
                    orbit_guard.as_mut().unwrap()
                }
            };

            // Apply mouse input with immediate rotation (zero latency) - but only if magnesis isn't controlling mouse
            // When magnesis is active, don't apply mouse input to camera
            
            // Handle magnesis state - manage NOP patches dynamically instead of disabling camera completely
            // For experimental magnesis, wait for object movement before switching camera control
            static mut LAST_MAGNESIS_STATE: bool = false;
            if magnesis_is_active != LAST_MAGNESIS_STATE {
                if magnesis_is_active {
                    // EXPERIMENTAL MODE (always on): Activate control and protect rotation
                    orbit_cam.save_rotation_for_magnesis_protection();
                    magnesis_experimental::activate_magnesis_control();
                    info!("[MAGNESIS] EXPERIMENTAL: Mouse control of magnesis object activated with rotation protection");
                    log_infof!("MAGNESIS ACTIVE: EXPERIMENTAL mouse control enabled with rotation protection!");
                } else {
                    // Deactivate experimental magnesis control
                    magnesis_experimental::deactivate_magnesis_control();
                    // First sync to the game camera to avoid micro-shift, then restore FPS zoom
                    orbit_cam.sync_to_game_camera(gc);
                    orbit_cam.clear_magnesis_rotation_protection();
                }
                LAST_MAGNESIS_STATE = magnesis_is_active;
            }
            
            // Determine whether magnesis camera should actively control the view (after startup capture)
            let magnesis_camera_should_activate = magnesis_is_active && !magnesis_experimental::is_in_startup_capture_phase();
            
            // Update orbit camera when magnesis camera control is NOT active (waits for movement in experimental mode)
            // Also check if PhoneCamera is active to avoid zoom conflicts
            // Use current menu state to prevent any phonecamera effect while menu is open
            let menu_open_now = crate::menu_state::is_in_menu();
            let phonecamera_open = get_phonecamera_open_state();
            
            // Handle phone camera state changes
            if menu_open_now && phonecamera_open {
                // Menu just opened while phone camera was active - remove zoom immediately
                orbit_cam.remove_phonecamera_zoom();
                debug!("[PHONECAMERA] Menu opened - removing phone camera zoom");
            }
            if !magnesis_camera_should_activate {
                // If PhoneCamera is active and menu is closed, don't pass zoom to normal camera controls
                let zoom_input = if phonecamera_open && !menu_open_now { 0.0 } else { input.zoom };
                orbit_cam.update_orbit(input.orbit_x, input.orbit_y, zoom_input);
            } else {
                // When magnesis camera is active, don't update orbit camera from mouse input
                // For both normal and experimental magnesis, continuously enforce the saved rotation
                orbit_cam.enforce_magnesis_rotation_protection();
                
                static mut LAST_MAGNESIS_LOG: Option<std::time::Instant> = None;
                let should_log = LAST_MAGNESIS_LOG.map_or(true, |t| t.elapsed() > std::time::Duration::from_secs(3));
                if should_log {
                    info!("[MAGNESIS] Active - camera updates deferred; experimental magnesis using mouse input");
                    LAST_MAGNESIS_LOG = Some(std::time::Instant::now());
                }
            }
            
            // Only do camera processing when magnesis camera control is NOT active
            if !magnesis_camera_should_activate {
                // Handle middle mouse click to reset zoom ONLY (no rotation changes)
                // But only if PhoneCamera is not active (PhoneCamera handles its own reset)
                if input.reset_camera && !(phonecamera_open && !menu_open_now) {
                    orbit_cam.reset_zoom_to_default();
                    input.reset_camera = false; // consume
                }

                // Get current target position (Link's actual position with stabilized reading)
                let target_pos = if link_addr != 0 {
                    match read_coordinates_safely(link_addr) {
                        Some((x, y, z)) => {
                            let mut pos = glm::vec3(x, y, z);
                            // Add Y-offset to focus on Link's torso instead of feet
                            pos.y += 1.8;
                            pos
                        }
                        None => {
                            // Fallback to camera focus point if Link position unavailable
                            gc.focus.into()
                        }
                    }
                } else {
                    // Fallback to camera focus point
                    gc.focus.into()
                };

                // Update smooth player position (only for smooth following, not rotation)
                orbit_cam.smooth_position_update(target_pos);
            }

            // Read raw player state from multiple sources
            let mut raw_player_state = 0u8;
            
            // If we have a resolved runtime address, poll it each tick so we see state changes
            if g_runtime_player_state_addr != 0 {
                if let Some(val) = read_memory_safe(g_runtime_player_state_addr) {
                    raw_player_state = val;
                } else {
                    // Fallback to last known value if read fails
                    raw_player_state = g_runtime_player_state_value;
                }
            } else if let Some((addr, player_state_value)) = get_player_state_from_shared_memory() {
                // Use shared memory value and cache the address for continuous polling
                raw_player_state = player_state_value as u8;
                if addr != 0 {
                    g_runtime_player_state_addr = addr;
                }
            } else {
                // Last resort: keep last known value
                raw_player_state = g_runtime_player_state_value;
            }

            // Apply state stabilization to handle rapid oscillations
            let current_player_state = stabilize_player_state(raw_player_state);

            // Update the global value for other parts of the code
            g_runtime_player_state_value = current_player_state;
            
            // Debug player state changes - show raw vs stabilized states
            static mut LAST_LOGGED_RAW_STATE: u8 = 255;
            static mut LAST_LOGGED_STABLE_STATE: u8 = 255;
            static mut LAST_STATE_LOG: Option<Instant> = None;
            let should_log_state = LAST_STATE_LOG.map_or(true, |t| t.elapsed() > Duration::from_secs(2)); // Every 2 seconds
            
            // Always log stabilized state changes immediately
            if current_player_state != LAST_LOGGED_STABLE_STATE {
                info!("[PLAYER_STATE] Stabilized state changed: {} → {} (0=normal, 1=aiming, 3=aiming_bow) [addr=0x{:x}]", 
                      LAST_LOGGED_STABLE_STATE, current_player_state, g_runtime_player_state_addr);
                LAST_LOGGED_STABLE_STATE = current_player_state;
                LAST_STATE_LOG = Some(Instant::now());
            }
            
            // Log raw state changes when they differ from stabilized (shows oscillations)
            if raw_player_state != LAST_LOGGED_RAW_STATE {
                if raw_player_state != current_player_state {
                    debug!("[PLAYER_STATE] Raw oscillation: {} (stabilized: {}) [addr=0x{:x}]", 
                           raw_player_state, current_player_state, g_runtime_player_state_addr);
                }
                LAST_LOGGED_RAW_STATE = raw_player_state;
            }
            
            // Periodic status logging when phonecamera logging enabled
            if should_log_state && g_phonecamera_logging_enabled {
                if raw_player_state != current_player_state {
                    info!("[PLAYER_STATE] Status: raw={}, stable={} (oscillating) [addr=0x{:x}]", 
                          raw_player_state, current_player_state, g_runtime_player_state_addr);
                } else {
                    info!("[PLAYER_STATE] Status: {} (stable) [addr=0x{:x}]", 
                          current_player_state, g_runtime_player_state_addr);
                }
                LAST_STATE_LOG = Some(Instant::now());
            }

            // Handle PhoneCamera zoom before camera updates
            // Only apply phone camera effects when menu is closed
            if phonecamera_open && !menu_open_now {
                orbit_cam.apply_phonecamera_zoom();

                // FOV-based zoom for PhoneCamera: save original on entry and blend toward current target FOV
                {
                    let current_fov: f32 = gc.fov.into();
                    unsafe {
                        if !g_phonecamera_fov_saved {
                            g_phonecamera_original_fov = current_fov;
                            g_phonecamera_fov_saved = true;
                            // Initialize target FOV to base (2x of previous)
                            g_phonecamera_current_target_fov = PHONECAMERA_BASE_FOV;
                            info!("[PHONECAMERA] Saved original FOV: {:.3}; base target: {:.3}", g_phonecamera_original_fov, g_phonecamera_current_target_fov);
                        }
                    }
                    // Blend toward the current target FOV
                    unsafe {
                        let target = g_phonecamera_current_target_fov;
                        let fov_diff = target - current_fov;
                        if fov_diff.abs() > 0.001 {
                            let new_fov = current_fov + fov_diff * 0.6; // Much faster blend toward target
                            gc.fov = new_fov.into();
                        } else {
                            // Snap when very close
                            unsafe { gc.fov = g_phonecamera_current_target_fov.into(); }
                        }
                    }
                }
                
                // Handle PhoneCamera mouse wheel to adjust photo FOV (allow up to extreme zoom)
                if input.zoom != 0.0 {
                    unsafe {
                        let mut target = g_phonecamera_current_target_fov;
                        // Positive zoom => zoom in (reduce FOV). Negative => zoom out (increase FOV)
                        let step = 0.1; // about 15 steps from base (0.175) to min (0.025) assuming input.zoom~0.1
                        target -= input.zoom * step;
                        // Clamp to [MIN, BASE]
                        target = target.clamp(PHONECAMERA_MIN_FOV, PHONECAMERA_BASE_FOV);
                        g_phonecamera_current_target_fov = target;
                    }
                    input.zoom = 0.0; // Consume the zoom input
                }
                
                // Middle mouse click to reset photo FOV to base (2x) and keep camera at pivot
                if input.reset_camera {
                    orbit_cam.reset_phonecamera_zoom();
                    unsafe { g_phonecamera_current_target_fov = PHONECAMERA_BASE_FOV; }
                    input.reset_camera = false; // Consume the reset input
                    info!("[PHONECAMERA] Photo FOV reset to base: {:.3}", PHONECAMERA_BASE_FOV);
                }
            } else {
                // Remove phone camera zoom when not active or menu is open
                orbit_cam.remove_phonecamera_zoom();

                // Restore FOV toward original after exiting PhoneCamera
                unsafe {
                    if g_phonecamera_fov_saved {
                        let current_fov: f32 = gc.fov.into();
                        let diff = g_phonecamera_original_fov - current_fov;
                        if diff.abs() > 0.001 {
                            let new_fov = current_fov + diff * 0.35; // Faster return to original FOV
                            gc.fov = new_fov.into();
                        } else {
                            // Snap to original and clear saved flag
                            gc.fov = g_phonecamera_original_fov.into();
                            g_phonecamera_fov_saved = false;
                            // Reset target for next time
                            g_phonecamera_current_target_fov = PHONECAMERA_BASE_FOV;
                            info!("[PHONECAMERA] Restored original FOV: {:.3}", g_phonecamera_original_fov);
                        }
                    }
                }
            }

            // Update camera position/focus/rotation based on magnesis state
            if !magnesis_camera_should_activate {
                // NORMAL MODE: Use mod's orbit camera system
                // HYBRID APPROACH: smooth position following + immediate mouse rotation
                // Get immediate camera position using smoothed focus (no OrbitCamera modifications)
                let smooth_focus = orbit_cam.smooth_player_pos;
                let new_pos = orbit_cam.get_immediate_camera_position(smooth_focus);

                // Update base camera from orbit calculation (normal camera processing)
                gc.pos = new_pos.into();

                // Focus behavior:
                // - Normal mode: focus stays on the player (smooth_focus)
                // - PhoneCamera mode: focus is pushed AHEAD of the camera along the current view direction
                if (phonecamera_open && !menu_open_now) || orbit_cam.phonecamera_zoom_active {
                    // Compute base direction from orbit angles (focus -> camera), then look the opposite way
                    let dir_x = orbit_cam.phi.sin() * orbit_cam.theta.cos();
                    let dir_y = orbit_cam.phi.cos();
                    let dir_z = orbit_cam.phi.sin() * orbit_cam.theta.sin();
                    let dir = glm::normalize(&glm::vec3(dir_x, dir_y, dir_z));

                    let ahead_dist = orbit_cam.distance.abs().max(5.0) + 10.0;
                    // Look AWAY from the player (behind), i.e. along -dir from camera position
                    let final_focus = new_pos - dir * ahead_dist;
                    gc.focus = final_focus.into();
                } else {
                    gc.focus = smooth_focus.into();
                }

                // Apply simple precision mode AFTER orbit calculation (avoids conflicts)
                apply_precision_mode_simple(gc, current_player_state);

                // Ensure PhoneCamera FOV override wins over aim blending (if any)
                if (phonecamera_open && !menu_open_now) || orbit_cam.phonecamera_zoom_active {
                    let current_fov: f32 = gc.fov.into();
                    unsafe {
                        let target = g_phonecamera_current_target_fov;
                        let fov_diff = target - current_fov;
                        if fov_diff.abs() > 0.001 {
                            let new_fov = current_fov + fov_diff * 0.6;
                            gc.fov = new_fov.into();
                        } else {
                            gc.fov = target.into(); // Snap when close
                        }
                    }
                }

                // Enforce rotation protection only when magnesis camera control is active
                // During startup-capture (before NOPing), keep normal orbit updates responsive
                if magnesis_camera_should_activate {
                    orbit_cam.enforce_magnesis_rotation_protection();
                    // Final reinforcement to ensure saved rotation is applied when active
                    orbit_cam.enforce_magnesis_rotation_protection();
                }
                
                // Calculate rotation (up vector) using focus for stability
                let final_pos: glm::Vec3 = gc.pos.into();
                let final_focus: glm::Vec3 = gc.focus.into();
                let up = glm::vec3(0.0, 1.0, 0.0);
                let forward = glm::normalize(&(final_focus - final_pos));
                let right = glm::normalize(&glm::cross::<f32, glm::U3>(&forward, &up));
                let camera_up = glm::cross::<f32, glm::U3>(&right, &forward);

                gc.rot = camera_up.into();
            } else {
                // MAGNESIS MODE
                if let Some((obj_x, obj_y, obj_z)) = crate::magnesis_experimental::get_current_magnesis_position() {
                    let cfg = utils::get_global_config();
                    if cfg.experimental_magnesis_fps_camera {
                        // FPS camera: fix camera at player head; only rotate to face object (no vertical follow of object)
                        let mut head_opt: Option<glm::Vec3> = None;
                        if link_addr != 0 {
                            if let Some((px, py, pz)) = read_coordinates_safely(link_addr) {
                                head_opt = Some(glm::vec3(px, py + 1.8, pz));
                            }
                        }
                        if head_opt.is_none() {
                            if let Some((bpx, bpy, bpz)) = crate::magnesis_experimental::get_base_player_position() {
                                head_opt = Some(glm::vec3(bpx, bpy + 1.8, bpz));
                            }
                        }
                        if let Some(head_pos) = head_opt {
                            // Smooth the focus on the object to avoid snaps when target changes abruptly
                            let smoothed_focus = orbit_cam.update_magnesis_focus(glm::vec3(obj_x, obj_y, obj_z));
                            // Apply FPS camera: position at head, focus on object
                            gc.pos = head_pos.into();
                            gc.focus = smoothed_focus.into();
                            // Compute rotation to face the object
                            let up = glm::vec3(0.0, 1.0, 0.0);
                            let forward = glm::normalize(&(smoothed_focus - head_pos));
                            let right = glm::normalize(&glm::cross::<f32, glm::U3>(&forward, &up));
                            let camera_up = glm::cross::<f32, glm::U3>(&right, &forward);
                            gc.rot = camera_up.into();
                        } else {
                            // Fallback to third-person behavior if we cannot resolve a head position
                            if let Some((base_obj_x, base_obj_y, base_obj_z)) = crate::magnesis_experimental::get_base_magnesis_position() {
                                if let Some((base_player_x, base_player_y, base_player_z)) = crate::magnesis_experimental::get_base_player_position() {
                                    if link_addr != 0 {
                                        if let Some((current_player_x, current_player_y, current_player_z)) = read_coordinates_safely(link_addr) {
                                            // Use BASE positions for all distance/focus calculations (completely stable)
                                            let base_dx = base_obj_x - base_player_x;
                                            let base_dz = base_obj_z - base_player_z;
                                            let base_horizontal_distance = (base_dx * base_dx + base_dz * base_dz).sqrt().max(1.0);
                                            
                                            // Use CURRENT Y difference for vertical behavior (responsive to vertical movement only)
                                            let base_dy = base_obj_y - base_player_y;
                                            let current_dy = obj_y - current_player_y;
                                            let vertical_change = current_dy - base_dy; // how much Y has changed from base
                                            
                                            // Calculate current object direction for focus calculation only
                                            let current_dx = obj_x - current_player_x;
                                            let current_dz = obj_z - current_player_z;
                                            
                                            // Camera distance: use original stable calculation (no dynamic scaling)
                                            let height_factor = (vertical_change / base_horizontal_distance).max(-1.0);
                                            let distance_multiplier = 1.0 + height_factor * 0.140625; // Original height-based adjustment
                                            let camera_distance = base_horizontal_distance * 1.875 * distance_multiplier; // Original stable distance
                                            
                                            // Camera height: smooth transition zone between 4.5m and 5.5m (1 meter transition)
                                            let normal_camera_height = {
                                                let base_camera_height = base_player_y + 4.0;
                                                let dynamic_height_offset = height_factor * 2.5;
                                                base_camera_height + dynamic_height_offset
                                            };
                                            
                                            let above_object_height = obj_y + 5.0;  // Camera 5m above object mode
                                            
                                            let target_camera_height = if obj_y <= 4.5 {
                                                // Below 4.5m: use normal camera height calculation
                                                normal_camera_height
                                            } else if obj_y >= 5.5 {
                                                // Above 5.5m: use above-object mode (5m above object)
                                                above_object_height
                                            } else {
                                                // Transition zone (4.5m to 5.5m): smooth interpolation between modes
                                                let transition_progress = (obj_y - 4.5) / 1.0;  // 0.0 at 4.5m, 1.0 at 5.5m
                                                let smoothed_progress = transition_progress * transition_progress * (3.0 - 2.0 * transition_progress); // Smooth step function
                                                
                                                // Linear interpolation between normal and above-object heights
                                                normal_camera_height * (1.0 - smoothed_progress) + above_object_height * smoothed_progress
                                            };
                                            
                                            // Persistent camera height for smooth transitions
                                            static mut PERSISTENT_CAMERA_Y: f32 = 0.0;
                                            static mut CAMERA_Y_INITIALIZED: bool = false;
                                            
                                            let mut camera_y = unsafe {
                                                if !CAMERA_Y_INITIALIZED {
                                                    PERSISTENT_CAMERA_Y = normal_camera_height;
                                                    CAMERA_Y_INITIALIZED = true;
                                                }
                                                
                                                // Smooth transition with 20% blend per frame (much faster)
                                                PERSISTENT_CAMERA_Y = PERSISTENT_CAMERA_Y + (target_camera_height - PERSISTENT_CAMERA_Y) * 0.2;
                                                PERSISTENT_CAMERA_Y
                                            };

                                            // Enforce a floor on camera Y during magnesis so it doesn't drop below the starting height
                                            if let Ok(mut min_lock) = crate::camera::MAGNESIS_CAMERA_MIN_Y.lock() {
                                                match *min_lock {
                                                    Some(min_y) => {
                                                        if camera_y < min_y {
                                                            camera_y = min_y;
                                                            // Keep the persistent value in sync with the clamped value
                                                            unsafe { PERSISTENT_CAMERA_Y = camera_y; }
                                                        }
                                                    }
                                                    None => {
                                                        // Anchor the floor at the first computed height in magnesis mode
                                                        *min_lock = Some(camera_y);
                                                    }
                                                }
                                            }
                                            
                                            // Debug camera height calculations (throttled)
                                            {
                                                use std::time::{Duration, Instant};
                                                static mut LAST_HEIGHT_LOG: Option<Instant> = None;
                                                let now = Instant::now();
                                                let should_log = unsafe { LAST_HEIGHT_LOG.map_or(true, |t| now.duration_since(t) > Duration::from_millis(500)) };
                                                if should_log {
                                                    if obj_y > 4.5 && obj_y < 5.5 {
                                                        let transition_progress = (obj_y - 4.5) / 1.0;
                                                        info!("[CAMERA_HEIGHT] obj_y={:.2}, TRANSITION_ZONE (4.5-5.5m), progress={:.2}, normal_height={:.2}, above_obj_height={:.2}, target_height={:.2}, final_camera_y={:.2}", 
                                                              obj_y, transition_progress, normal_camera_height, above_object_height, target_camera_height, camera_y);
                                                        info!("[CAMERA_DISTANCE] base_dist={:.2}, height_factor={:.2}, dist_mult={:.3}, final_camera_dist={:.2}", 
                                                              base_horizontal_distance, height_factor, distance_multiplier, camera_distance);
                                                    } else {
                                                        let mode = if obj_y <= 4.5 { "NORMAL" } else { "ABOVE_OBJECT" };
                                                        info!("[CAMERA_HEIGHT] obj_y={:.2}, mode={}, normal_height={:.2}, target_height={:.2}, final_camera_y={:.2}", 
                                                              obj_y, mode, normal_camera_height, target_camera_height, camera_y);
                                                        info!("[CAMERA_DISTANCE] base_dist={:.2}, height_factor={:.2}, dist_mult={:.3}, final_camera_dist={:.2}", 
                                                              base_horizontal_distance, height_factor, distance_multiplier, camera_distance);
                                                    }
                                                    unsafe { LAST_HEIGHT_LOG = Some(now); }
                                                }
                                            }
                                            
                                            // Focus point: Only shifts based on vertical movement (height), not horizontal push/pull
                                            // X and Z focus always remain at 50/50 midpoint between player and object
                                            // Y focus shifts from 50/50 to 75% object, 25% player based on height
                                            let max_vertical_change = 20.0; // Maximum vertical movement limit
                                            let height_blend_factor = (vertical_change / max_vertical_change).clamp(0.0, 1.0);
                                            // Interpolate from 0.5 (50/50) to 0.75 (75% object, 25% player) for Y only
                                            let object_weight_y = 0.5 + (0.25 * height_blend_factor);
                                            let player_weight_y = 1.0 - object_weight_y;
                                            
                                            // X and Z focus calculated using actual object position (follows push/pull movements)
                                            // Use the actual current object position for smooth midpoint tracking
                                            let focus_x = (current_player_x + obj_x) * 0.5;
                                            let focus_y = (base_player_y + 1.8) * player_weight_y + base_obj_y * object_weight_y + vertical_change * object_weight_y;
                                            let focus_z = (current_player_z + obj_z) * 0.5;
                                            let focus = glm::vec3(focus_x, focus_y, focus_z);
                                            
                                            // Direction from CURRENT object to CURRENT player (camera follows current positions)
                                            // (current_dx and current_dz already calculated above)
                                            let mut dir = glm::vec3(-current_dx, 0.0, -current_dz); // negative to get behind player
                                            let dir_len = glm::length(&dir);
                                            if dir_len > 0.001 {
                                                dir = glm::normalize(&dir);
                                                
                                                // Position camera behind CURRENT player, using stable distance and height
                                                let camera_x = current_player_x + dir.x * camera_distance;
                                                let camera_z = current_player_z + dir.z * camera_distance;
                                                
                                                let camera_pos = glm::vec3(camera_x, camera_y, camera_z);
                                                
                                                // Apply camera position and focus
                                                gc.pos = camera_pos.into();
                                                gc.focus = focus.into();
                                                
                                                // Calculate rotation based on camera looking at focus
                                                let up = glm::vec3(0.0, 1.0, 0.0);
                                                let forward = glm::normalize(&(focus - camera_pos));
                                                let right = glm::normalize(&glm::cross::<f32, glm::U3>(&forward, &up));
                                                let camera_up = glm::cross::<f32, glm::U3>(&right, &forward);
                                                gc.rot = camera_up.into();
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        // Third-person magnesis camera (existing behavior)
                        if let Some((base_obj_x, base_obj_y, base_obj_z)) = crate::magnesis_experimental::get_base_magnesis_position() {
                            if let Some((base_player_x, base_player_y, base_player_z)) = crate::magnesis_experimental::get_base_player_position() {
                                if link_addr != 0 {
                                    if let Some((current_player_x, current_player_y, current_player_z)) = read_coordinates_safely(link_addr) {
                                        // Use BASE positions for all distance/focus calculations (completely stable)
                                        let base_dx = base_obj_x - base_player_x;
                                        let base_dz = base_obj_z - base_player_z;
                                        let base_horizontal_distance = (base_dx * base_dx + base_dz * base_dz).sqrt().max(1.0);
                                        
                                        // Use CURRENT Y difference for vertical behavior (responsive to vertical movement only)
                                        let base_dy = base_obj_y - base_player_y;
                                        let current_dy = obj_y - current_player_y;
                                        let vertical_change = current_dy - base_dy; // how much Y has changed from base
                                        
                                        // Calculate current object direction for focus calculation only
                                        let current_dx = obj_x - current_player_x;
                                        let current_dz = obj_z - current_player_z;
                                        
                                        // Camera distance: use original stable calculation (no dynamic scaling)
                                        let height_factor = (vertical_change / base_horizontal_distance).max(-1.0);
                                        let distance_multiplier = 1.0 + height_factor * 0.140625; // Original height-based adjustment
                                        let camera_distance = base_horizontal_distance * 1.875 * distance_multiplier; // Original stable distance
                                        
                                        // Camera height: smooth transition zone between 4.5m and 5.5m (1 meter transition)
                                        let normal_camera_height = {
                                            let base_camera_height = base_player_y + 4.0;
                                            let dynamic_height_offset = height_factor * 2.5;
                                            base_camera_height + dynamic_height_offset
                                        };
                                        
                                        let above_object_height = obj_y + 5.0;  // Camera 5m above object mode
                                        
                                        let target_camera_height = if obj_y <= 4.5 {
                                            // Below 4.5m: use normal camera height calculation
                                            normal_camera_height
                                        } else if obj_y >= 5.5 {
                                            // Above 5.5m: use above-object mode (5m above object)
                                            above_object_height
                                        } else {
                                            // Transition zone (4.5m to 5.5m): smooth interpolation between modes
                                            let transition_progress = (obj_y - 4.5) / 1.0;  // 0.0 at 4.5m, 1.0 at 5.5m
                                            let smoothed_progress = transition_progress * transition_progress * (3.0 - 2.0 * transition_progress); // Smooth step function
                                            
                                            // Linear interpolation between normal and above-object heights
                                            normal_camera_height * (1.0 - smoothed_progress) + above_object_height * smoothed_progress
                                        };
                                        
                                        // Persistent camera height for smooth transitions
                                        static mut PERSISTENT_CAMERA_Y: f32 = 0.0;
                                        static mut CAMERA_Y_INITIALIZED: bool = false;
                                        
                                        let mut camera_y = unsafe {
                                            if !CAMERA_Y_INITIALIZED {
                                                PERSISTENT_CAMERA_Y = normal_camera_height;
                                                CAMERA_Y_INITIALIZED = true;
                                            }
                                            
                                            // Smooth transition with 20% blend per frame (much faster)
                                            PERSISTENT_CAMERA_Y = PERSISTENT_CAMERA_Y + (target_camera_height - PERSISTENT_CAMERA_Y) * 0.2;
                                            PERSISTENT_CAMERA_Y
                                        };

                                        // Enforce a floor on camera Y during magnesis so it doesn't drop below the starting height
                                        if let Ok(mut min_lock) = crate::camera::MAGNESIS_CAMERA_MIN_Y.lock() {
                                            match *min_lock {
                                                Some(min_y) => {
                                                    if camera_y < min_y {
                                                        camera_y = min_y;
                                                        // Keep the persistent value in sync with the clamped value
                                                        unsafe { PERSISTENT_CAMERA_Y = camera_y; }
                                                    }
                                                }
                                                None => {
                                                    // Anchor the floor at the first computed height in magnesis mode
                                                    *min_lock = Some(camera_y);
                                                }
                                            }
                                        }
                                        
                                        // Focus point: Only shifts based on vertical movement (height), not horizontal push/pull
                                        // X and Z focus always remain at 50/50 midpoint between player and object
                                        // Y focus shifts from 50/50 to 75% object, 25% player based on height
                                        let max_vertical_change = 20.0; // Maximum vertical movement limit
                                        let height_blend_factor = (vertical_change / max_vertical_change).clamp(0.0, 1.0);
                                        // Interpolate from 0.5 (50/50) to 0.75 (75% object, 25% player) for Y only
                                        let object_weight_y = 0.5 + (0.25 * height_blend_factor);
                                        let player_weight_y = 1.0 - object_weight_y;
                                        
                                        // X and Z focus calculated using actual object position (follows push/pull movements)
                                        // Use the actual current object position for smooth midpoint tracking
                                        let focus_x = (current_player_x + obj_x) * 0.5;
                                        let focus_y = (base_player_y + 1.8) * player_weight_y + base_obj_y * object_weight_y + vertical_change * object_weight_y;
                                        let focus_z = (current_player_z + obj_z) * 0.5;
                                        let focus = glm::vec3(focus_x, focus_y, focus_z);
                                        
                                        // Direction from CURRENT object to CURRENT player (camera follows current positions)
                                        // (current_dx and current_dz already calculated above)
                                        let mut dir = glm::vec3(-current_dx, 0.0, -current_dz); // negative to get behind player
                                        let dir_len = glm::length(&dir);
                                        if dir_len > 0.001 {
                                            dir = glm::normalize(&dir);
                                            
                                            // Position camera behind CURRENT player, using stable distance and height
                                            let camera_x = current_player_x + dir.x * camera_distance;
                                            let camera_z = current_player_z + dir.z * camera_distance;
                                            
                                            let camera_pos = glm::vec3(camera_x, camera_y, camera_z);
                                            
                                            // Apply camera position and focus
                                            gc.pos = camera_pos.into();
                                            gc.focus = focus.into();
                                            
                                            // Calculate rotation based on camera looking at focus
                                            let up = glm::vec3(0.0, 1.0, 0.0);
                                            let forward = glm::normalize(&(focus - camera_pos));
                                            let right = glm::normalize(&glm::cross::<f32, glm::U3>(&forward, &up));
                                            let camera_up = glm::cross::<f32, glm::U3>(&right, &forward);
                                            gc.rot = camera_up.into();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                // Normal magnesis mode: NOP patches remain active, but rotation is protected
                // Camera position can be updated by the mod (following the object), but rotation is locked
                // to the value saved when magnesis was activated, preventing camera angle changes.
            }
        }

        // DEBUGGING: Check magnesis breakpoint status and re-establishment
        unsafe {
            static mut DEBUG_COUNTER: u32 = 0;
            DEBUG_COUNTER += 1;
            
            // Reduce debug spam - only log every 10 seconds instead of every 1 second
            if DEBUG_COUNTER % 10000 == 0 {
                let magnesis_x_addr = get_magnesis_x_address_from_shared_memory();
                let magnesis_active = should_magnesis_control_mouse();
                info!("[MAGNESIS_DEBUG] Breakpoint addr: 0x{:x}, Shared mem addr: {:?}, Active: {}, Enabled: {}", 
                      g_magnesis_breakpoint_addr, magnesis_x_addr, magnesis_active, g_magnesis_enabled_state);
                
                if let Some(last_update) = g_magnesis_last_update_time {
                    let elapsed = last_update.elapsed().as_millis();
                    info!("[MAGNESIS_DEBUG] Last update: {}ms ago", elapsed);
                }
            }
            
            // Check EVERY loop iteration if magnesis breakpoint needs re-establishment
            if g_magnesis_breakpoint_addr == 0 {
                if let Some(magnesis_x_addr) = get_magnesis_x_address_from_shared_memory() {
                    if setup_magnesis_x_breakpoint(magnesis_x_addr) {
                        // Reduce spam - only log occasionally when re-establishing breakpoints
                        if DEBUG_COUNTER % 1000 == 0 { // Log every 10 seconds instead of every second
                            info!("[MAGNESIS_DEBUG] Re-established breakpoint at 0x{:x}", magnesis_x_addr);
                        }
                    } else {
                        if DEBUG_COUNTER % 1000 == 0 {
                            info!("[MAGNESIS_DEBUG] Failed to re-establish breakpoint at 0x{:x}", magnesis_x_addr);
                        }
                    }
                }
            } else {
                // Comment out this noisy debug message - it's not useful for end users
                // if DEBUG_COUNTER % 5000 == 0 { // Every ~5 seconds
                //     info!("[MAGNESIS_DEBUG] Breakpoint supposedly active at 0x{:x}, but no recent updates", g_magnesis_breakpoint_addr);
                // }
            }
        }

        // Update Magnesis monitoring system (tracks memory updates to detect enable/disable)
        update_magnesis_monitoring();
        
        // No magnesis coordinate modification - magnesis detection only

        // Keyboard fallback emulation when camera mode is ON (works with Cemu keyboard mappings)
        // This runs ALWAYS when camera mode is active (gamepad functionality is now unified)
        utils::keyboard_emulation_tick(active);



        input.reset();

        
        // MAXIMUM FREQUENCY UPDATES: Absolute zero lag and perfect high-speed tracking
        // Optimized for 960Hz+ displays and ultra-smooth high-speed movement
        std::thread::sleep(std::time::Duration::from_micros(833)); // ~1200Hz updates for perfect responsiveness
    }

    // Clean up mouse input and external processes
    utils::cleanup_mouse_input();
    cleanup_all_breakpoints(); // CRITICAL: Restore all original code before exit
    cleanup_external_position_finder();
    cleanup_menu_state_detection();
    magnesis_experimental::cleanup_magnesis_experimental(); // Clean up experimental magnesis patches

    Ok(())
}



#[no_mangle]
pub unsafe extern "system" fn DllMain(
    hinstance: *mut std::ffi::c_void,
    fdw_reason: DWORD,
    _lpv_reserved: *mut std::ffi::c_void,
) -> BOOL {
    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            // Disable thread attach/detach notifications to improve performance
            DisableThreadLibraryCalls(hinstance as _);
            
            // Convert pointer to usize for thread safety
            let hinstance_addr = hinstance as usize;
            
            // Start the main wrapper thread
            let _handle = std::thread::spawn(move || {
                wrapper(hinstance_addr as *mut std::ffi::c_void);
            });
            
            TRUE
        }
        DLL_PROCESS_DETACH => {
            // CRITICAL: Clean up all breakpoints and restore original instructions
            println!("RUST DLL: Process detaching - cleaning up all breakpoints...");
            
            // CRITICAL: Always cleanup experimental magnesis NOPs on process detach
            // This ensures any NOPed MOVBE instructions are restored
            magnesis_experimental::cleanup_magnesis_experimental();
            
            cleanup_all_breakpoints();
            cleanup_external_position_finder();
            
            // Also call menu state cleanup if available
            #[allow(unused_unsafe)]
            unsafe {
                crate::menu_state::cleanup_menu_state_detection();
            }
            
            println!("RUST DLL: Process detach cleanup completed");
            TRUE
        }
        _ => TRUE,
    }
}
