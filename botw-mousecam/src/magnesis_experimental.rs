// Experimental magnesis control module - direct mouse control of magnesis coordinates
use crate::{info, warn, debug};
use std::sync::atomic::{AtomicUsize, Ordering};

// Define constants for exception handling
const EXCEPTION_BREAKPOINT: u32 = 0x80000003;
const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

// Size of these MOVBE store instructions in this site (REX + 0F 38 F1 + ModRM + SIB + disp8)
const MOVBE_SIZE: usize = 7;

// Standard MOVBE instruction bytes (these are the actual original instructions we need to restore)
// Pattern: REX + 0F 38 F1 + ModRM + SIB + disp8 for experimental magnesis MOVBE instructions
const MOVBE_X_BYTES: [u8; 7] = [0x45, 0x0F, 0x38, 0xF1, 0x74, 0x2D, 0x68]; // CORRECTED: movbe [r13+rbp*1+0x68], r14d  
const MOVBE_Y_BYTES: [u8; 7] = [0x45, 0x0F, 0x38, 0xF1, 0x74, 0x2D, 0x6C]; // CORRECTED: movbe [r13+rbp*1+0x6C], r14d
const MOVBE_Z_BYTES: [u8; 7] = [0x45, 0x0F, 0x38, 0xF1, 0x74, 0x2D, 0x70]; // CORRECTED: movbe [r13+rbp*1+0x70], r14d

// Fixed positioning constants for magnesis objects
const MIN_ORBIT_RADIUS: f32 = 1.5;     // minimum distance from Link in meters
const START_HEIGHT_OFFSET: f32 = 1.8;  // object at player torso level (1.8m above player feet)
const OBJECT_START_DISTANCE: f32 = 2.25; // object starts 2.25m in front of player (50% further)

// Limit how much the angle can change per tick so movement follows the orbit arc
// With ~1200Hz updates, 0.25 rad/tick lets 180° turn complete in ~6ms (fast but arc-correct)
const MAX_ANGLE_STEP: f32 = 0.25; // radians per tick (~14.3°)

// Global state for magnesis control
lazy_static::lazy_static! {
    pub static ref MAGNESIS_STATE: std::sync::Mutex<MagnesisControlState> = std::sync::Mutex::new(MagnesisControlState::new());
}

#[derive(Debug)]
pub struct MagnesisControlState {
    // Base addresses for the 3 MOVBE instructions (X, Y, Z)
    movbe_x_addr: usize,
    movbe_y_addr: usize,
    movbe_z_addr: usize,
    
    // Destination addresses where MOVBE instructions write coordinates
    dest_x_addr: usize,
    dest_y_addr: usize,
    dest_z_addr: usize,
    
    // Per-axis readiness flags (each MOVBE computes its own dest using its own R13/RBP)
    x_addr_ready: bool,
    y_addr_ready: bool,
    z_addr_ready: bool,
    
    // Whether all three destination addresses have been calculated
    addresses_calculated: bool,
    
    // Experimental MOVBE breakpoint handlers (using AtomicUsize for thread safety)
    x_exception_handler: AtomicUsize,
    y_exception_handler: AtomicUsize, 
    z_exception_handler: AtomicUsize,
    
    // Original bytes for breakpoints
    original_x_breakpoint_byte: u8,
    original_y_breakpoint_byte: u8,
    original_z_breakpoint_byte: u8,
    
    // Manual coordinate override system (no detours needed)
    coordinate_override_enabled: bool,
    
    // Current magnesis object position (world coordinates)
    current_x: f32,
    current_y: f32,
    current_z: f32,
    
    // Base position for relative movement
    base_x: f32,
    base_y: f32,
    base_z: f32,
    // Orbit params relative to player (Link)
    base_radius: f32,
    base_angle: f32, // radians, atan2(dz, dx) relative to player
    
    // Mouse delta accumulator
    mouse_delta_x: f32,
    mouse_delta_y: f32,
    mouse_wheel_delta: f32,
    
    // Control state
    pub is_patched: bool,
    is_active: bool,

    // Whether we've NOP'ed X, Y and Z MOVBE instructions
    nop_xyz_applied: bool,

    // Startup capture state: wait for first valid position (first sample is wrong)
    awaiting_first_valid_start: bool,
    initial_sample: Option<(f32, f32, f32)>,
    
    // Camera reset tracking
    camera_position_needs_reset: bool,
}

impl MagnesisControlState {
    fn new() -> Self {
        Self {
            movbe_x_addr: 0,
            movbe_y_addr: 0,
            movbe_z_addr: 0,
            dest_x_addr: 0,
            dest_y_addr: 0,
            dest_z_addr: 0,
            x_addr_ready: false,
            y_addr_ready: false,
            z_addr_ready: false,
            addresses_calculated: false,
            x_exception_handler: AtomicUsize::new(0),
            y_exception_handler: AtomicUsize::new(0),
            z_exception_handler: AtomicUsize::new(0),
            original_x_breakpoint_byte: 0,
            original_y_breakpoint_byte: 0,
            original_z_breakpoint_byte: 0,
            coordinate_override_enabled: false,
            current_x: 0.0,
            current_y: 0.0,
            current_z: 0.0,
            base_x: 0.0,
            base_y: 0.0,
            base_z: 0.0,
            base_radius: 0.0,
            base_angle: 0.0,
            mouse_delta_x: 0.0,
            mouse_delta_y: 0.0,
            mouse_wheel_delta: 0.0,
            is_patched: false,
            is_active: false,
            nop_xyz_applied: false,
            awaiting_first_valid_start: false,
            initial_sample: None,
            camera_position_needs_reset: false,
        }
    }

    // Public getter for nop_xyz_applied field
    pub fn is_nop_xyz_applied(&self) -> bool {
        self.nop_xyz_applied
    }
}


// Initialize experimental magnesis control using addresses from position finder
pub fn init_experimental_magnesis_from_shared_memory() -> Result<(), String> {
    let mut state = MAGNESIS_STATE.lock().unwrap();
    
    if state.is_patched {
        return Ok(()); // Already initialized
    }
    
    info!("[MAGNESIS_EXP] Initializing experimental magnesis control from shared memory...");
    
    // Get MOVBE addresses from position finder via shared memory
    let (x_addr, y_addr, z_addr) = get_magnesis_addresses_from_shared_memory()?;
    
    state.movbe_x_addr = x_addr;
    state.movbe_y_addr = y_addr; 
    state.movbe_z_addr = z_addr;
    
    info!("[MAGNESIS_EXP] MOVBE addresses from position finder:");
    info!("  X: 0x{:x}", state.movbe_x_addr);
    info!("  Y: 0x{:x}", state.movbe_y_addr);
    info!("  Z: 0x{:x}", state.movbe_z_addr);
    
    // Read current bytes from memory and compare with our hardcoded values
    unsafe {
        // Read actual bytes from memory
        let mut actual_x_bytes: [u8; MOVBE_SIZE] = [0; MOVBE_SIZE];
        let mut actual_y_bytes: [u8; MOVBE_SIZE] = [0; MOVBE_SIZE];
        let mut actual_z_bytes: [u8; MOVBE_SIZE] = [0; MOVBE_SIZE];
        
        std::ptr::copy_nonoverlapping(state.movbe_x_addr as *const u8, actual_x_bytes.as_mut_ptr(), MOVBE_SIZE);
        std::ptr::copy_nonoverlapping(state.movbe_y_addr as *const u8, actual_y_bytes.as_mut_ptr(), MOVBE_SIZE);
        std::ptr::copy_nonoverlapping(state.movbe_z_addr as *const u8, actual_z_bytes.as_mut_ptr(), MOVBE_SIZE);
        
        info!("[MAGNESIS_EXP] Current bytes in memory:");
        info!("  X (0x{:x}): [{}]", state.movbe_x_addr, actual_x_bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
        info!("  Y (0x{:x}): [{}]", state.movbe_y_addr, actual_y_bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
        info!("  Z (0x{:x}): [{}]", state.movbe_z_addr, actual_z_bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
        
        info!("[MAGNESIS_EXP] Expected hardcoded bytes:");
        info!("  X: [{}]", MOVBE_X_BYTES.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
        info!("  Y: [{}]", MOVBE_Y_BYTES.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
        info!("  Z: [{}]", MOVBE_Z_BYTES.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
        
        // Check if they match
        let x_match = actual_x_bytes == MOVBE_X_BYTES;
        let y_match = actual_y_bytes == MOVBE_Y_BYTES;
        let z_match = actual_z_bytes == MOVBE_Z_BYTES;
        
        if x_match && y_match && z_match {
            info!("[MAGNESIS_EXP] ✓ All hardcoded bytes match current memory! Safe to proceed.");
        } else {
            warn!("[MAGNESIS_EXP] ⚠ Hardcoded bytes don't match memory:");
            if !x_match { warn!("  X mismatch!"); }
            if !y_match { warn!("  Y mismatch!"); }
            if !z_match { warn!("  Z mismatch!"); }
            warn!("[MAGNESIS_EXP] This may cause crashes during restoration!");
        }
    }
    
    // Destination addresses will be calculated dynamically on first breakpoint hit (X/Y/Z)
    info!("[MAGNESIS_EXP] Waiting for runtime breakpoint to compute destination addresses");
    
    Ok(())
}

// Get experimental magnesis MOVBE addresses from position finder via shared memory
fn get_magnesis_addresses_from_shared_memory() -> Result<(usize, usize, usize), String> {
    use crate::g_shared_position_data;
    
    unsafe {
        if g_shared_position_data.is_null() {
            return Err("Shared memory not initialized".to_string());
        }
        
        let shared_data = &*g_shared_position_data;
        
        // Check if all three EXPERIMENTAL magnesis addresses are valid
        if shared_data.exp_magnesis_x_valid == 0 || 
           shared_data.exp_magnesis_y_valid == 0 || 
           shared_data.exp_magnesis_z_valid == 0 {
            return Err("Experimental magnesis MOVBE addresses not available from position finder".to_string());
        }
        
        let x_addr = shared_data.exp_magnesis_x_address as usize;
        let y_addr = shared_data.exp_magnesis_y_address as usize;
        let z_addr = shared_data.exp_magnesis_z_address as usize;
        
        if x_addr == 0 || y_addr == 0 || z_addr == 0 {
            return Err("Invalid experimental magnesis MOVBE addresses from position finder".to_string());
        }
        
        Ok((x_addr, y_addr, z_addr))
    }
}

// Calculate destination addresses using captured register values
fn calculate_experimental_dest_addresses(r13: u64, rbp: u64) {
    let r13 = r13 as usize;
    let rbp = rbp as usize;
    if let Ok(mut state) = MAGNESIS_STATE.lock() {
        state.dest_x_addr = r13 + rbp + 0x68;
        state.dest_y_addr = r13 + rbp + 0x6C;
        state.dest_z_addr = r13 + rbp + 0x70;
        state.addresses_calculated = true;
        info!("[MAGNESIS_EXP] Calculated destination addresses using r13=0x{:x}, rbp=0x{:x}:", r13, rbp);
        info!("  X: 0x{:x}", state.dest_x_addr);
        info!("  Y: 0x{:x}", state.dest_y_addr);
        info!("  Z: 0x{:x}", state.dest_z_addr);
        
        // If magnesis is active but base position isn't initialized, read current object position
        if state.is_active && (state.base_x == 0.0 && state.base_y == 0.0 && state.base_z == 0.0) {
            initialize_base_position_from_memory(&mut state);
        }
    }
}

// Initialize base position by placing object 1.5m in front of player
fn initialize_base_position_from_memory(state: &mut MagnesisControlState) {
    if state.dest_x_addr != 0 && state.dest_y_addr != 0 && state.dest_z_addr != 0 {
        if let Some((px, py, pz)) = read_link_position() {
            // Position object 1.5m in front of the player at torso level
            // Assuming player is facing forward in positive Z direction
            state.base_x = px;
            state.base_y = py + START_HEIGHT_OFFSET; // at player torso level
            state.base_z = pz + OBJECT_START_DISTANCE; // 1.5m in front
            
            state.current_x = state.base_x;
            state.current_y = state.base_y;
            state.current_z = state.base_z;
            
            // Set base parameters for consistent positioning
            state.base_angle = 0.0; // facing forward
            state.base_radius = OBJECT_START_DISTANCE;

            debug!("[MAGNESIS_EXP] Object positioned 1.5m in front of player: X={:.2}, Y={:.2}, Z={:.2}",
                   state.base_x, state.base_y, state.base_z);
        } else {
            // Fallback: read current object position if player pos unavailable
            let obj_x = read_f32_from_memory(state.dest_x_addr);
            let obj_y = read_f32_from_memory(state.dest_y_addr);
            let obj_z = read_f32_from_memory(state.dest_z_addr);
            
            state.base_x = obj_x;
            state.base_y = obj_y;
            state.base_z = obj_z;
            state.current_x = state.base_x;
            state.current_y = state.base_y;
            state.current_z = state.base_z;
            state.base_angle = 0.0;
            state.base_radius = OBJECT_START_DISTANCE;
            
            debug!("[MAGNESIS_EXP] Initialized base from object (no player pos): X={:.2}, Y={:.2}, Z={:.2}", state.base_x, state.base_y, state.base_z);
        }
    }
}



// Set up breakpoints on experimental MOVBE instructions to capture register values
pub fn patch_magnesis_instructions() -> Result<(), String> {
    let mut state = MAGNESIS_STATE.lock().unwrap();
    
    if state.is_patched {
        return Ok(());
    }
    
    if state.movbe_x_addr == 0 {
        return Err("Magnesis addresses not initialized".to_string());
    }
    
    // No need to save original bytes - we use hardcoded MOVBE instructions for restoration
    
    info!("[MAGNESIS_EXP] Setting up breakpoints on experimental MOVBE instructions at X=0x{:x}, Y=0x{:x}, Z=0x{:x}", 
          state.movbe_x_addr, state.movbe_y_addr, state.movbe_z_addr);
    
    unsafe {
        // Install single-step handler first (only needs to be done once)
        if SINGLE_STEP_HANDLER.is_null() {
            use winapi::um::errhandlingapi::AddVectoredExceptionHandler;
            SINGLE_STEP_HANDLER = AddVectoredExceptionHandler(1, Some(single_step_handler));
            if SINGLE_STEP_HANDLER.is_null() {
                return Err("Failed to install single-step exception handler".to_string());
            }
        }
        
        // Set up breakpoint on X coordinate MOVBE
        let mut x_handler_ptr = 0usize;
        if let Err(e) = setup_experimental_breakpoint(state.movbe_x_addr, exp_magnesis_x_handler, &mut state.original_x_breakpoint_byte, &mut x_handler_ptr) {
            return Err(format!("Failed to set up X coordinate breakpoint: {}", e));
        }
        state.x_exception_handler.store(x_handler_ptr, Ordering::SeqCst);
        
        // Set up breakpoint on Y coordinate MOVBE  
        let mut y_handler_ptr = 0usize;
        if let Err(e) = setup_experimental_breakpoint(state.movbe_y_addr, exp_magnesis_y_handler, &mut state.original_y_breakpoint_byte, &mut y_handler_ptr) {
            return Err(format!("Failed to set up Y coordinate breakpoint: {}", e));
        }
        state.y_exception_handler.store(y_handler_ptr, Ordering::SeqCst);
        
        // Set up breakpoint on Z coordinate MOVBE
        let mut z_handler_ptr = 0usize;
        if let Err(e) = setup_experimental_breakpoint(state.movbe_z_addr, exp_magnesis_z_handler, &mut state.original_z_breakpoint_byte, &mut z_handler_ptr) {
            return Err(format!("Failed to set up Z coordinate breakpoint: {}", e));
        }
        state.z_exception_handler.store(z_handler_ptr, Ordering::SeqCst);
        
        state.is_patched = true;
        info!("[MAGNESIS_EXP] Experimental MOVBE breakpoints set up successfully");
    }
    
    Ok(())
}

// Set up a breakpoint on an experimental MOVBE instruction
fn setup_experimental_breakpoint(
    addr: usize,
    handler: unsafe extern "system" fn(*mut winapi::um::winnt::EXCEPTION_POINTERS) -> i32,
    original_byte: &mut u8,
    exception_handler: &mut usize,
) -> Result<(), String> {
    unsafe {
        use winapi::um::memoryapi::{VirtualProtect, WriteProcessMemory};
        use winapi::um::processthreadsapi::GetCurrentProcess;
        use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
        use winapi::um::errhandlingapi::AddVectoredExceptionHandler;
        
        // Save original byte
        *original_byte = *(addr as *const u8);
        
        // Set up exception handler first
        let handler_ptr = AddVectoredExceptionHandler(1, Some(handler));
        if handler_ptr.is_null() {
            return Err("Failed to add vectored exception handler".to_string());
        }
        *exception_handler = handler_ptr as usize;
        
        // Make memory writable
        let mut old_protect = 0u32;
        if VirtualProtect(addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect) == 0 {
            return Err("Failed to change memory protection".to_string());
        }
        
        // Write breakpoint (INT3 = 0xCC)
        let breakpoint_byte = 0xCCu8;
        let mut bytes_written = 0usize;
        let success = WriteProcessMemory(
            GetCurrentProcess(),
            addr as *mut _,
            &breakpoint_byte as *const _ as *const _,
            1,
            &mut bytes_written,
        );
        
        // Restore memory protection
        VirtualProtect(addr as *mut _, 1, old_protect, &mut old_protect);
        
        if success == 0 || bytes_written != 1 {
            return Err("Failed to write breakpoint".to_string());
        }
        
        // Reduce log spam for breakpoint setup
        // info!("[MAGNESIS_EXP] Breakpoint set at 0x{:x}", addr);
        Ok(())
    }
}

// Global state for single-step reinstallation
static mut SINGLE_STEP_HANDLER: *mut winapi::ctypes::c_void = std::ptr::null_mut();
static mut PENDING_BREAKPOINT_REINSTALL: usize = 0;

// Single-step exception handler to re-install breakpoints
unsafe extern "system" fn single_step_handler(exception_info: *mut winapi::um::winnt::EXCEPTION_POINTERS) -> i32 {
    // Constants are defined at module level
    use winapi::um::memoryapi::{VirtualProtect, WriteProcessMemory};
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
    
    let exception_record = (*exception_info).ExceptionRecord;
    let context = (*exception_info).ContextRecord;
    
    if (*exception_record).ExceptionCode == EXCEPTION_SINGLE_STEP {
        // Check if we need to re-install a breakpoint
        if PENDING_BREAKPOINT_REINSTALL != 0 {
            let addr = PENDING_BREAKPOINT_REINSTALL;
            
            // Re-install breakpoint
            let mut old_protect = 0u32;
            VirtualProtect(addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect);
            
            let breakpoint_byte = 0xCCu8;
            let mut bytes_written = 0usize;
            WriteProcessMemory(
                GetCurrentProcess(),
                addr as *mut _,
                &breakpoint_byte as *const _ as *const _,
                1,
                &mut bytes_written,
            );
            
            VirtualProtect(addr as *mut _, 1, old_protect, &mut old_protect);
            
            // Clear pending reinstall
            PENDING_BREAKPOINT_REINSTALL = 0;
            
            // Clear trap flag
            (*context).EFlags &= !0x100;

            // After executing original instruction, override destination values if active
            let (dx, dy, dz, xv, yv, zv, active, calc) = {
                if let Ok(state) = MAGNESIS_STATE.lock() {
                    (state.dest_x_addr, state.dest_y_addr, state.dest_z_addr,
                     state.current_x, state.current_y, state.current_z,
                     state.is_active, state.addresses_calculated)
                } else {
                    (0usize,0usize,0usize,0.0,0.0,0.0,false,false)
                }
            };
            if active && calc && dx != 0 && dy != 0 && dz != 0 {
                // Write our custom coordinates to override game's write
                write_f32_to_memory(dx, xv);
                write_f32_to_memory(dy, yv);
                write_f32_to_memory(dz, zv);
            }
            
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    
    EXCEPTION_CONTINUE_SEARCH
}

// Helper to remove experimental breakpoints and restore original first bytes (no NOPs yet)
fn remove_exp_breakpoints_restore_bytes() {
    unsafe {
        use winapi::um::errhandlingapi::RemoveVectoredExceptionHandler;
        use winapi::um::memoryapi::{VirtualProtect, WriteProcessMemory};
        use winapi::um::processthreadsapi::GetCurrentProcess;
        use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
        if let Ok(mut state) = MAGNESIS_STATE.lock() {
            // X
            if state.movbe_x_addr != 0 {
                let mut old_protect = 0u32;
                VirtualProtect(state.movbe_x_addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect);
                let mut bytes_written = 0usize;
                WriteProcessMemory(
                    GetCurrentProcess(),
                    state.movbe_x_addr as *mut _,
                    &state.original_x_breakpoint_byte as *const _ as *const _,
                    1,
                    &mut bytes_written,
                );
                VirtualProtect(state.movbe_x_addr as *mut _, 1, old_protect, &mut old_protect);
            }
            // Y
            if state.movbe_y_addr != 0 {
                let mut old_protect = 0u32;
                VirtualProtect(state.movbe_y_addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect);
                let mut bytes_written = 0usize;
                WriteProcessMemory(
                    GetCurrentProcess(),
                    state.movbe_y_addr as *mut _,
                    &state.original_y_breakpoint_byte as *const _ as *const _,
                    1,
                    &mut bytes_written,
                );
                VirtualProtect(state.movbe_y_addr as *mut _, 1, old_protect, &mut old_protect);
            }
            // Z
            if state.movbe_z_addr != 0 {
                let mut old_protect = 0u32;
                VirtualProtect(state.movbe_z_addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect);
                let mut bytes_written = 0usize;
                WriteProcessMemory(
                    GetCurrentProcess(),
                    state.movbe_z_addr as *mut _,
                    &state.original_z_breakpoint_byte as *const _ as *const _,
                    1,
                    &mut bytes_written,
                );
                VirtualProtect(state.movbe_z_addr as *mut _, 1, old_protect, &mut old_protect);
            }
            // Remove handlers
            let xh = state.x_exception_handler.load(Ordering::SeqCst) as *mut winapi::ctypes::c_void;
            let yh = state.y_exception_handler.load(Ordering::SeqCst) as *mut winapi::ctypes::c_void;
            let zh = state.z_exception_handler.load(Ordering::SeqCst) as *mut winapi::ctypes::c_void;
            if !xh.is_null() { RemoveVectoredExceptionHandler(xh); }
            if !yh.is_null() { RemoveVectoredExceptionHandler(yh); }
            if !zh.is_null() { RemoveVectoredExceptionHandler(zh); }
            state.x_exception_handler.store(0, Ordering::SeqCst);
            state.y_exception_handler.store(0, Ordering::SeqCst);
            state.z_exception_handler.store(0, Ordering::SeqCst);
        }
        // Ensure we don't try to reinstall any pending breakpoint
        PENDING_BREAKPOINT_REINSTALL = 0;
    }
}

// Exception handler for X coordinate MOVBE
unsafe extern "system" fn exp_magnesis_x_handler(exception_info: *mut winapi::um::winnt::EXCEPTION_POINTERS) -> i32 {
    // Constants are defined at module level
    use winapi::um::memoryapi::{VirtualProtect, WriteProcessMemory};
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
    
    let exception_record = (*exception_info).ExceptionRecord;
    let context = (*exception_info).ContextRecord;
    
    if (*exception_record).ExceptionCode == EXCEPTION_BREAKPOINT {
        let addr = (*exception_record).ExceptionAddress as usize;
        
        // Check if this is our X coordinate MOVBE breakpoint
        if let Ok(mut state) = MAGNESIS_STATE.lock() {
            if addr == state.movbe_x_addr {
                // Compute X destination using this instruction's captured registers
                if !state.x_addr_ready {
                    let r13 = (*context).R13 as usize;
                    let rbp = (*context).Rbp as usize;
                    state.dest_x_addr = r13 + rbp + 0x68;
                    state.x_addr_ready = true;
            // Reduce log spam for destination address computation
            // info!("[MAGNESIS_EXP] Computed dest X address: 0x{:x} (r13=0x{:x}, rbp=0x{:x})", state.dest_x_addr, r13, rbp);
                }

                let all_ready = state.x_addr_ready && state.y_addr_ready && state.z_addr_ready;
                if all_ready && !state.nop_xyz_applied && state.is_active {
                    // All destination addresses known. Do NOT NOP yet; allow the game to run until we capture first valid start.
                    state.addresses_calculated = true;
                    state.awaiting_first_valid_start = true;
                    // Restore original instruction bytes for X/Y/Z and remove handlers, so execution continues normally.
                    drop(state);
                    remove_exp_breakpoints_restore_bytes();
                    // Ensure no trap or pending reinstall; execute this instruction normally now that byte is restored.
                    (*context).EFlags &= !0x100; // clear trap flag if any
                    return EXCEPTION_CONTINUE_EXECUTION;
                } else {
                    if all_ready && !state.is_active {
                        debug!("[MAGNESIS_EXP] All destination addresses known; waiting for ENABLE before takeover");
                    }
                    // Not all ready yet or not active: execute original instruction once via single-step
                    let mut old_protect = 0u32;
                    VirtualProtect(addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect);

                    let mut bytes_written = 0usize;
                    WriteProcessMemory(
                        GetCurrentProcess(),
                        addr as *mut _,
                        &state.original_x_breakpoint_byte as *const _ as *const _,
                        1,
                        &mut bytes_written,
                    );

                    VirtualProtect(addr as *mut _, 1, old_protect, &mut old_protect);

                    // Set up pending breakpoint reinstall and enable single-step
                    PENDING_BREAKPOINT_REINSTALL = addr;
                    (*context).EFlags |= 0x100; // Set trap flag

                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
        }
    }
    
    EXCEPTION_CONTINUE_SEARCH
}

// Exception handlers for Y and Z coordinates (similar but don't trigger magnesis detection)
unsafe extern "system" fn exp_magnesis_y_handler(exception_info: *mut winapi::um::winnt::EXCEPTION_POINTERS) -> i32 {
    // Constants are defined at module level
    use winapi::um::memoryapi::{VirtualProtect, WriteProcessMemory};
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
    
    let exception_record = (*exception_info).ExceptionRecord;
    let context = (*exception_info).ContextRecord;
    
    if (*exception_record).ExceptionCode == EXCEPTION_BREAKPOINT {
        let addr = (*exception_record).ExceptionAddress as usize;
        
        if let Ok(mut state) = MAGNESIS_STATE.lock() {
            if addr == state.movbe_y_addr {
                // Compute Y destination using this instruction's captured registers
                if !state.y_addr_ready {
                    let r13 = (*context).R13 as usize;
                    let rbp = (*context).Rbp as usize;
                    state.dest_y_addr = r13 + rbp + 0x6C;
                    state.y_addr_ready = true;
                    // Reduce log spam for destination address computation
                    // info!("[MAGNESIS_EXP] Computed dest Y address: 0x{:x} (r13=0x{:x}, rbp=0x{:x})", state.dest_y_addr, r13, rbp);
                }

                let all_ready = state.x_addr_ready && state.y_addr_ready && state.z_addr_ready;
                if all_ready && !state.nop_xyz_applied && state.is_active {
                    state.addresses_calculated = true;
                    state.awaiting_first_valid_start = true;
                    drop(state);
                    remove_exp_breakpoints_restore_bytes();
                    (*context).EFlags &= !0x100; // clear trap flag
                    return EXCEPTION_CONTINUE_EXECUTION;
                } else if all_ready && !state.is_active {
                    debug!("[MAGNESIS_EXP] All destination addresses known; waiting for ENABLE before takeover");
                }
                
                // Temporarily restore original instruction and set up single-step
                let mut old_protect = 0u32;
                VirtualProtect(addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect);
                
                let mut bytes_written = 0usize;
                WriteProcessMemory(
                    GetCurrentProcess(),
                    addr as *mut _,
                    &state.original_y_breakpoint_byte as *const _ as *const _,
                    1,
                    &mut bytes_written,
                );
                
                VirtualProtect(addr as *mut _, 1, old_protect, &mut old_protect);
                
                // Set up pending breakpoint reinstall and enable single-step
                PENDING_BREAKPOINT_REINSTALL = addr;
                (*context).EFlags |= 0x100; // Set trap flag
                
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }
    
    EXCEPTION_CONTINUE_SEARCH
}

unsafe extern "system" fn exp_magnesis_z_handler(exception_info: *mut winapi::um::winnt::EXCEPTION_POINTERS) -> i32 {
    // Constants are defined at module level
    use winapi::um::memoryapi::{VirtualProtect, WriteProcessMemory};
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
    
    let exception_record = (*exception_info).ExceptionRecord;
    let context = (*exception_info).ContextRecord;
    
    if (*exception_record).ExceptionCode == EXCEPTION_BREAKPOINT {
        let addr = (*exception_record).ExceptionAddress as usize;
        
        if let Ok(mut state) = MAGNESIS_STATE.lock() {
            if addr == state.movbe_z_addr {
                // Compute Z destination using this instruction's captured registers
                if !state.z_addr_ready {
                    let r13 = (*context).R13 as usize;
                    let rbp = (*context).Rbp as usize;
                    state.dest_z_addr = r13 + rbp + 0x70;
                    state.z_addr_ready = true;
                    // Reduce log spam for destination address computation
                    // info!("[MAGNESIS_EXP] Computed dest Z address: 0x{:x} (r13=0x{:x}, rbp=0x{:x})", state.dest_z_addr, r13, rbp);
                }

                let all_ready = state.x_addr_ready && state.y_addr_ready && state.z_addr_ready;
                if all_ready && !state.nop_xyz_applied && state.is_active {
                    state.addresses_calculated = true;
                    state.awaiting_first_valid_start = true;
                    drop(state);
                    remove_exp_breakpoints_restore_bytes();
                    (*context).EFlags &= !0x100; // clear trap flag
                    return EXCEPTION_CONTINUE_EXECUTION;
                } else if all_ready && !state.is_active {
                    debug!("[MAGNESIS_EXP] All destination addresses known; waiting for ENABLE before takeover");
                }
                
                // Temporarily restore original instruction and set up single-step
                let mut old_protect = 0u32;
                VirtualProtect(addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect);
                
                let mut bytes_written = 0usize;
                WriteProcessMemory(
                    GetCurrentProcess(),
                    addr as *mut _,
                    &state.original_z_breakpoint_byte as *const _ as *const _,
                    1,
                    &mut bytes_written,
                );
                
                VirtualProtect(addr as *mut _, 1, old_protect, &mut old_protect);
                
                // Set up pending breakpoint reinstall and enable single-step
                PENDING_BREAKPOINT_REINSTALL = addr;
                (*context).EFlags |= 0x100; // Set trap flag
                
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }
    
    EXCEPTION_CONTINUE_SEARCH
}


// Helper function to NOP out instructions
fn nop_instruction(addr: usize, size: usize) -> Result<(), String> {
    info!("[MAGNESIS_EXP] NOPing {} bytes at address 0x{:x}", size, addr);
    
    unsafe {
        use winapi::um::memoryapi::{VirtualProtect, WriteProcessMemory};
        use winapi::um::processthreadsapi::GetCurrentProcess;
        use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
        
        // Read and log what we're about to overwrite
        let mut original_bytes = vec![0u8; size];
        std::ptr::copy_nonoverlapping(addr as *const u8, original_bytes.as_mut_ptr(), size);
        let original_hex: Vec<String> = original_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        info!("[MAGNESIS_EXP] About to NOP over: [{}]", original_hex.join(" "));
        
        let mut old_protect = 0u32;
        
        // Make memory writable
        if VirtualProtect(
            addr as *mut _,
            size,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect
        ) == 0 {
            return Err("Failed to change memory protection".to_string());
        }
        
        // Write NOP bytes (0x90)
        let nop_bytes = vec![0x90u8; size];
        let mut bytes_written = 0usize;
        
        let success = WriteProcessMemory(
            GetCurrentProcess(),
            addr as *mut _,
            nop_bytes.as_ptr() as *const _,
            size,
            &mut bytes_written
        );
        
        // Restore original protection
        VirtualProtect(
            addr as *mut _,
            size,
            old_protect,
            &mut old_protect
        );
        
        if success == 0 || bytes_written != size {
            return Err("Failed to write NOP bytes".to_string());
        }
        
        info!("[MAGNESIS_EXP] Successfully NOPed {} bytes at 0x{:x}", bytes_written, addr);
        Ok(())
    }
}

// Write custom coordinates directly to the calculated destination addresses
// This replaces the NOPed MOVBE instructions with manual coordinate control
pub fn write_custom_coordinates_to_magnesis_object() {
    if let Ok(state) = MAGNESIS_STATE.lock() {
        if !state.is_active || !state.is_patched {
            return;
        }
        
        if !state.addresses_calculated || state.dest_x_addr == 0 || state.dest_y_addr == 0 || state.dest_z_addr == 0 {
            return; // quietly skip until ready
        }
        
        // If awaiting the first valid start, do not write yet
        if state.awaiting_first_valid_start {
            return;
        }

        // Write coordinates directly to the destination addresses
        write_f32_to_memory(state.dest_x_addr, state.current_x);
        write_f32_to_memory(state.dest_y_addr, state.current_y);
        write_f32_to_memory(state.dest_z_addr, state.current_z);
        
        debug!("[MAGNESIS_EXP] Wrote coordinates: X={:.2}@0x{:x}, Y={:.2}@0x{:x}, Z={:.2}@0x{:x}", 
               state.current_x, state.dest_x_addr, state.current_y, state.dest_y_addr, state.current_z, state.dest_z_addr);
    }
}

// Deactivate experimental magnesis control and clean up breakpoints
pub fn unpatch_magnesis_instructions() -> Result<(), String> {
    let mut state = MAGNESIS_STATE.lock().unwrap();
    
    if !state.is_patched {
        // Also clear disable flag on original system
        crate::disable_original_magnesis_detection(false);
        return Ok(());
    }
    
    info!("[MAGNESIS_EXP] Deactivating experimental magnesis control");
    
    unsafe {
        // Remove exception handlers first (without writing any bytes)
        use winapi::um::errhandlingapi::RemoveVectoredExceptionHandler;
        
        let xh = state.x_exception_handler.load(Ordering::SeqCst);
        let yh = state.y_exception_handler.load(Ordering::SeqCst);
        let zh = state.z_exception_handler.load(Ordering::SeqCst);
        
        if xh != 0 {
            RemoveVectoredExceptionHandler(xh as *mut winapi::ctypes::c_void);
            state.x_exception_handler.store(0, Ordering::SeqCst);
        }
        if yh != 0 {
            RemoveVectoredExceptionHandler(yh as *mut winapi::ctypes::c_void);
            state.y_exception_handler.store(0, Ordering::SeqCst);
        }
        if zh != 0 {
            RemoveVectoredExceptionHandler(zh as *mut winapi::ctypes::c_void);
            state.z_exception_handler.store(0, Ordering::SeqCst);
        }
        
        // Remove single-step handler
        if !SINGLE_STEP_HANDLER.is_null() {
            RemoveVectoredExceptionHandler(SINGLE_STEP_HANDLER);
            SINGLE_STEP_HANDLER = std::ptr::null_mut();
        }
        
        // Clear any pending single-step reinstall request
        PENDING_BREAKPOINT_REINSTALL = 0;
    }
    
    // Restore MOVBE instructions using hardcoded bytes
    info!("[MAGNESIS_EXP] State check: nop_xyz_applied={}", state.nop_xyz_applied);
    
    if state.nop_xyz_applied {
        // If NOPs were applied, restore full MOVBE instructions using hardcoded bytes
        info!("[MAGNESIS_EXP] Restoring NOPed MOVBE instructions to original state using hardcoded bytes");
        
        // Verify addresses are valid before restoration
        info!("[MAGNESIS_EXP] About to restore to addresses - X: 0x{:x}, Y: 0x{:x}, Z: 0x{:x}", state.movbe_x_addr, state.movbe_y_addr, state.movbe_z_addr);
        
        // Check what's currently at those addresses before restoration
        let mut current_x: [u8; MOVBE_SIZE] = [0; MOVBE_SIZE];
        let mut current_y: [u8; MOVBE_SIZE] = [0; MOVBE_SIZE];
        let mut current_z: [u8; MOVBE_SIZE] = [0; MOVBE_SIZE];
        unsafe {
            std::ptr::copy_nonoverlapping(state.movbe_x_addr as *const u8, current_x.as_mut_ptr(), MOVBE_SIZE);
            std::ptr::copy_nonoverlapping(state.movbe_y_addr as *const u8, current_y.as_mut_ptr(), MOVBE_SIZE);
            std::ptr::copy_nonoverlapping(state.movbe_z_addr as *const u8, current_z.as_mut_ptr(), MOVBE_SIZE);
        }
        
        let x_nops = current_x.iter().all(|&b| b == 0x90);
        let y_nops = current_y.iter().all(|&b| b == 0x90);
        let z_nops = current_z.iter().all(|&b| b == 0x90);
        
        info!("[MAGNESIS_EXP] Pre-restoration check: X has NOPs: {}, Y has NOPs: {}, Z has NOPs: {}", x_nops, y_nops, z_nops);
        
        if !x_nops || !y_nops || !z_nops {
            warn!("[MAGNESIS_EXP] WARNING: Not all addresses contain NOPs as expected!");
            let x_hex: Vec<String> = current_x.iter().map(|b| format!("{:02x}", b)).collect();
            let y_hex: Vec<String> = current_y.iter().map(|b| format!("{:02x}", b)).collect();
            let z_hex: Vec<String> = current_z.iter().map(|b| format!("{:02x}", b)).collect();
            warn!("[MAGNESIS_EXP] Current X bytes: [{}]", x_hex.join(" "));
            warn!("[MAGNESIS_EXP] Current Y bytes: [{}]", y_hex.join(" "));
            warn!("[MAGNESIS_EXP] Current Z bytes: [{}]", z_hex.join(" "));
        }
        
        let _ = restore_hardcoded_movbe(state.movbe_x_addr, &MOVBE_X_BYTES, "X");
        let _ = restore_hardcoded_movbe(state.movbe_y_addr, &MOVBE_Y_BYTES, "Y");
        let _ = restore_hardcoded_movbe(state.movbe_z_addr, &MOVBE_Z_BYTES, "Z");
        info!("[MAGNESIS_EXP] Original MOVBE instructions restored - magnesis object should be movable again");
    } else {
        // If only breakpoints were set, restore individual bytes
        info!("[MAGNESIS_EXP] NOPs were not applied, restoring individual breakpoint bytes instead");
        if state.movbe_x_addr != 0 && state.original_x_breakpoint_byte != 0 {
            let _ = restore_single_byte(state.movbe_x_addr, state.original_x_breakpoint_byte);
        }
        if state.movbe_y_addr != 0 && state.original_y_breakpoint_byte != 0 {
            let _ = restore_single_byte(state.movbe_y_addr, state.original_y_breakpoint_byte);
        }
        if state.movbe_z_addr != 0 && state.original_z_breakpoint_byte != 0 {
            let _ = restore_single_byte(state.movbe_z_addr, state.original_z_breakpoint_byte);
        }
    }

    // Reset runtime state
    state.is_patched = false;
    state.addresses_calculated = false;
    state.dest_x_addr = 0;
    state.dest_y_addr = 0;
    state.dest_z_addr = 0;
    state.x_addr_ready = false;
    state.y_addr_ready = false;
    state.z_addr_ready = false;
    state.nop_xyz_applied = false;
    
    // Re-enable original detection system
    crate::disable_original_magnesis_detection(false);

    info!("[MAGNESIS_EXP] Experimental magnesis control deactivated");
    
    Ok(())
}

// Helper to restore a MOVBE instruction using hardcoded bytes
fn restore_hardcoded_movbe(addr: usize, movbe_bytes: &[u8; MOVBE_SIZE], coordinate_name: &str) -> Result<(), String> {
    unsafe {
        use winapi::um::memoryapi::{VirtualProtect, WriteProcessMemory};
        use winapi::um::processthreadsapi::GetCurrentProcess;
        use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
        
        if addr == 0 {
            warn!("[MAGNESIS_EXP] Restoration skipped - invalid address for {} coordinate", coordinate_name);
            return Ok(());
        }
        
        // Log what we're about to restore
        let movbe_hex: Vec<String> = movbe_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        info!("[MAGNESIS_EXP] Restoring {} MOVBE at 0x{:x}: [{}]", coordinate_name, addr, movbe_hex.join(" "));
        
        let mut old_protect = 0u32;
        if VirtualProtect(addr as *mut _, MOVBE_SIZE, PAGE_EXECUTE_READWRITE, &mut old_protect) == 0 {
            return Err(format!("Failed to change memory protection for {} MOVBE restore at 0x{:x}", coordinate_name, addr));
        }
        
        let mut bytes_written = 0usize;
        let success = WriteProcessMemory(
            GetCurrentProcess(),
            addr as *mut _,
            movbe_bytes.as_ptr() as *const _,
            MOVBE_SIZE,
            &mut bytes_written,
        );
        
        VirtualProtect(addr as *mut _, MOVBE_SIZE, old_protect, &mut old_protect);
        
        if success == 0 || bytes_written != MOVBE_SIZE {
            return Err(format!("Failed to restore {} MOVBE at 0x{:x} - wrote {}/{} bytes", coordinate_name, addr, bytes_written, MOVBE_SIZE));
        }
        
        // Flush instruction cache to ensure CPU sees the restored instructions immediately
        use winapi::um::processthreadsapi::FlushInstructionCache;
        FlushInstructionCache(GetCurrentProcess(), addr as *const _, MOVBE_SIZE);
        
        // Additional memory barrier and more aggressive cache flush
        
        // Flush entire instruction cache
        FlushInstructionCache(GetCurrentProcess(), std::ptr::null(), 0);
        
        // Add memory barrier
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        
        // Small delay to give game time to recognize changes - reduced for faster response
        std::thread::sleep(std::time::Duration::from_millis(2));
        
        // Verify the restoration by reading back the bytes
        let mut verify_bytes: [u8; MOVBE_SIZE] = [0; MOVBE_SIZE];
        std::ptr::copy_nonoverlapping(addr as *const u8, verify_bytes.as_mut_ptr(), MOVBE_SIZE);
        
        let matches = verify_bytes == *movbe_bytes;
        if matches {
            info!("[MAGNESIS_EXP] ✓ {} MOVBE restoration verified - bytes match expected values", coordinate_name);
        } else {
            let actual_hex: Vec<String> = verify_bytes.iter().map(|b| format!("{:02x}", b)).collect();
            warn!("[MAGNESIS_EXP] ✗ {} MOVBE restoration verification FAILED!", coordinate_name);
            warn!("[MAGNESIS_EXP]   Expected: [{}]", movbe_hex.join(" "));
            warn!("[MAGNESIS_EXP]   Actually read back: [{}]", actual_hex.join(" "));
        }
        
        info!("[MAGNESIS_EXP] Successfully restored {} MOVBE ({} bytes) at 0x{:x} with cache flush", coordinate_name, bytes_written, addr);
        
        // Debug: Read some additional context bytes around the restored instruction
        let mut context_bytes: [u8; 32] = [0; 32];
        std::ptr::copy_nonoverlapping((addr.saturating_sub(8)) as *const u8, context_bytes.as_mut_ptr(), 32);
        let context_hex: Vec<String> = context_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        info!("[MAGNESIS_EXP] Context around {}: [{}]", coordinate_name, context_hex.join(" "));
        
        Ok(())
    }
}

// Helper to restore a single byte (for breakpoint cleanup)
fn restore_single_byte(addr: usize, original_byte: u8) -> Result<(), String> {
    unsafe {
        use winapi::um::memoryapi::{VirtualProtect, WriteProcessMemory};
        use winapi::um::processthreadsapi::GetCurrentProcess;
        use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
        
        let mut old_protect = 0u32;
        if VirtualProtect(addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect) == 0 {
            return Err("Failed to change memory protection for single byte restore".to_string());
        }
        
        let mut bytes_written = 0usize;
        let success = WriteProcessMemory(
            GetCurrentProcess(),
            addr as *mut _,
            &original_byte as *const _ as *const _,
            1,
            &mut bytes_written,
        );
        
        VirtualProtect(addr as *mut _, 1, old_protect, &mut old_protect);
        
        if success == 0 || bytes_written != 1 {
            return Err("Failed to restore single byte".to_string());
        }
        
        Ok(())
    }
}

// Clean up a breakpoint and restore original instruction (first byte)
fn cleanup_experimental_breakpoint(
    addr: usize,
    original_byte: u8,
    exception_handler: usize,
) -> Result<(), String> {
    unsafe {
        use winapi::um::memoryapi::{VirtualProtect, WriteProcessMemory};
        use winapi::um::processthreadsapi::GetCurrentProcess;
        use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
        use winapi::um::errhandlingapi::RemoveVectoredExceptionHandler;
        
        // Remove exception handler
        if exception_handler != 0 {
            RemoveVectoredExceptionHandler(exception_handler as *mut winapi::ctypes::c_void);
        }
        
        // Restore original instruction byte
        let mut old_protect = 0u32;
        if VirtualProtect(addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect) == 0 {
            return Err("Failed to change memory protection for cleanup".to_string());
        }
        
        let mut bytes_written = 0usize;
        let success = WriteProcessMemory(
            GetCurrentProcess(),
            addr as *mut _,
            &original_byte as *const _ as *const _,
            1,
            &mut bytes_written,
        );
        
        VirtualProtect(addr as *mut _, 1, old_protect, &mut old_protect);
        
        if success == 0 || bytes_written != 1 {
            return Err("Failed to restore original instruction byte".to_string());
        }
        
        // Reduce log spam for cleanup operations
        // info!("[MAGNESIS_EXP] Cleaned up breakpoint at 0x{:x}", addr);
        Ok(())
    }
}

// Restore original bytes from breakpoints before NOPing to prevent cc corruption
fn restore_breakpoints_before_nop() -> Result<(), String> {
    if let Ok(state) = MAGNESIS_STATE.lock() {
        // Restore original bytes for X, Y, Z breakpoints if they exist
        if state.movbe_x_addr != 0 && state.original_x_breakpoint_byte != 0 {
            let _ = restore_single_byte(state.movbe_x_addr, state.original_x_breakpoint_byte);
        }
        if state.movbe_y_addr != 0 && state.original_y_breakpoint_byte != 0 {
            let _ = restore_single_byte(state.movbe_y_addr, state.original_y_breakpoint_byte);
        }
        if state.movbe_z_addr != 0 && state.original_z_breakpoint_byte != 0 {
            let _ = restore_single_byte(state.movbe_z_addr, state.original_z_breakpoint_byte);
        }
    }
    Ok(())
}

fn apply_nop_xyz_addrs(x_addr: usize, y_addr: usize, z_addr: usize) -> Result<(), String> {
    if x_addr == 0 || y_addr == 0 || z_addr == 0 { return Err("Invalid MOVBE addresses for NOP".to_string()); }
    
    // Apply NOPs to all three MOVBE instructions
    nop_instruction(x_addr, MOVBE_SIZE)?;
    nop_instruction(y_addr, MOVBE_SIZE)?;
    nop_instruction(z_addr, MOVBE_SIZE)?;
    Ok(())
}

fn finalize_experimental_after_addresses(x_addr: usize, y_addr: usize, z_addr: usize) -> Result<(), String> {
    // CRITICAL: First restore original bytes from breakpoints, then NOP them
    // This prevents NOPing over breakpoint bytes (cc) instead of original MOVBE bytes
    restore_breakpoints_before_nop()?;
    
    // Now NOP all three experimental MOVBE instructions with clean original bytes
    apply_nop_xyz_addrs(x_addr, y_addr, z_addr)?;

    // Remove experimental breakpoints and single-step handler
    if let Ok(mut state) = MAGNESIS_STATE.lock() {
        unsafe {
            use winapi::um::errhandlingapi::RemoveVectoredExceptionHandler;
            let xh = state.x_exception_handler.load(Ordering::SeqCst) as *mut winapi::ctypes::c_void;
            let yh = state.y_exception_handler.load(Ordering::SeqCst) as *mut winapi::ctypes::c_void;
            let zh = state.z_exception_handler.load(Ordering::SeqCst) as *mut winapi::ctypes::c_void;
            if !xh.is_null() { RemoveVectoredExceptionHandler(xh); }
            if !yh.is_null() { RemoveVectoredExceptionHandler(yh); }
            if !zh.is_null() { RemoveVectoredExceptionHandler(zh); }
            state.x_exception_handler.store(0, Ordering::SeqCst);
            state.y_exception_handler.store(0, Ordering::SeqCst);
            state.z_exception_handler.store(0, Ordering::SeqCst);

            // Clear any pending single-step reinstall request
            PENDING_BREAKPOINT_REINSTALL = 0;

            if !SINGLE_STEP_HANDLER.is_null() {
                RemoveVectoredExceptionHandler(SINGLE_STEP_HANDLER);
                SINGLE_STEP_HANDLER = std::ptr::null_mut();
            }
        }
        state.nop_xyz_applied = true;
        // Re-enable original magnesis detection to handle detection events
        crate::disable_original_magnesis_detection(false);
        // Keep is_patched=true to indicate we've modified instructions
        if !state.is_patched { state.is_patched = true; }
        info!("[MAGNESIS_EXP] NOP applied to X/Y/Z experimental MOVBE and handlers removed; original detection re-enabled");
    }

    Ok(())
}


// Read Link (player) position using global address, if available
fn read_link_position() -> Option<(f32, f32, f32)> {
    unsafe {
        use crate::g_link_position_addr;
        let addr = g_link_position_addr;
        if addr == 0 { return None; }
        let x = read_f32_from_memory(addr);
        let y = read_f32_from_memory(addr + 4);
        let z = read_f32_from_memory(addr + 8);
        Some((x, y, z))
    }
}

// Update magnesis object position based on mouse input (orbital mapping)
pub fn update_magnesis_position(delta_x: f32, delta_y: f32, wheel_delta: f32, sensitivity: f32) {
    let mut state = MAGNESIS_STATE.lock().unwrap();
    
    if !state.is_active || !state.is_patched {
        return;
    }

    // If we are awaiting the first valid start, watch memory until it changes from the initial bad sample.
    if state.addresses_calculated && state.dest_x_addr != 0 && state.dest_y_addr != 0 && state.dest_z_addr != 0 && state.awaiting_first_valid_start {
        let curr_x = read_f32_from_memory(state.dest_x_addr);
        let curr_y = read_f32_from_memory(state.dest_y_addr);
        let curr_z = read_f32_from_memory(state.dest_z_addr);
        match state.initial_sample {
            None => {
                // Store the initial (likely wrong) sample and wait for a change
                state.initial_sample = Some((curr_x, curr_y, curr_z));
                debug!("[MAGNESIS_EXP] Initial sample captured (awaiting change): X={:.2}, Y={:.2}, Z={:.2}", curr_x, curr_y, curr_z);
                return; // Do nothing this frame
            }
            Some((ix, iy, iz)) => {
                let changed = (curr_x - ix).abs() > 0.0005 || (curr_y - iy).abs() > 0.0005 || (curr_z - iz).abs() > 0.0005;
                if changed {
                    // Keep object where it is, only adjust distance if too far/close
                    if let Some((px, py, pz)) = read_link_position() {
                        info!("[MAGNESIS_EXP] Player position: X={:.2}, Y={:.2}, Z={:.2}", px, py, pz);
                        info!("[MAGNESIS_EXP] Object position before adjustment: X={:.2}, Y={:.2}, Z={:.2}", curr_x, curr_y, curr_z);
                        // Calculate current direction from player to object
                        let dx = curr_x - px;
                        let dz = curr_z - pz;
                        let current_distance = (dx * dx + dz * dz).sqrt();
                        info!("[MAGNESIS_EXP] Current horizontal distance: {:.2}m", current_distance);
                        
                        // Always position object at exactly 2.25m from player along the line (50% further)
                        let desired_distance = 2.25;
                        if current_distance > 0.1 {
                            // Normalize direction and scale to exactly 2.25m distance
                            let scale = desired_distance / current_distance;
                            state.base_x = px + dx * scale;
                            state.base_z = pz + dz * scale;
                            info!("[MAGNESIS_EXP] Scaled to 2.25m: scale={:.2}, new X={:.2}, new Z={:.2}", scale, state.base_x, state.base_z);
                        } else {
                            // Object too close to player, place 2.25m in front
                            state.base_x = px;
                            state.base_z = pz + desired_distance;
                            info!("[MAGNESIS_EXP] Too close - placed 2.25m in front: X={:.2}, Z={:.2}", state.base_x, state.base_z);
                        }
                        // Force object to torso level (player Y + offset)
                        state.base_y = py + START_HEIGHT_OFFSET;
                        info!("[MAGNESIS_EXP] Set torso height: player_y={:.2} + offset={:.2} = {:.2}", py, START_HEIGHT_OFFSET, state.base_y);
                        state.base_radius = desired_distance;
                        
                        // Calculate angle for orbital movement
                        let final_dx = state.base_x - px;
                        let final_dz = state.base_z - pz;
                        state.base_angle = final_dz.atan2(final_dx); // angle from player to object
                        
                        state.current_x = state.base_x;
                        state.current_y = state.base_y;
                        state.current_z = state.base_z;
                        state.awaiting_first_valid_start = false;
                        state.initial_sample = None;
                        // NOW set camera reset flag since startup capture is complete
                        state.camera_position_needs_reset = true;
                        // Reset accumulators so movement starts fresh
                        state.mouse_delta_x = 0.0;
                        state.mouse_delta_y = 0.0;
                        state.mouse_wheel_delta = 0.0;
                        // Now that we have a valid start, take over by NOPing the MOVBEs
                        let (x_addr, y_addr, z_addr) = (state.movbe_x_addr, state.movbe_y_addr, state.movbe_z_addr);
                        let (log_x, log_y, log_z) = (state.base_x, state.base_y, state.base_z);
                        drop(state); // release lock before patching
                        if let Err(e) = finalize_experimental_after_addresses(x_addr, y_addr, z_addr) {
                            warn!("[MAGNESIS_EXP] Failed to finalize after start capture: {}", e);
                        } else {
                            info!("[MAGNESIS_EXP] Start captured and control taken: X={:.2}, Y={:.2}, Z={:.2}", log_x, log_y, log_z);
                        }
                        // After finalize, write once with the captured start
                        write_custom_coordinates_to_magnesis_object();
                        return;
                    } else {
                        // No link pos; keep object exactly where it is
                        state.base_x = curr_x;
                        state.base_y = curr_y;
                        state.base_z = curr_z;
                        state.base_radius = 2.25; // Default radius for orbital movement (50% further)
                        state.base_angle = 0.0;
                        state.current_x = state.base_x;
                        state.current_y = state.base_y;
                        state.current_z = state.base_z;
                        state.awaiting_first_valid_start = false;
                        state.initial_sample = None;
                        // NOW set camera reset flag since startup capture is complete
                        state.camera_position_needs_reset = true;
                        // Reset accumulators
                        state.mouse_delta_x = 0.0;
                        state.mouse_delta_y = 0.0;
                        state.mouse_wheel_delta = 0.0;
                        let (x_addr, y_addr, z_addr) = (state.movbe_x_addr, state.movbe_y_addr, state.movbe_z_addr);
                        let (log_x, log_y, log_z) = (state.base_x, state.base_y, state.base_z);
                        drop(state);
                        if let Err(e) = finalize_experimental_after_addresses(x_addr, y_addr, z_addr) {
                            warn!("[MAGNESIS_EXP] Failed to finalize after start capture (no link pos): {}", e);
                        } else {
                            info!("[MAGNESIS_EXP] Start captured (no link pos) and control taken: X={:.2}, Y={:.2}, Z={:.2}", log_x, log_y, log_z);
                        }
                        write_custom_coordinates_to_magnesis_object();
                        return;
                    }
                } else {
                    // Still waiting for first change
                    return;
                }
            }
        }
    }
    
    // Accumulate mouse deltas across frames (cursor is re-centered each frame)
    // delta_x/delta_y are already scaled by camera_sensitivity in utils.rs
    // Invert Y-axis for more natural mouse movement (up moves up, down moves down)
    state.mouse_delta_x += delta_x;
    state.mouse_delta_y -= delta_y * 2.0; // Invert Y-axis + 2.0x vertical sensitivity (increased by 0.5x)

    // Convert accumulated movement to orbital mapping around player
    // - Mouse X: horizontal orbit (angle around Y axis)
    // - Mouse Y: vertical up/down
    // - Wheel: push/pull (radius change)
    let movement_scale = sensitivity.max(0.01);

    if let Some((px, py, pz)) = read_link_position() {
        // Target angle from accumulated mouse movement
        let target_angle = state.base_angle + state.mouse_delta_x * movement_scale;

        // Saturate wheel accumulator at the minimum radius so pulling at the limit doesn't keep accumulating negative value
        // Increase wheel effectiveness by 3x for better push/pull control
        let new_wheel_acc = state.mouse_wheel_delta + wheel_delta * 3.0;
        let mut delta_r = new_wheel_acc * movement_scale;
        let min_delta_r = MIN_ORBIT_RADIUS - state.base_radius; // usually <= 0
        if delta_r < min_delta_r {
            delta_r = min_delta_r;
            state.mouse_wheel_delta = delta_r / movement_scale; // clamp accumulator so it doesn't go past the limit
        } else {
            state.mouse_wheel_delta = new_wheel_acc;
        }

        let radius = (state.base_radius + delta_r).max(MIN_ORBIT_RADIUS);
        let y = state.base_y + state.mouse_delta_y * movement_scale;

        // Compute current angle from current position relative to player
        let mut current_angle = (state.current_z - pz).atan2(state.current_x - px);
        // Shortest angular difference to target in [-PI, PI]
        let mut diff = target_angle - current_angle;
        while diff > std::f32::consts::PI { diff -= 2.0 * std::f32::consts::PI; }
        while diff < -std::f32::consts::PI { diff += 2.0 * std::f32::consts::PI; }
        // Step toward target, limited per tick to preserve orbital path
        let applied_step = diff.clamp(-MAX_ANGLE_STEP, MAX_ANGLE_STEP);
        let angle = current_angle + applied_step;

        // Apply 24m distance limits from player (20% increase from 20m)
        let proposed_x = px + radius * angle.cos();
        let proposed_z = pz + radius * angle.sin();
        
        // Check horizontal distance (X-Z plane) and clamp to 24m max
        let dx = proposed_x - px;
        let dz = proposed_z - pz;
        let horizontal_distance = (dx * dx + dz * dz).sqrt();
        
        if horizontal_distance > 24.0 {
            let scale = 24.0 / horizontal_distance;
            state.current_x = px + dx * scale;
            state.current_z = pz + dz * scale;
        } else {
            state.current_x = proposed_x;
            state.current_z = proposed_z;
        }
        
        // Check vertical distance and clamp to 24m max
        let vertical_distance = (y - py).abs();
        if vertical_distance > 24.0 {
            // Clamp the Y position and adjust the accumulated delta to prevent over-accumulation
            let max_delta_y = if y > py {
                state.current_y = py + 24.0;
                (24.0 - state.base_y + py) / movement_scale  // Calculate max allowed delta
            } else {
                state.current_y = py - 24.0;
                (-24.0 - state.base_y + py) / movement_scale  // Calculate max allowed delta (negative)
            };
            // Clamp the accumulator so it doesn't store movement beyond the limit
            state.mouse_delta_y = max_delta_y;
        } else {
            state.current_y = y;
        }
    } else {
        // Fallback: relative mapping if player position unavailable
        // For fallback mode, we'll limit to 24m from the base position as an approximation (20% increase from 20m)
        let proposed_x = state.base_x + state.mouse_delta_x * movement_scale;
        let proposed_y = state.base_y + state.mouse_delta_y * movement_scale;
        let proposed_z = state.base_z + state.mouse_wheel_delta * movement_scale;
        
        // Apply distance limits from base position (as approximation of player position)
        let dx = proposed_x - state.base_x;
        let dy = proposed_y - state.base_y;
        let dz = proposed_z - state.base_z;
        
        let horizontal_distance = (dx * dx + dz * dz).sqrt();
        if horizontal_distance > 24.0 {
            let scale = 24.0 / horizontal_distance;
            state.current_x = state.base_x + dx * scale;
            state.current_z = state.base_z + dz * scale;
        } else {
            state.current_x = proposed_x;
            state.current_z = proposed_z;
        }
        
        let vertical_distance = dy.abs();
        if vertical_distance > 24.0 {
            // Clamp the Y position and adjust the accumulated delta to prevent over-accumulation
            let max_delta_y = if dy > 0.0 {
                state.current_y = state.base_y + 24.0;
                24.0 / movement_scale  // Calculate max allowed delta
            } else {
                state.current_y = state.base_y - 24.0;
                -24.0 / movement_scale  // Calculate max allowed delta (negative)
            };
            // Clamp the accumulator so it doesn't store movement beyond the limit
            state.mouse_delta_y = max_delta_y;
        } else {
            state.current_y = proposed_y;
        }
    }

    // Throttled debug log for visibility (every ~300ms)
    {
        use std::time::{Duration, Instant};
        static mut LAST_WRITE_LOG: Option<Instant> = None;
        let now = Instant::now();
        let should_log = unsafe { LAST_WRITE_LOG.map_or(true, |t| now.duration_since(t) > Duration::from_millis(300)) };
        if should_log {
            debug!("[MAGNESIS_EXP] Move -> X={:.2}, Y={:.2}, Z={:.2} (scale={:.2})",
                   state.current_x, state.current_y, state.current_z, movement_scale);
            unsafe { LAST_WRITE_LOG = Some(now); }
        }
    }
    
    // Release the lock before calling coordinate writing function
    drop(state);
    
    // Write coordinates directly to magnesis object memory
    // This replaces the NOPed MOVBE instructions
    write_custom_coordinates_to_magnesis_object();
}


// Read a float value from memory address as 4-byte big-endian
fn read_f32_from_memory(addr: usize) -> f32 {
    unsafe {
        use winapi::um::memoryapi::{VirtualProtect, ReadProcessMemory};
        use winapi::um::processthreadsapi::GetCurrentProcess;
        use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
        
        let mut old_protect = 0u32;
        let mut buf = [0u8; 4];
        
        // Make memory readable (usually already is)
        if VirtualProtect(
            addr as *mut _,
            4,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect
        ) != 0 {
            let mut bytes_read = 0usize;
            let result = ReadProcessMemory(
                GetCurrentProcess(),
                addr as *const _,
                buf.as_mut_ptr() as *mut _,
                4,
                &mut bytes_read
            );
            
            // Restore protection
            VirtualProtect(
                addr as *mut _,
                4,
                old_protect,
                &mut old_protect
            );
            
            if result != 0 && bytes_read == 4 {
                let bits = u32::from_be_bytes(buf);
                return f32::from_bits(bits);
            }
        }
        
        // Return 0.0 on failure
        0.0
    }
}

// Write a float value to memory address as 4-byte big-endian (to match MOVBE semantics)
fn write_f32_to_memory(addr: usize, value: f32) {
    unsafe {
        use winapi::um::memoryapi::{VirtualProtect, WriteProcessMemory};
        use winapi::um::processthreadsapi::GetCurrentProcess;
        use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
        
        let bytes = value.to_be_bytes();
        let mut old_protect = 0u32;
        
        // Make memory writable
        if VirtualProtect(
            addr as *mut _,
            4,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect
        ) != 0 {
            let mut bytes_written = 0usize;
            WriteProcessMemory(
                GetCurrentProcess(),
                addr as *mut _,
                bytes.as_ptr() as *const _,
                4,
                &mut bytes_written
            );
            
            // Restore protection
            VirtualProtect(
                addr as *mut _,
                4,
                old_protect,
                &mut old_protect
            );
        }
    }
}





// Safe memory readability check
fn is_memory_readable_safe(addr: usize) -> bool {
    unsafe {
        use winapi::um::memoryapi::VirtualQuery;
        use winapi::um::winnt::{MEMORY_BASIC_INFORMATION, MEM_COMMIT};
        
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        let result = VirtualQuery(
            addr as *const _,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>()
        );
        
        result != 0 && (mbi.State & MEM_COMMIT) != 0
    }
}

// Activate experimental magnesis control
pub fn activate_magnesis_control() {
    // Set active first
    {
        let mut state = MAGNESIS_STATE.lock().unwrap();
        state.is_active = true;
        info!("[MAGNESIS_EXP] ENABLED (user) - experimental magnesis active");
        
        // CRITICAL: Reset state flags to allow re-detection and re-initialization
        // This fixes the issue where magnesis can't be re-enabled after being disabled
        state.awaiting_first_valid_start = true; // Wait for object to move first
        state.initial_sample = None;
        state.addresses_calculated = false;  // Force re-calculation of destination addresses
        state.x_addr_ready = false;
        state.y_addr_ready = false;
        state.z_addr_ready = false;
        state.nop_xyz_applied = false;      // Allow NOPs to be re-applied
        state.camera_position_needs_reset = false; // Don't reset camera until startup capture completes
        
        // Reset accumulators on activation
        state.mouse_delta_x = 0.0;
        state.mouse_delta_y = 0.0;
        state.mouse_wheel_delta = 0.0;
        
        // Reset base position - will be set properly during startup capture phase
        state.base_x = 0.0;
        state.base_y = 0.0;
        state.base_z = 0.0;
        state.base_radius = 0.0;
        state.base_angle = 0.0;
        state.current_x = 0.0;
        state.current_y = 0.0;
        state.current_z = 0.0;
        debug!("[MAGNESIS_EXP] Magnesis activated - awaiting object movement to capture initial position");
    }

    // Always start monitoring thread with fresh timers (it will fast-path if addresses already exist)
    start_experimental_magnesis_monitoring();

    // If addresses already exist and we aren't patched yet, install breakpoints immediately
    let (have_addrs, already_patched, nop_applied) = {
        let st = MAGNESIS_STATE.lock().unwrap();
        (st.movbe_x_addr != 0 && st.movbe_y_addr != 0 && st.movbe_z_addr != 0, st.is_patched, st.nop_xyz_applied)
    };
    
    if have_addrs && !already_patched {
        if let Err(e) = patch_magnesis_instructions() {
            warn!("[MAGNESIS_EXP] Immediate breakpoint install failed: {}", e);
        } else {
            info!("[MAGNESIS_EXP] Experimental MOVBE breakpoints installed immediately on activation");
        }
    }

    // CRITICAL: Only apply NOPs immediately if destination addresses are already calculated
    // This prevents bypassing breakpoint-based address calculation on re-activation
    let addresses_calculated = {
        let st = MAGNESIS_STATE.lock().unwrap();
        st.addresses_calculated && st.dest_x_addr != 0 && st.dest_y_addr != 0 && st.dest_z_addr != 0
    };
    
    if have_addrs && !nop_applied && addresses_calculated {
        let (x_addr, y_addr, z_addr) = {
            let st = MAGNESIS_STATE.lock().unwrap();
            (st.movbe_x_addr, st.movbe_y_addr, st.movbe_z_addr)
        };
        info!("[MAGNESIS_EXP] Re-activation detected with known destination addresses - applying NOPs immediately");
        match finalize_experimental_after_addresses(x_addr, y_addr, z_addr) {
            Ok(_) => info!("[MAGNESIS_EXP] ENABLE finalize: NOPs applied immediately on re-activation"),
            Err(e) => warn!("[MAGNESIS_EXP] ENABLE finalize failed on re-activation: {}", e),
        }
    } else if have_addrs && !nop_applied {
        info!("[MAGNESIS_EXP] Re-activation detected but destination addresses unknown - breakpoints will calculate them");
    }

    info!("[MAGNESIS_EXP] Magnesis control activated - waiting for breakpoints to initialize");
}

// Deactivate experimental magnesis control
pub fn deactivate_magnesis_control() {
    {
        let mut state = MAGNESIS_STATE.lock().unwrap();
        state.is_active = false;
        info!("[MAGNESIS_EXP] DISABLED (user) - experimental magnesis inactive");
        
        // Clear accumulated deltas
        state.mouse_delta_x = 0.0;
        state.mouse_delta_y = 0.0;
        state.mouse_wheel_delta = 0.0;
        
        // Reset the waiting state to prevent issues on next activation
        state.awaiting_first_valid_start = false;
        state.initial_sample = None;
        state.camera_position_needs_reset = false; // Clear camera reset flag
    }
    
    
    // Remove detours when deactivating to restore normal game behavior
    info!("[MAGNESIS_EXP] Disabling: removing experimental MOVBE breakpoints (if any) and restoring original instructions...");
    match unpatch_magnesis_instructions() {
        Ok(_) => info!("[MAGNESIS_EXP] Deactivation cleanup successful"),
        Err(e) => warn!("[MAGNESIS_EXP] Deactivation cleanup failed: {}", e),
    }
}

// Check if experimental control is active
pub fn is_magnesis_control_active() -> bool {
    let state = MAGNESIS_STATE.lock().unwrap();
    state.is_active
}

// Check if camera position needs to be reset (only after startup capture completes)
pub fn should_reset_camera_position() -> bool {
    if let Ok(state) = MAGNESIS_STATE.lock() {
        // Only allow camera reset if startup capture is complete AND reset flag is set
        state.camera_position_needs_reset && !state.awaiting_first_valid_start
    } else {
        false
    }
}

// Check if magnesis is in startup capture phase (waiting for object to move)
pub fn is_in_startup_capture_phase() -> bool {
    if let Ok(state) = MAGNESIS_STATE.lock() {
        state.is_active && state.awaiting_first_valid_start
    } else {
        false
    }
}

// Mark camera position reset as done
pub fn mark_camera_position_reset_done() {
    if let Ok(mut state) = MAGNESIS_STATE.lock() {
        state.camera_position_needs_reset = false;
    }
}

// Provide current magnesis object position if experimental control is active
pub fn get_current_magnesis_position() -> Option<(f32, f32, f32)> {
    if let Ok(state) = MAGNESIS_STATE.lock() {
        if state.is_active {
            return Some((state.current_x, state.current_y, state.current_z));
        }
    }
    None
}

// Provide base magnesis object position (before mouse movement) for stable focus point
pub fn get_base_magnesis_position() -> Option<(f32, f32, f32)> {
    if let Ok(state) = MAGNESIS_STATE.lock() {
        if state.is_active {
            return Some((state.base_x, state.base_y, state.base_z));
        }
    }
    None
}

// Get the base player position (from when magnesis started) for stable camera calculations
pub fn get_base_player_position() -> Option<(f32, f32, f32)> {
    if let Ok(state) = MAGNESIS_STATE.lock() {
        if state.is_active {
            // Calculate base player position from base object position and radius/angle
            if state.base_radius > 0.0 {
                let base_player_x = state.base_x - state.base_radius * state.base_angle.cos();
                let base_player_z = state.base_z - state.base_radius * state.base_angle.sin();
                let base_player_y = state.base_y - START_HEIGHT_OFFSET;
                return Some((base_player_x, base_player_y, base_player_z));
            }
        }
    }
    None
}


// Cleanup on exit
pub fn cleanup_magnesis_experimental() {
    let _ = unpatch_magnesis_instructions();
    // Reset monitoring thread flag to allow restart
    MONITORING_THREAD_RUNNING.store(false, std::sync::atomic::Ordering::SeqCst);
    info!("[MAGNESIS_EXP] Cleanup completed");
}

// Global flag to track if monitoring thread is already running
static MONITORING_THREAD_RUNNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// Start monitoring thread that waits for experimental MOVBE addresses and sets breakpoints
pub fn start_experimental_magnesis_monitoring() {
    // Prevent multiple monitoring threads from running simultaneously
    if MONITORING_THREAD_RUNNING.swap(true, std::sync::atomic::Ordering::SeqCst) {
        // Thread already running, don't spawn another
        return;
    }

    std::thread::spawn(|| {
        info!("[MAGNESIS_EXP] Monitoring for experimental MOVBE addresses...");
        // Keep original magnesis detection enabled for detection-only mode
        
        // Fast-path: if addresses already populated by an earlier init, install breakpoints now
        {
            let need_install_now = {
                let st = MAGNESIS_STATE.lock().unwrap();
                st.movbe_x_addr != 0 && st.movbe_y_addr != 0 && st.movbe_z_addr != 0 && !st.is_patched
            };
            if need_install_now {
                match patch_magnesis_instructions() {
                    Ok(_) => {
                        info!("[MAGNESIS_EXP] Breakpoints installed; experimental monitoring ready (fast-path)");
                        // Reset thread flag before exiting
                        MONITORING_THREAD_RUNNING.store(false, std::sync::atomic::Ordering::SeqCst);
                        return; // Done
                    }
                    Err(e) => warn!("[MAGNESIS_EXP] Fast-path breakpoint install failed: {}", e),
                }
            }
        }

        // Keep retrying until addresses are found or thread is stopped
        // Magnesis addresses only appear after player uses magnesis for the first time
        // IMPORTANT: attempt counter starts fresh on each activation, giving fast polling timers
        let mut attempt = 0;
        loop {
            // Check if thread should exit (magnesis was disabled)
            if !MONITORING_THREAD_RUNNING.load(std::sync::atomic::Ordering::SeqCst) {
                info!("[MAGNESIS_EXP] Monitoring thread stopping due to magnesis deactivation");
                return;
            }
            
            attempt += 1;
            
            // Give shared memory time to initialize
            unsafe {
                if !crate::g_shared_position_data.is_null() {
                    match get_magnesis_addresses_from_shared_memory() {
                        Ok((x, y, z)) => {
                            let active_now = {
                                let mut state = MAGNESIS_STATE.lock().unwrap();
                                state.movbe_x_addr = x;
                                state.movbe_y_addr = y;
                                state.movbe_z_addr = z;
                                info!("[MAGNESIS_EXP] Found experimental MOVBE addresses: X=0x{:x}, Y=0x{:x}, Z=0x{:x}", x, y, z);
                                state.is_active
                            };
                            if active_now {
                                // Set up breakpoints only if currently active
                                match patch_magnesis_instructions() {
                                    Ok(_) => {
                                        info!("[MAGNESIS_EXP] Breakpoints installed; experimental monitoring ready");
                                    }
                                    Err(e) => {
                                        warn!("[MAGNESIS_EXP] Failed to set breakpoints: {}", e);
                                    }
                                }
                            } else {
                                info!("[MAGNESIS_EXP] Addresses stored; will install breakpoints on ENABLE");
                            }
                            // Reset thread flag before exiting
                            MONITORING_THREAD_RUNNING.store(false, std::sync::atomic::Ordering::SeqCst);
                            return; // Done - addresses found
                        }
                        Err(_) => {
                            // Not ready yet - keep trying
                        }
                    }
                }
            }
            
            // Sleep between attempts - fast but not excessive to avoid interfering with camera
            let sleep_ms = if attempt < 100 {
                25   // Fast polling for first 2.5 seconds (100 * 25ms = 2.5s)
            } else if attempt < 300 {
                50   // Medium polling for next 10 seconds (200 * 50ms = 10s)
            } else if attempt < 600 {
                100  // Normal polling for next 30 seconds (300 * 100ms = 30s)
            } else {
                250  // Slower polling after that to avoid system interference
            };
            std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
            
            // Log progress periodically
            if attempt % 20 == 0 && attempt < 200 {
                info!("[MAGNESIS_EXP] Still waiting for experimental MOVBE addresses... (attempt {}, use magnesis rune in-game to make them detectable)", attempt);
            } else if attempt % 100 == 0 {
                info!("[MAGNESIS_EXP] Long wait for experimental MOVBE addresses... (attempt {}, use magnesis rune in-game)", attempt);
            }
        }
    });
}
