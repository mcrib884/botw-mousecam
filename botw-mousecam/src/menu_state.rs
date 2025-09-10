use std::sync::atomic::{AtomicU32, AtomicUsize, AtomicBool, Ordering};
use winapi::um::memoryapi::{VirtualQuery, VirtualProtectEx, ReadProcessMemory};
use winapi::um::errhandlingapi::{AddVectoredExceptionHandler, RemoveVectoredExceptionHandler, GetLastError};
use winapi::um::winnt::{MEMORY_BASIC_INFORMATION, EXCEPTION_POINTERS, PAGE_EXECUTE_READ, PAGE_GUARD};

// Exception constants
const EXCEPTION_GUARD_PAGE: u32 = 0x80000001;
const EXCEPTION_CONTINUE_EXECUTION: LONG_PTR = -1;
const EXCEPTION_CONTINUE_SEARCH: LONG_PTR = 0;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::shared::basetsd::LONG_PTR;
use log::*;

// Menu state detection globals
static MENU_STATE_ADDRESS: AtomicUsize = AtomicUsize::new(0);
static LAST_MENU_STATE: AtomicU32 = AtomicU32::new(0);
static MENU_MOVBE_ADDRESS: AtomicUsize = AtomicUsize::new(0);
static MENU_EXCEPTION_HANDLER: AtomicUsize = AtomicUsize::new(0);
static MENU_STATE_INITIALIZED: AtomicBool = AtomicBool::new(false);

// Menu states
const MENU_STATE_INGAME: u32 = 2;
const MENU_STATE_MENU: u32 = 3;

// Menu state detection no longer scans - gets address from position finder

// Exception handler for breakpoint on MOVBE - ONE SHOT
unsafe extern "system" fn menu_breakpoint_handler(exception_info: *mut winapi::ctypes::c_void) -> LONG_PTR {
    let exception_info = exception_info as *mut EXCEPTION_POINTERS;
    if exception_info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    let exception_record = (*exception_info).ExceptionRecord;
    let context = (*exception_info).ContextRecord;
    
    if exception_record.is_null() || context.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    // Check for guard page exception
    if (*exception_record).ExceptionCode != EXCEPTION_GUARD_PAGE {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    let exception_addr = (*exception_record).ExceptionAddress as usize;
    let movbe_addr = MENU_MOVBE_ADDRESS.load(Ordering::Relaxed) as usize;
    
    // Check if this exception is on the same page as our MOVBE
    let movbe_page = movbe_addr & !0xFFF;
    let exception_page = exception_addr & !0xFFF;
    
    if exception_page != movbe_page {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    info!("[MENU_STATE] Guard page hit at 0x{:x} (MOVBE at 0x{:x})", exception_addr, movbe_addr);
    
    // Only process if this is exactly our MOVBE instruction or very close to it
    if exception_addr >= movbe_addr && exception_addr < movbe_addr + 0x10 {
        info!("[MENU_STATE] MOVBE breakpoint hit - extracting menu state address");
        
        // Extract the target address from the instruction
        // MOVBE esi, [r13+rbx+0] - we need r13+rbx
        let r13 = (*context).R13;
        let rbx = (*context).Rbx;
        let target_addr = (r13 + rbx) as usize;
        
// Store the menu state address
MENU_STATE_ADDRESS.store(target_addr as usize, Ordering::Relaxed);
info!("[MENU_STATE] Found menu state address: 0x{:x} (r13=0x{:x}, rbx=0x{:x})", 
              target_addr, r13, rbx);
    }
    
    // ALWAYS remove the guard page for this page to prevent re-triggering
    let mut old_protect = 0u32;
    let result = VirtualProtectEx(
        GetCurrentProcess(),
        exception_page as *mut _, // Page aligned
        0x1000, // Page size
        PAGE_EXECUTE_READ, // Remove guard flag PERMANENTLY
        &mut old_protect as *mut _,
    );
    
    if result != 0 {
        info!("[MENU_STATE] Guard page removed from page 0x{:x} - breakpoint disabled", exception_page);
    } else {
        let error = GetLastError();
        info!("[MENU_STATE] WARNING: Failed to remove guard page (error: {})", error);
    }
    
    return EXCEPTION_CONTINUE_EXECUTION;
}

// Initialize menu state detection with address from position finder
pub fn init_menu_state_detection_with_address(movbe_addr: usize) -> Result<(), String> {
    if MENU_STATE_INITIALIZED.load(Ordering::Relaxed) {
        return Ok(());
    }
    
    info!("[MENU_STATE] Initializing menu state detection with MOVBE at 0x{:x}", movbe_addr);
    
MENU_MOVBE_ADDRESS.store(movbe_addr as usize, Ordering::Relaxed);
    
    unsafe {
        // Install exception handler
        let handler = AddVectoredExceptionHandler(1, Some(std::mem::transmute(menu_breakpoint_handler as *const ())));
        if handler.is_null() {
            return Err("Failed to install menu breakpoint handler".into());
        }
        MENU_EXCEPTION_HANDLER.store(handler as usize, Ordering::Relaxed);
        
        // Query current page protection
        use winapi::um::memoryapi::VirtualQuery;
        use winapi::um::winnt::MEMORY_BASIC_INFORMATION;
        
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        let page_start = (movbe_addr & !0xFFF) as *mut _; // Align to page boundary
        
        if VirtualQuery(page_start, &mut mbi, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) == 0 {
            let error = GetLastError();
            return Err(format!("Failed to query page protection (error: {})", error));
        }
        
        info!("[MENU_STATE] Current page protection at 0x{:x}: 0x{:x}", page_start as usize, mbi.Protect);
        
        // Set guard page on the MOVBE instruction
        let mut old_protect = 0u32;
        
        if VirtualProtectEx(
            GetCurrentProcess(),
            page_start,
            0x1000, // Page size
            PAGE_EXECUTE_READ | PAGE_GUARD,
            &mut old_protect as *mut _,
        ) == 0 {
            let error = GetLastError();
            return Err(format!("Failed to set guard page on MOVBE at 0x{:x} (error: {}, old_protect: 0x{:x})", 
                movbe_addr, error, mbi.Protect));
        }
        
        info!("[MENU_STATE] Guard page set on MOVBE at 0x{:x} (old protection was 0x{:x})", movbe_addr, old_protect);
    }
    
    MENU_STATE_INITIALIZED.store(true, Ordering::Relaxed);
    info!("[MENU_STATE] Menu state detection initialized successfully");
    
    Ok(())
}

// Cleanup menu state detection
pub fn cleanup_menu_state_detection() {
    if !MENU_STATE_INITIALIZED.load(Ordering::Relaxed) {
        return;
    }
    
    unsafe {
        // Remove exception handler
        let handler = MENU_EXCEPTION_HANDLER.load(Ordering::Relaxed);
        if handler != 0 {
            RemoveVectoredExceptionHandler(handler as *mut _);
        }
        
        // Remove guard page
        let movbe_addr = MENU_MOVBE_ADDRESS.load(Ordering::Relaxed) as usize;
        if movbe_addr != 0 {
            let mut old_protect = 0u32;
            let page_start = (movbe_addr & !0xFFF) as *mut _;
            VirtualProtectEx(
                GetCurrentProcess(),
                page_start,
                0x1000,
                PAGE_EXECUTE_READ, // Remove guard flag
                &mut old_protect as *mut _,
            );
        }
    }
    
    MENU_STATE_INITIALIZED.store(false, Ordering::Relaxed);
    info!("[MENU_STATE] Menu state detection cleaned up");
}

// Get current menu state
pub fn get_menu_state() -> Option<u32> {
    let state_addr = MENU_STATE_ADDRESS.load(Ordering::Relaxed) as usize;
    if state_addr == 0 {
        return None;
    }
    
    unsafe {
        let mut menu_state_bytes = [0u8; 4];
        let mut bytes_read = 0usize;
        
        if ReadProcessMemory(
            GetCurrentProcess(),
            state_addr as *const _,
            menu_state_bytes.as_mut_ptr() as *mut _,
            4,
            &mut bytes_read as *mut _,
        ) != 0 && bytes_read == 4 {
            // Convert from big endian
            Some(u32::from_be_bytes(menu_state_bytes))
        } else {
            None
        }
    }
}

// Check if currently in menu
pub fn is_in_menu() -> bool {
    get_menu_state() == Some(MENU_STATE_MENU)
}

// Check if currently in game
pub fn is_in_game() -> bool {
    get_menu_state() == Some(MENU_STATE_INGAME)
}

// Poll menu state for transitions (called from main loop)
pub fn check_menu_transition() {
    if let Some(menu_state) = get_menu_state() {
        // Swap returns the previous observed state
        let last_state = LAST_MENU_STATE.swap(menu_state, Ordering::Relaxed);

        // On first observation (uninitialized), set baseline without triggering a transition
        if last_state == 0 {
            debug!("[MENU_STATE] Initializing baseline state to {} (no transition)", menu_state);
            return;
        }
        
        // Only trigger grace period on a real menu -> in-game transition (3 -> 2)
        if last_state == MENU_STATE_MENU && menu_state == MENU_STATE_INGAME {
            // Ignore this transition if phonecamera overlay is active (photo mode may reuse the same flag)
            if !crate::is_phonecamera_flag_active_raw() {
                info!("[MENU_STATE] Menu closed - transitioned to in-game (state: {} -> {})", last_state, menu_state);
                // Set flag for main loop to handle camera snap and 0.5s phonecamera grace
                unsafe { super::set_menu_just_closed(true); }
            } else {
                info!("[MENU_STATE] 3->2 transition ignored because phonecamera flag is active");
            }
        }
        
        // Debug logging for other state changes
        if last_state != menu_state {
            info!("[MENU_STATE] Menu state changed: {} -> {}", last_state, menu_state);
        }
    }
}
