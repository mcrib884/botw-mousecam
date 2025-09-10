use winapi::um::winuser::{
    GetForegroundWindow, GetWindowTextA, GetWindowThreadProcessId, GetClassNameA, SetForegroundWindow, 
    FindWindowA, IsWindowVisible, GetWindowLongPtrA, SetWindowLongPtrA, CallWindowProcA, SetCursor,
    WM_SETCURSOR, GWLP_WNDPROC
};
use winapi::um::processthreadsapi::GetCurrentProcessId;
use winapi::shared::windef::HWND;
use winapi::shared::minwindef::{UINT, DWORD, WPARAM, LPARAM, LRESULT};
use std::ffi::{CStr, CString};
use log::{debug, info, warn};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::ptr;

pub struct FocusDetector {
    cemu_process_id: u32,
    last_check_time: std::time::Instant,
    last_result: bool,
    check_interval: std::time::Duration,
}

impl FocusDetector {
    pub fn new() -> Self {
        Self {
            cemu_process_id: 0,
            last_check_time: std::time::Instant::now() - std::time::Duration::from_secs(1),
            last_result: true, // Assume focused initially
            check_interval: std::time::Duration::from_millis(100), // Check every 100ms
        }
    }
    
    pub fn is_cemu_focused(&mut self) -> bool {
        let now = std::time::Instant::now();
        
        // Only check focus every 100ms for performance
        if now.duration_since(self.last_check_time) < self.check_interval {
            return self.last_result;
        }
        
        self.last_check_time = now;
        self.last_result = self.check_focus_internal();
        self.last_result
    }
    
    fn check_focus_internal(&mut self) -> bool {
        unsafe {
            let hwnd = GetForegroundWindow();
            if hwnd.is_null() {
                return false;
            }

            // If the console has focus, do NOT treat it as Cemu focus
            if is_console_window(hwnd) {
                return false;
            }
            
            // Get window title and class name for better detection
            let mut title: [i8; 256] = [0; 256];
            let title_len = GetWindowTextA(hwnd, title.as_mut_ptr(), title.len() as i32);
            
            let mut class_name: [i8; 256] = [0; 256];
            let class_len = GetClassNameA(hwnd, class_name.as_mut_ptr(), class_name.len() as i32);
            
            if title_len > 0 && class_len > 0 {
                let title_bytes = &title[..title_len as usize];
                let class_bytes = &class_name[..class_len as usize];
                
                if let (Ok(title_str), Ok(class_str)) = (
                    CStr::from_ptr(title_bytes.as_ptr()).to_str(),
                    CStr::from_ptr(class_bytes.as_ptr()).to_str()
                ) {
                    let title_lower = title_str.to_lowercase();
                    let class_lower = class_str.to_lowercase();
                    
                    // Debug logging for window detection
                    debug!("[FOCUS] Checking window: title='{}', class='{}'" , title_str, class_str);
                    
                    // More specific detection to avoid false positives:
                    // 1. Avoid Windows Explorer (class: "CabinetWClass" or "ExplorerWClass")
                    // 2. Look for exact Cemu window title patterns
                    // 3. Check for specific window classes that Cemu uses
                    
                    if class_lower.contains("cabinetw") || 
                       class_lower.contains("explorer") ||
                       class_lower.contains("shell_") {
                        // This is Windows Explorer or similar - not Cemu
                        debug!("[FOCUS] Rejected: Windows Explorer or shell window");
                        return false;
                    }
                    
                    // Look for specific Cemu patterns in title
                    if (title_lower.starts_with("cemu ") || title_str == "Cemu") ||
                       title_lower.contains("breath of the wild") ||
                       (title_lower.contains("zelda") && !title_lower.contains("folder") && !title_lower.contains("directory")) {
                        // Additional validation: check if it's likely a game window
                        // Game windows typically don't have explorer-like class names
                        if !class_lower.contains("cabinet") && 
                           !class_lower.contains("listview") &&
                           !class_lower.contains("syslistview") {
                            debug!("[FOCUS] Accepted: Valid Cemu window detected");
                            return true;
                        } else {
                            debug!("[FOCUS] Rejected: Has explorer-like class name");
                        }
                    } else {
                        debug!("[FOCUS] Rejected: Title doesn't match Cemu patterns");
                    }
                }
            }
            
            // Fallback: Check if the window belongs to our process (injected into CEMU) and is not a console window
            let mut process_id: u32 = 0;
            GetWindowThreadProcessId(hwnd, &mut process_id);
            
            // If we haven't stored CEMU's process ID yet, get it
            if self.cemu_process_id == 0 {
                self.cemu_process_id = GetCurrentProcessId();
            }
            
            process_id == self.cemu_process_id
        }
    }
    
    // Force an immediate focus check (for testing)
    pub fn force_check(&mut self) -> bool {
        self.last_check_time = std::time::Instant::now() - self.check_interval;
        self.is_cemu_focused()
    }
}

// Global focus detector instance
static mut FOCUS_DETECTOR: Option<FocusDetector> = None;

// Cursor control globals
static CURSOR_HIDDEN: AtomicBool = AtomicBool::new(false);
static ORIGINAL_WNDPROC: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(ptr::null_mut());
static HOOKED_HWND: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(ptr::null_mut());

// Find the Cemu main window handle by title or foreground window fallback
pub fn get_cemu_hwnd() -> HWND {
    unsafe {
        // Try by exact title first
        let title = CString::new("Cemu").unwrap();
        let hwnd = FindWindowA(std::ptr::null(), title.as_ptr());
        if !hwnd.is_null() && IsWindowVisible(hwnd) != 0 {
            // Validate this is actually Cemu and not a false positive
            if is_valid_cemu_window(hwnd) {
                return hwnd;
            }
        }
        
        // Fallback: use foreground window if it belongs to our process and passes validation
        let fg = GetForegroundWindow();
        if !fg.is_null() && !is_console_window(fg) {
            let mut pid: u32 = 0;
            GetWindowThreadProcessId(fg, &mut pid);
            if pid == GetCurrentProcessId() && IsWindowVisible(fg) != 0 && is_valid_cemu_window(fg) {
                return fg;
            }
        }
        std::ptr::null_mut()
    }
}

// Try to bring Cemu to the foreground (best-effort)
pub fn bring_cemu_to_foreground() {
    unsafe {
        let hwnd = get_cemu_hwnd();
        if !hwnd.is_null() {
            SetForegroundWindow(hwnd);
        }
    }
}

pub fn init_focus_detector() {
    unsafe {
        FOCUS_DETECTOR = Some(FocusDetector::new());
    }
}

pub fn is_cemu_focused() -> bool {
    unsafe {
        match &mut FOCUS_DETECTOR {
            Some(detector) => detector.is_cemu_focused(),
            None => {
                // If not initialized, assume focused
                true
            }
        }
    }
}

fn is_console_window(hwnd: HWND) -> bool {
    unsafe {
        let mut class_name: [i8; 256] = [0; 256];
        let len = GetClassNameA(hwnd, class_name.as_mut_ptr(), class_name.len() as i32);
        if len > 0 {
            if let Ok(name_str) = CStr::from_ptr(class_name.as_ptr()).to_str() {
                return name_str == "ConsoleWindowClass";
            }
        }
        false
    }
}

// Helper function to validate that a window is actually Cemu (not a file explorer, etc.)
fn is_valid_cemu_window(hwnd: HWND) -> bool {
    unsafe {
        let mut title: [i8; 256] = [0; 256];
        let title_len = GetWindowTextA(hwnd, title.as_mut_ptr(), title.len() as i32);
        
        let mut class_name: [i8; 256] = [0; 256];
        let class_len = GetClassNameA(hwnd, class_name.as_mut_ptr(), class_name.len() as i32);
        
        if title_len > 0 && class_len > 0 {
            let title_bytes = &title[..title_len as usize];
            let class_bytes = &class_name[..class_len as usize];
            
            if let (Ok(title_str), Ok(class_str)) = (
                CStr::from_ptr(title_bytes.as_ptr()).to_str(),
                CStr::from_ptr(class_bytes.as_ptr()).to_str()
            ) {
                let title_lower = title_str.to_lowercase();
                let class_lower = class_str.to_lowercase();
                
                // Immediately reject explorer windows
                if class_lower.contains("cabinetw") || 
                   class_lower.contains("explorer") ||
                   class_lower.contains("shell_") {
                    return false;
                }
                
                // Check for valid Cemu title patterns
                let has_valid_title = (title_lower.starts_with("cemu ") || title_str == "Cemu") ||
                                     title_lower.contains("breath of the wild") ||
                                     (title_lower.contains("zelda") && 
                                      !title_lower.contains("folder") && 
                                      !title_lower.contains("directory"));
                
                // Ensure it's not an explorer-type window
                let is_not_explorer = !class_lower.contains("cabinet") && 
                                     !class_lower.contains("listview") &&
                                     !class_lower.contains("syslistview");
                
                return has_valid_title && is_not_explorer;
            }
        }
        false
    }
}

pub fn check_cemu_focus_immediate() -> bool {
    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd.is_null() {
            return false;
        }

        // If the console has focus, do NOT treat it as Cemu focus
        if is_console_window(hwnd) {
            return false;
        }

        // Get window title and class name for better detection
        let mut title: [i8; 256] = [0; 256];
        let title_len = GetWindowTextA(hwnd, title.as_mut_ptr(), title.len() as i32);
        
        let mut class_name: [i8; 256] = [0; 256];
        let class_len = GetClassNameA(hwnd, class_name.as_mut_ptr(), class_name.len() as i32);
        
        if title_len > 0 && class_len > 0 {
            let title_bytes = &title[..title_len as usize];
            let class_bytes = &class_name[..class_len as usize];
            
            if let (Ok(title_str), Ok(class_str)) = (
                CStr::from_ptr(title_bytes.as_ptr()).to_str(),
                CStr::from_ptr(class_bytes.as_ptr()).to_str()
            ) {
                let title_lower = title_str.to_lowercase();
                let class_lower = class_str.to_lowercase();
                
                // Avoid Windows Explorer and similar windows
                if class_lower.contains("cabinetw") || 
                   class_lower.contains("explorer") ||
                   class_lower.contains("shell_") {
                    return false;
                }
                
                // Look for specific Cemu patterns
                if (title_lower.starts_with("cemu ") || title_str == "Cemu") ||
                   title_lower.contains("breath of the wild") ||
                   (title_lower.contains("zelda") && !title_lower.contains("folder") && !title_lower.contains("directory")) {
                    // Additional validation to ensure it's not an explorer window
                    if !class_lower.contains("cabinet") && 
                       !class_lower.contains("listview") &&
                       !class_lower.contains("syslistview") {
                        return true;
                    }
                }
            }
        }

        let mut process_id: u32 = 0;
        GetWindowThreadProcessId(hwnd, &mut process_id);
        let current_process_id = GetCurrentProcessId();
        process_id == current_process_id
    }
}

// Custom window procedure to handle cursor hiding
unsafe extern "system" fn custom_wnd_proc(
    hwnd: HWND,
    msg: UINT,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // Handle WM_SETCURSOR to hide cursor when needed
    if msg == WM_SETCURSOR {
        let should_hide = CURSOR_HIDDEN.load(Ordering::SeqCst);
        if should_hide {
            // Hide cursor by setting it to NULL
            SetCursor(ptr::null_mut());
            return 1; // TRUE - we handled the message
        }
    }
    
    // Pass all other messages (and WM_SETCURSOR when not hiding) to original procedure
    let original_proc = ORIGINAL_WNDPROC.load(Ordering::SeqCst);
    if !original_proc.is_null() {
        CallWindowProcA(
            std::mem::transmute(original_proc),
            hwnd,
            msg,
            wparam,
            lparam,
        )
    } else {
        0
    }
}

// Set up window procedure hooking for cursor control
pub fn setup_cursor_control() -> bool {
    unsafe {
        let hwnd = get_cemu_hwnd();
        if hwnd.is_null() {
            warn!("[CURSOR] Cannot set up cursor control - no valid Cemu window found");
            return false;
        }
        
        // Check if we're already hooked to this window
        let current_hooked = HOOKED_HWND.load(Ordering::SeqCst) as HWND;
        if current_hooked == hwnd {
            // Already hooked to this window
            return true;
        }
        
        // Clean up any existing hook first
        cleanup_cursor_control();
        
        // Get the original window procedure
        let original_proc = GetWindowLongPtrA(hwnd, GWLP_WNDPROC);
        if original_proc == 0 {
            warn!("[CURSOR] Failed to get original window procedure");
            return false;
        }
        
        // Store the original procedure and window handle
        ORIGINAL_WNDPROC.store(original_proc as *mut std::ffi::c_void, Ordering::SeqCst);
        HOOKED_HWND.store(hwnd as *mut std::ffi::c_void, Ordering::SeqCst);
        
        // Set our custom window procedure
        let result = SetWindowLongPtrA(hwnd, GWLP_WNDPROC, custom_wnd_proc as isize);
        if result == 0 {
            warn!("[CURSOR] Failed to set custom window procedure");
            // Clean up on failure
            ORIGINAL_WNDPROC.store(ptr::null_mut(), Ordering::SeqCst);
            HOOKED_HWND.store(ptr::null_mut(), Ordering::SeqCst);
            return false;
        }
        
        info!("[CURSOR] Successfully set up cursor control for Cemu window");
        true
    }
}

// Clean up window procedure hooking
pub fn cleanup_cursor_control() {
    unsafe {
        let hwnd = HOOKED_HWND.load(Ordering::SeqCst) as HWND;
        let original_proc = ORIGINAL_WNDPROC.load(Ordering::SeqCst);
        
        if !hwnd.is_null() && !original_proc.is_null() {
            // Restore original window procedure
            SetWindowLongPtrA(hwnd, GWLP_WNDPROC, original_proc as isize);
            info!("[CURSOR] Restored original window procedure for Cemu window");
        }
        
        // Clear stored values
        ORIGINAL_WNDPROC.store(ptr::null_mut(), Ordering::SeqCst);
        HOOKED_HWND.store(ptr::null_mut(), Ordering::SeqCst);
        CURSOR_HIDDEN.store(false, Ordering::SeqCst);
    }
}

// Show or hide the cursor
pub fn set_cursor_hidden(hidden: bool) {
    let was_hidden = CURSOR_HIDDEN.swap(hidden, Ordering::SeqCst);
    if was_hidden != hidden {
        if hidden {
            debug!("[CURSOR] Cursor will be hidden on next WM_SETCURSOR message");
        } else {
            debug!("[CURSOR] Cursor will be shown on next WM_SETCURSOR message");
        }
    }
}

// Check if cursor is currently set to be hidden
pub fn is_cursor_hidden() -> bool {
    CURSOR_HIDDEN.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_focus_detector_creation() {
        let detector = FocusDetector::new();
        assert_eq!(detector.cemu_process_id, 0);
        assert_eq!(detector.last_result, true);
    }
}
