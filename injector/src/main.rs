use std::{
    path::PathBuf,
    fs,
    ffi::{CString, OsString},
    ptr::null_mut,
    mem,
    os::windows::ffi::OsStringExt,
    time::Duration,
    thread,
};
use winapi::{
    um::{
        tlhelp32::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
            PROCESSENTRY32W, TH32CS_SNAPPROCESS
        },
        processthreadsapi::{
            OpenProcess, CreateRemoteThread, GetExitCodeThread,
            GetCurrentProcess, OpenProcessToken
        },
        memoryapi::{VirtualAllocEx, WriteProcessMemory, VirtualFreeEx},
        libloaderapi::{GetProcAddress, GetModuleHandleA},
        winnt::{
            PROCESS_ALL_ACCESS, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
            PROCESS_VM_OPERATION, PROCESS_VM_WRITE, PROCESS_VM_READ,
            MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, 
            PAGE_EXECUTE_READWRITE, HANDLE, TOKEN_QUERY
        },
        handleapi::CloseHandle,
        synchapi::WaitForSingleObject,
        winbase::WAIT_OBJECT_0,
        errhandlingapi::GetLastError,
        securitybaseapi::GetTokenInformation,
        winnt::TokenElevation,
    },
    shared::{
        minwindef::{DWORD, FALSE},
    },
};

const DLL_NAME: &str = "botw_mousecam.dll";
const CEMU_PROCESS_NAME: &str = "cemu.exe";
const INJECTION_TIMEOUT_MS: u32 = 15000; // 15 seconds
const WAIT_TIMEOUT: u32 = 258; // WAIT_TIMEOUT constant value
const MAX_RETRY_ATTEMPTS: u32 = 5; // Increased for better scan failure resilience
const SCAN_FAILURE_RETRY_DELAY_MS: u64 = 500; // Delay between scan failure retries
const SCAN_FAILURE_MAX_WAIT_MS: u64 = 30000; // Maximum time to wait for game startup

// Colored output utilities
struct Console;

impl Console {
    fn success(msg: &str) {
        println!("SUCCESS: {}", msg);
    }
    
    fn error(msg: &str) {
        println!("ERROR: {}", msg);
    }
    
    fn info(msg: &str) {
        println!("INFO: {}", msg);
    }
    
    fn warning(msg: &str) {
        println!("WARNING: {}", msg);
    }
    
    fn progress(msg: &str) {
        println!("... {}", msg);
    }
    
    fn header() {
        println!("╔════════════════════════════════════════════════╗");
        println!("║        BOTW Mouse Camera Injector v3.0        ║");
        println!("║              Enhanced & Robust                 ║");
        println!("╚════════════════════════════════════════════════╝");
        println!();
    }
    
    fn controls() {
        println!("CONTROLS:");
        println!("   F3 ............. Toggle mouse camera and gamepad mode");
        println!("   F4 ............. Open configuration menu");
        println!("   Mouse .......... Orbit around Link");
        println!("   Mouse wheel .... Zoom in/out");
        println!("   HOME ........... Exit mod");
    }
}

#[derive(Debug, Clone)]
struct ProcessInfo {
    pid: DWORD,
    name: String,
    path: Option<String>,
}

struct InjectionError {
    message: String,
    code: Option<DWORD>,
}

impl InjectionError {
    fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
            code: None,
        }
    }
    
    fn with_code(message: &str, code: DWORD) -> Self {
        Self {
            message: message.to_string(),
            code: Some(code),
        }
    }
    
    fn display(&self) -> String {
        match self.code {
            Some(code) => format!("{} (Error Code: {})", self.message, code),
            None => self.message.clone(),
        }
    }
}

type Result<T> = std::result::Result<T, InjectionError>;

struct Injector {
    dll_path: PathBuf,
    target_processes: Vec<ProcessInfo>,
    debug: bool,
}

impl Injector {
    fn new(debug: bool) -> Result<Self> {
        let dll_path = Self::find_dll_path()?;
        let target_processes = Self::find_target_processes()?;
        
        if target_processes.is_empty() {
            return Err(InjectionError::new(
                "Cemu process not detected"
            ));
        }
        
        Ok(Self {
            dll_path,
            target_processes,
            debug,
        })
    }
    
    fn find_dll_path() -> Result<PathBuf> {
        let current_dir = std::env::current_dir()
            .map_err(|_| InjectionError::new("Failed to get current directory"))?;
        
        let dll_path = current_dir.join(DLL_NAME);
        
        if !dll_path.exists() {
            return Err(InjectionError::new(&format!(
                "DLL not found: {}. Make sure {} is in the same folder as the injector.",
                dll_path.display(),
                DLL_NAME
            )));
        }
        
        let metadata = fs::metadata(&dll_path)
            .map_err(|_| InjectionError::new("Cannot read DLL file metadata"))?;
        
        if metadata.len() == 0 {
            return Err(InjectionError::new("DLL file is empty"));
        }
        
        Console::success(&format!("DLL found: {} ({} bytes)", dll_path.display(), metadata.len()));
        Ok(dll_path)
    }
    
    fn find_target_processes() -> Result<Vec<ProcessInfo>> {
        Console::progress("Searching for Cemu processes...");
        
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot == null_mut() {
                return Err(InjectionError::with_code(
                    "Failed to create process snapshot",
                    GetLastError()
                ));
            }
            
            let mut entry: PROCESSENTRY32W = mem::zeroed();
            entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as DWORD;
            
            if Process32FirstW(snapshot, &mut entry) == 0 {
                CloseHandle(snapshot);
                return Err(InjectionError::with_code(
                    "Failed to enumerate processes",
                    GetLastError()
                ));
            }
            
            let mut processes = Vec::new();
            
            loop {
                let process_name = Self::extract_process_name(&entry.szExeFile);
                
                if process_name.to_lowercase() == CEMU_PROCESS_NAME {
                    processes.push(ProcessInfo {
                        pid: entry.th32ProcessID,
                        name: process_name.clone(),
                        path: None, // We could get this, but not necessary for injection
                    });
                }
                
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
            
            CloseHandle(snapshot);
            
            if processes.is_empty() {
                return Err(InjectionError::new("Cemu process not detected"));
            }
            
            Console::success(&format!("Found {} Cemu process(es)", processes.len()));
            for (i, proc) in processes.iter().enumerate() {
                Console::info(&format!("  {}: {} (PID: {})", i + 1, proc.name, proc.pid));
            }
            
            Ok(processes)
        }
    }
    
    fn extract_process_name(sz_exe_file: &[u16]) -> String {
        let len = sz_exe_file.iter().position(|&c| c == 0).unwrap_or(sz_exe_file.len());
        OsString::from_wide(&sz_exe_file[..len])
            .to_string_lossy()
            .to_string()
    }
    
    fn check_privileges(&self) -> Result<bool> {
        unsafe {
            let mut token: HANDLE = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Ok(false);
            }
            
            let mut elevation = mem::zeroed::<winapi::um::winnt::TOKEN_ELEVATION>();
            let mut size = mem::size_of::<winapi::um::winnt::TOKEN_ELEVATION>() as DWORD;
            
            let result = GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut _ as *mut _,
                size,
                &mut size,
            );
            
            CloseHandle(token);
            
            if result == 0 {
                return Ok(false);
            }
            
            Ok(elevation.TokenIsElevated != 0)
        }
    }
    
    fn inject_into_process(&self, process: &ProcessInfo, attempt: u32) -> Result<()> {
        Console::progress(&format!(
            "Attempting injection into PID {} (attempt {}/{})",
            process.pid, attempt, MAX_RETRY_ATTEMPTS
        ));

        let process_handle = self.open_process(process.pid)?;

        let result = match attempt {
            1..=3 => {
                // First 3 attempts: Use LoadLibrary with scan failure resilience
                Console::info("Using LoadLibrary injection with scan failure handling...");
                self.inject_loadlibrary_with_scan_resilience(&process_handle)
            },
            4 => {
                // 4th attempt: Standard LoadLibrary with fallback
                Console::info("Using LoadLibrary injection with fallback...");
                self.inject_loadlibrary_with_fallback(&process_handle)
            },
            _ => {
                // Final attempt: Manual mapping fallback
                Console::info("Using manual mapping injection as final fallback...");
                self.inject_manual_map(&process_handle)
            }
        };

        unsafe {
            CloseHandle(process_handle);
        }
        
        result
    }
    
    fn open_process(&self, pid: DWORD) -> Result<HANDLE> {
        unsafe {
            // Try with full access first
            let process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            if !process_handle.is_null() {
                return Ok(process_handle);
            }
            
            // Fallback to minimal required permissions
            let process_handle = OpenProcess(
                PROCESS_CREATE_THREAD 
                    | PROCESS_QUERY_INFORMATION 
                    | PROCESS_VM_OPERATION 
                    | PROCESS_VM_WRITE 
                    | PROCESS_VM_READ,
                FALSE,
                pid
            );
            
            if process_handle.is_null() {
                return Err(InjectionError::with_code(
                    "Failed to open target process. Try running as Administrator.",
                    GetLastError()
                ));
            }
            
            Ok(process_handle)
        }
    }
    
    fn inject_loadlibrary(&self, process_handle: &HANDLE) -> Result<()> {
        Console::progress("Using LoadLibrary injection method...");
        
        unsafe {
            // Get absolute DLL path
            let dll_abs_path = fs::canonicalize(&self.dll_path)
                .map_err(|e| InjectionError::new(&format!("Failed to get absolute DLL path: {}", e)))?;
            
            let dll_path_str = dll_abs_path.to_string_lossy();
            let dll_path_cstr = CString::new(dll_path_str.as_ref())
                .map_err(|_| InjectionError::new("Invalid characters in DLL path"))?;
            
            Console::info(&format!("DLL path: {}", dll_path_str));
            
            // Get LoadLibraryA address
            let kernel32 = GetModuleHandleA(CString::new("kernel32.dll").unwrap().as_ptr());
            if kernel32.is_null() {
                return Err(InjectionError::new("Failed to get kernel32.dll handle"));
            }
            
            let loadlibrary_addr = GetProcAddress(
                kernel32, 
                CString::new("LoadLibraryA").unwrap().as_ptr()
            );
            if loadlibrary_addr.is_null() {
                return Err(InjectionError::new("Failed to get LoadLibraryA address"));
            }
            
            Console::info(&format!("LoadLibraryA address: {:p}", loadlibrary_addr));
            
            // Allocate memory in target process
            let path_len = dll_path_cstr.as_bytes_with_nul().len();
            let remote_memory = VirtualAllocEx(
                *process_handle,
                null_mut(),
                path_len,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            
            if remote_memory.is_null() {
                return Err(InjectionError::with_code(
                    "Failed to allocate memory in target process",
                    GetLastError()
                ));
            }
            
            Console::info(&format!("Allocated {} bytes at {:p}", path_len, remote_memory));
            
            // Write DLL path to target process
            let mut bytes_written = 0;
            let write_result = WriteProcessMemory(
                *process_handle,
                remote_memory,
                dll_path_cstr.as_ptr() as *const _,
                path_len,
                &mut bytes_written,
            );
            
            if write_result == 0 || bytes_written != path_len {
                VirtualFreeEx(*process_handle, remote_memory, 0, MEM_RELEASE);
                return Err(InjectionError::with_code(
                    "Failed to write DLL path to target process",
                    GetLastError()
                ));
            }
            
            Console::info(&format!("Wrote {} bytes to target process", bytes_written));
            
            // Create remote thread
            let thread_handle = CreateRemoteThread(
                *process_handle,
                null_mut(),
                0,
                Some(mem::transmute(loadlibrary_addr)),
                remote_memory,
                0,
                null_mut(),
            );
            
            if thread_handle.is_null() {
                VirtualFreeEx(*process_handle, remote_memory, 0, MEM_RELEASE);
                return Err(InjectionError::with_code(
                    "Failed to create remote thread",
                    GetLastError()
                ));
            }
            
            Console::progress("Remote thread created, waiting for completion...");
            
            // Wait for thread completion with timeout
            let wait_result = WaitForSingleObject(thread_handle, INJECTION_TIMEOUT_MS);
            
            let result = match wait_result {
                WAIT_OBJECT_0 => {
                    let mut exit_code = 0;
                    GetExitCodeThread(thread_handle, &mut exit_code);
                    
                    if exit_code == 0 {
                        Err(InjectionError::new(
                            "LoadLibrary returned NULL - DLL failed to load. Check for missing dependencies or antivirus interference."
                        ))
                    } else {
                        Console::success(&format!("LoadLibrary succeeded (module handle: 0x{:x})", exit_code));
                        Ok(())
                    }
                }
                258 => { // WAIT_TIMEOUT
                    Err(InjectionError::new("Injection timed out"))
                }
                _ => {
                    Err(InjectionError::with_code(
                        "Wait failed",
                        GetLastError()
                    ))
                }
            };
            
            // Cleanup
            CloseHandle(thread_handle);
            VirtualFreeEx(*process_handle, remote_memory, 0, MEM_RELEASE);
            
            result
        }
    }
    
    fn inject_loadlibrary_with_fallback(&self, process_handle: &HANDLE) -> Result<()> {
        Console::warning("Trying LoadLibrary with extended timeout...");

        // This is essentially the same as inject_loadlibrary but with different parameters
        // In a real implementation, you might try different approaches here
        self.inject_loadlibrary(process_handle)
    }

    fn inject_loadlibrary_with_scan_resilience(&self, process_handle: &HANDLE) -> Result<()> {
        Console::info("Attempting injection with scan failure resilience...");

        let start_time = std::time::Instant::now();
        let mut attempt = 1;

        loop {
            match self.inject_loadlibrary(process_handle) {
                Ok(()) => {
                    Console::success(&format!("Injection successful on resilient attempt {}", attempt));
                    return Ok(());
                },
                Err(e) => {
                    let error_msg = e.display();

                    // Check if this looks like a scan failure (DLL failed to load)
                    let is_scan_failure = error_msg.contains("DLL failed to load") ||
                                         error_msg.contains("LoadLibrary returned NULL") ||
                                         error_msg.contains("missing dependencies");

                    if is_scan_failure && start_time.elapsed().as_millis() < SCAN_FAILURE_MAX_WAIT_MS as u128 {
                        Console::warning(&format!(
                            "Scan failure detected (attempt {}): {}. Game may still be starting up...",
                            attempt, error_msg
                        ));
                        Console::info(&format!(
                            "Waiting {}ms before retry (game startup can take time)...",
                            SCAN_FAILURE_RETRY_DELAY_MS
                        ));

                        thread::sleep(Duration::from_millis(SCAN_FAILURE_RETRY_DELAY_MS));
                        attempt += 1;
                        continue;
                    } else {
                        // Not a scan failure or timeout exceeded, return the error
                        if start_time.elapsed().as_millis() >= SCAN_FAILURE_MAX_WAIT_MS as u128 {
                            Console::error(&format!(
                                "Scan failure resilience timeout after {}ms. Game may not be fully loaded.",
                                SCAN_FAILURE_MAX_WAIT_MS
                            ));
                        }
                        return Err(e);
                    }
                }
            }
        }
    }

    fn inject_manual_map(&self, _process_handle: &HANDLE) -> Result<()> {
        Console::warning("Manual mapping injection not implemented in this version");
        Err(InjectionError::new("Manual mapping injection is not implemented"))
    }
    
    fn run(&self) -> Result<()> {
        Console::header();
        
        if self.debug {
            Console::info("Debug mode: ON (verbose diagnostics may be enabled in future versions)");
        }
        
        // Check privileges
        if !self.check_privileges()? {
            Console::warning("Not running as Administrator - some features may not work");
            Console::info("For best results, right-click and 'Run as Administrator'");
        } else {
            Console::success("Running with Administrator privileges");
        }
        
        println!();
        
        // Try to inject into each process
        let mut injection_successful = false;
        
        for process in &self.target_processes {
            for attempt in 1..=MAX_RETRY_ATTEMPTS {
                match self.inject_into_process(process, attempt) {
                    Ok(()) => {
                        Console::success(&format!("Successfully injected into PID {}", process.pid));
                        injection_successful = true;
                        break;
                    }
                    Err(e) => {
                        if attempt == MAX_RETRY_ATTEMPTS {
                            Console::error(&format!("Failed to inject into PID {}: {}", process.pid, e.display()));
                        } else {
                            let error_msg = e.display();
                            let is_scan_failure = error_msg.contains("DLL failed to load") ||
                                                 error_msg.contains("LoadLibrary returned NULL") ||
                                                 error_msg.contains("missing dependencies");

                            if is_scan_failure {
                                Console::warning(&format!("Scan failure on attempt {}: {}", attempt, error_msg));
                                Console::info("This may indicate the game is still starting up. Retrying in 1 second...");
                                thread::sleep(Duration::from_secs(1));
                            } else {
                                Console::warning(&format!("Attempt {} failed: {}", attempt, error_msg));
                                Console::info("Retrying in 2 seconds...");
                                thread::sleep(Duration::from_secs(2));
                            }
                        }
                    }
                }
            }
            
            if injection_successful {
                break;
            }
        }
        
        if !injection_successful {
            return Err(InjectionError::new("Failed to inject into any Cemu process"));
        }
        
        println!();
        Console::success("INJECTION SUCCESSFUL");
        println!();
        Console::controls();
        println!();
        Console::success("Mouse camera mod is now active in BOTW!");
        println!();
        Console::info("Closing injector...");
        
        Ok(())
    }
}

fn show_troubleshooting() {
    println!();
    Console::error("INJECTION FAILED");
    println!();
    println!("TROUBLESHOOTING STEPS:");
    println!("   1. Right-click injector.exe → 'Run as Administrator'");
    println!("   2. Temporarily disable antivirus/Windows Defender");
    println!("   3. Make sure BOTW is actually loaded (not just Cemu menu)");
    println!("   4. Ensure you're using a supported BOTW version (v1.5.0)");
    println!("   5. Try restarting Cemu completely");
    println!("   6. Check Windows Event Viewer for detailed error messages");
    println!("   7. Verify {} is not corrupted", DLL_NAME);
    println!();
    println!("ADDITIONAL NOTES:");
    println!("   • Some antivirus programs block DLL injection");
    println!("   • Cemu must be running the actual game, not just the menu");
    println!("   • If using graphics packs, try disabling them temporarily");
}

fn show_cemu_not_found_message() {
    println!();
    println!("Cemu was not detected.");
    println!();
    println!("To proceed:");
    println!("  1. Start Cemu and launch The Legend of Zelda: Breath of the Wild.");
    println!("  2. Load into the game world (not just the main menu).");
    println!("  3. Close this window and run injector.exe again.");
    println!();
    println!("If the issue persists:");
    println!("  - If Cemu is running as Administrator, run injector.exe as Administrator as well.");
    println!("  - Temporarily disable antivirus or add an exception for injector.exe.");
    println!("  - Ensure Cemu is not paused and is the standard \"cemu.exe\" process.");
}

fn pause_and_exit() {
    println!();
    println!("Press Enter to exit...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();
}

fn main() {
    // Parse command-line flags (future use): --debug / -d
    let debug = std::env::args().skip(1).any(|a| a == "--debug" || a == "-d");

    let result = Injector::new(debug).and_then(|injector| injector.run());
    
    match result {
        Ok(()) => {
            // Success case already handled in run() - injector will close automatically
        }
        Err(e) => {
            let msg = e.display();
            if msg.contains("Cemu process not detected") {
                // Professional, minimal guidance for not-found case
                show_cemu_not_found_message();
            } else {
                Console::error(&msg);
                show_troubleshooting();
            }
            pause_and_exit();
        }
    }
}