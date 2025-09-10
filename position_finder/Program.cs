using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;

namespace PositionFinder
{
    class Program
    {
        private static MemAPI mem;
        private static long coordinatesAddress = -1L;
        private static long playerStatePatternAddress = -1L;  // AOB pattern location
        private static long playerStateDataAddress = -1L;     // Calculated data address (r13+rdx+0x770)
        private static byte lastPlayerState = 255;            // Track last player state value
        private static long menuMovbeAddress = -1L;           // Menu MOVBE instruction address
        private static long magnesisMovbeAddress = -1L;       // Normal magnesis MOVBE instruction address
        private static long expMagnesisMovbeXAddress = -1L;   // Experimental magnesis X MOVBE instruction address
        private static long expMagnesisMovbeYAddress = -1L;   // Experimental magnesis Y MOVBE instruction address
        private static long expMagnesisMovbeZAddress = -1L;   // Experimental magnesis Z MOVBE instruction address
        private static long cameraCmpxchgAddress = -1L;       // Camera lock cmpxchg instruction address
        private static MemoryMappedFile mmf;
        private static MemoryMappedViewAccessor accessor;
        private static bool running = true;
        private static string logFilePath = "position_finder.log";
        private static StreamWriter logWriter;
        private static bool silentMode = false;
        private static bool wasConnectedToCemu = false;
        private static int lastCemuProcessId = -1;
        private static DateTime startTime = DateTime.Now;
        private static readonly TimeSpan MaxWaitTime = TimeSpan.FromMinutes(10); // Exit if no Cemu found for 10 minutes
        
        // Enhanced crash detection variables
        private static DateTime lastSuccessfulCheck = DateTime.Now;
        private static readonly TimeSpan CrashDetectionTimeout = TimeSpan.FromSeconds(30); // Exit if can't connect for 30 seconds
        private static bool hasValidatedOnce = false; // Track if we've ever successfully validated
        
        // Magnesis periodic search variables
        private static DateTime lastMagnesisSearchTime = DateTime.MinValue;
        private static readonly TimeSpan MagnesisSearchInterval = TimeSpan.FromSeconds(2); // Search every ~2 seconds until found
        // Experimental magnesis periodic search (for control) - independent timer
        private static DateTime lastExpMagnesisSearchTime = DateTime.MinValue;
        private static readonly TimeSpan ExpMagnesisSearchInterval = TimeSpan.FromSeconds(2);
        
        // PhoneCamera periodic search variables
        private static DateTime lastPhoneCameraSearchTime = DateTime.MinValue;
        private static readonly TimeSpan PhoneCameraSearchInterval = TimeSpan.FromSeconds(2); // Search every 2 seconds
        
        // Shared memory structure to communicate with mousecam dll
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct SharedPositionData
        {
            public ulong position_address;              // 0-7
            public ulong last_update;                   // 8-15
            public uint is_valid;                       // 16-19
            public ulong player_state_address;          // 20-27
            public uint player_state_value;             // 28-31
            public uint player_state_valid;             // 32-35
            public ulong movzx_instruction_address;     // 36-43
            public uint movzx_instruction_valid;        // 44-47
            public ulong menu_movbe_address;            // 48-55
            public uint menu_movbe_valid;               // 56-59
            // Normal magnesis MOVBE addresses (X, Y, Z) - for detection only
            public ulong magnesis_instruction_address;  // 60-67 (X coordinate MOVBE)
            public uint magnesis_instruction_valid;     // 68-71
            public ulong magnesis_y_instruction_address; // 72-79 (Y coordinate MOVBE)
            public uint magnesis_y_instruction_valid;   // 80-83
            public ulong magnesis_z_instruction_address; // 84-91 (Z coordinate MOVBE)
            public uint magnesis_z_instruction_valid;   // 92-95
            // Experimental magnesis MOVBE addresses (X, Y, Z) - for mouse control override
            public ulong exp_magnesis_x_address;        // 96-103 (Experimental X coordinate MOVBE)
            public uint exp_magnesis_x_valid;           // 104-107
            public ulong exp_magnesis_y_address;        // 108-115 (Experimental Y coordinate MOVBE)
            public uint exp_magnesis_y_valid;           // 116-119
            public ulong exp_magnesis_z_address;        // 120-127 (Experimental Z coordinate MOVBE)
            public uint exp_magnesis_z_valid;           // 128-131
            // Camera lock cmpxchg instruction address - for camera open detection
            public ulong camera_cmpxchg_address;        // 132-139 (Camera lock cmpxchg instruction)
            public uint camera_cmpxchg_valid;           // 140-143
            // Synchronization and control
            public uint shm_version;                    // 144-147
            public uint shm_seq;                        // 148-151
            public uint ready_flags;                    // 152-155
            public uint request_flags;                  // 156-159
        }

        // Using existing MEMORY_BASIC_INFORMATION from MemAPI

        static void Main(string[] args)
        {
            try
            {
                // Check for silent mode (auto launch)
                silentMode = args.Length > 0 && args.Contains("--auto");
                
                InitializeLogging();
                
                LogMessage("=== BOTW Position Finder v1.0 Started ===");
                LogMessage("Based on botw_editor architecture");
                LogMessage("Extracting Link position data from Cemu BOTW and providing it to mousecam dll");
                LogMessage($"Working Directory: {Environment.CurrentDirectory}");
                LogMessage($"Executable Path: {Environment.ProcessPath}");
                LogMessage($"Runtime Version: {Environment.Version}");
                LogMessage($"Command Line Args: {string.Join(" ", args)}");
                LogMessage($"Silent Mode: {silentMode}");
                
                if (!silentMode)
                {
                    LogMessage("BOTW Position Finder v1.0");
                    LogMessage("Based on botw_editor architecture");
                    LogMessage("Extracting Link position data from Cemu BOTW and providing it to mousecam dll");
                    LogMessage($"Logging to: {logFilePath}");
                    LogMessage("Press Ctrl+C to exit");
                    Console.WriteLine();
                }

                // Set up console cancel handler
                Console.CancelKeyPress += (sender, e) => {
                    e.Cancel = true;
                    running = false;
                    LogMessage("Shutdown requested via Ctrl+C");
                    if (!silentMode)
                    {
                        LogMessage("Shutting down...");
                    }
                };

                LogMessage("Initializing components...");
                InitializeMemoryAPI();
                InitializeSharedMemory();
                RunPositionFinder();
            }
            catch (Exception ex)
            {
                string errorMsg = $"FATAL ERROR: {ex.Message}\n{ex.StackTrace}";
                LogMessage(errorMsg);
                
                if (!silentMode)
                {
                    LogMessage($"Error: {ex.Message}");
                    LogMessage("Check position_finder.log for details");
                    LogMessage("Press any key to exit...");
                    Console.ReadKey();
                }
            }
            finally
            {
                LogMessage("=== Position Finder Shutting Down ===");
                CleanupResources();
            }
        }

        static void InitializeLogging()
        {
            try
            {
                // Reset log file like the Rust DLL does (start fresh each run)
                try
                {
                    if (File.Exists(logFilePath))
                    {
                        File.Delete(logFilePath);
                    }
                }
                catch (Exception exDel)
                {
                    if (!silentMode)
                    {
                        Console.WriteLine($"Warning: Could not delete old log: {exDel.Message}");
                    }
                }

                // Create a new log file (no append)
                logWriter = new StreamWriter(logFilePath, append: false);
                logWriter.AutoFlush = true;
            }
            catch (Exception ex)
            {
                if (!silentMode)
                {
                    Console.WriteLine($"Warning: Could not initialize logging: {ex.Message}");
                }
            }
        }

        static void LogMessage(string message)
        {
            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            string logEntry = $"[{timestamp}] {message}";
            
            // Only output to console if not in silent mode
            if (!silentMode)
            {
                Console.WriteLine(logEntry);
            }
            
            try
            {
                logWriter?.WriteLine(logEntry);
            }
            catch
            {
                // Ignore logging errors
            }
        }

        static void InitializeMemoryAPI()
        {
            try
            {
                LogMessage("Initializing Memory API...");
                mem = new MemAPI();
                mem.ProcessName = "Cemu";
                LogMessage("Memory API initialized, targeting Cemu process");
            }
            catch (Exception ex)
            {
                LogMessage($"Failed to initialize Memory API: {ex.Message}");
                throw;
            }
        }

        static void InitializeSharedMemory()
        {
            try
            {
                LogMessage("Initializing shared memory...");
                LogMessage($"Shared memory name: Local\\BotwPositionData");
                LogMessage($"Structure size: {Marshal.SizeOf<SharedPositionData>()} bytes");
                
                // Create shared memory for communication with mousecam dll
                mmf = MemoryMappedFile.CreateOrOpen("Local\\BotwPositionData", Marshal.SizeOf<SharedPositionData>());
                accessor = mmf.CreateViewAccessor();

                // Initialize protocol fields
                var data = new SharedPositionData();
                accessor.Read(0, out data);
                data.shm_version = 1;
                if (data.shm_seq == 0) data.shm_seq = 1;
                data.ready_flags = 0;
                // Keep any request flags that might have been set by DLL if it created the mapping first
                accessor.Write(0, ref data);

                LogMessage("Shared memory initialized successfully");
            }
            catch (Exception ex)
            {
                LogMessage($"Failed to initialize shared memory: {ex.Message}");
                throw new Exception($"Failed to initialize shared memory: {ex.Message}");
            }
        }

        static void RunPositionFinder()
        {
            LogMessage("Starting position finder main loop...");
            int loopCount = 0;
            
            while (running)
            {
                try
                {
                    loopCount++;

                    // Process any requests from DLL immediately to stay in sync
                    ProcessDllRequests();
                    if (loopCount % 30 == 1) // Log every ~30 seconds to avoid spam
                    {
                        LogMessage($"Main loop iteration #{loopCount}");
                    }

                    // Enhanced crash detection: Check if Cemu process is running
                    mem.UpdateProcess("");
                    if (mem.p == null)
                    {
                        // If we were previously connected to Cemu but now it's gone, exit immediately
                        if (wasConnectedToCemu)
                        {
                            LogMessage("Cemu process has exited or crashed. Position finder will now terminate.");
                            running = false;
                            break;
                        }
                        
                        if (loopCount % 2 == 1) // Log every ~10 seconds when waiting (since we sleep 5s now)
                        {
                            LogMessage("Waiting for Cemu process...");
                        }
                        
                        // Exit if we've been waiting too long without ever connecting to Cemu
                        if (!wasConnectedToCemu && DateTime.Now - startTime > MaxWaitTime)
                        {
                            LogMessage($"No Cemu process found after {MaxWaitTime.TotalMinutes} minutes. Position finder will terminate.");
                            running = false;
                            break;
                        }
                        
                        UpdateSharedMemory(0, false);
                        Thread.Sleep(5000); // Reduced frequency for crash detection
                        continue;
                    }
                    
                    // Enhanced crash detection: Check if DLL is still responsive
                    if (hasValidatedOnce && !CheckModuleStillLoaded())
                    {
                        LogMessage("Mod DLL appears to have been unloaded or crashed. Position finder will terminate.");
                        running = false;
                        break;
                    }
                    
                    // Check if this is a different Cemu process than before
                    if (wasConnectedToCemu && lastCemuProcessId != -1 && mem.p.Id != lastCemuProcessId)
                    {
                        LogMessage($"Cemu process changed (old PID: {lastCemuProcessId}, new PID: {mem.p.Id}). Position finder will restart search.");
                        coordinatesAddress = -1L; // Reset position search for new process
                        magnesisMovbeAddress = -1L; // Reset magnesis search for new process
                        wasConnectedToCemu = false; // Reset connection state
                        lastCemuProcessId = -1;

                        // Clear magnesis readiness in shared memory to avoid stale addresses
                        try
                        {
                            var d = new SharedPositionData(); accessor.Read(0, out d);
                            d.magnesis_instruction_valid = 0; d.magnesis_y_instruction_valid = 0; d.magnesis_z_instruction_valid = 0;
                            d.exp_magnesis_x_valid = 0; d.exp_magnesis_y_valid = 0; d.exp_magnesis_z_valid = 0;
                            d.ready_flags &= ~(1u << 3);
                            d.ready_flags &= ~(1u << 4);
                            unchecked { d.shm_seq += 1; }
                            accessor.Write(0, ref d);
                        }
                        catch { }
                    }

                    if (loopCount % 30 == 2)
                    {
                        LogMessage($"Cemu process found: PID {mem.p.Id}, Name: {mem.p.ProcessName}");
                    }

                    if (!mem.CheckOpenProcess())
                    {
                        LogMessage("Cannot access Cemu process memory. Insufficient privileges?");
                        UpdateSharedMemory(0, false);
                        Thread.Sleep(2000);
                        continue;
                    }
                    
                    // Mark that we have successfully connected to this Cemu process
                    if (!wasConnectedToCemu || lastCemuProcessId != mem.p.Id)
                    {
                        wasConnectedToCemu = true;
                        lastCemuProcessId = mem.p.Id;
                        LogMessage($"Successfully connected to Cemu process (PID: {mem.p.Id})");
                    }

                    // Special case: Magnesis needs periodic scanning until found, then we can stop
                    try
                    {
                        var dchk = new SharedPositionData(); accessor.Read(0, out dchk);
                        // Normal magnesis X MOVBE
                        if (magnesisMovbeAddress < 0L)
                        {
                            bool alreadyReady = dchk.magnesis_instruction_valid != 0 || (dchk.ready_flags & (1u << 3)) != 0;
                            if (alreadyReady)
                            {
                                magnesisMovbeAddress = (long)dchk.magnesis_instruction_address;
                            }
                            else if (DateTime.Now - lastMagnesisSearchTime >= MagnesisSearchInterval)
                            {
                                lastMagnesisSearchTime = DateTime.Now;
                                long found = FindMagnesisMovbeAddress();
                                if (found >= 0L)
                                {
                                    magnesisMovbeAddress = found;
                                    var d = new SharedPositionData(); accessor.Read(0, out d);
                                    d.magnesis_instruction_address = (ulong)magnesisMovbeAddress;
                                    d.magnesis_instruction_valid = 1;
                                    d.ready_flags |= 1u << 3; // READY_MAGNESIS_NORMAL
                                    unchecked { d.shm_seq += 1; }
                                    accessor.Write(0, ref d);
                                    LogMessage("[BG] Magnesis MOVBE found and published to DLL");
                                }
                                else
                                {
                                    LogMessage("[BG] Magnesis MOVBE not found this pass (will retry)");
                                }
                            }
                        }
                        // Experimental magnesis X/Y/Z MOVBEs for control
                        if (expMagnesisMovbeXAddress < 0L || expMagnesisMovbeYAddress < 0L || expMagnesisMovbeZAddress < 0L)
                        {
                            bool expReady = dchk.exp_magnesis_x_valid != 0 && dchk.exp_magnesis_y_valid != 0 && dchk.exp_magnesis_z_valid != 0;
                            if (expReady)
                            {
                                expMagnesisMovbeXAddress = (long)dchk.exp_magnesis_x_address;
                                expMagnesisMovbeYAddress = (long)dchk.exp_magnesis_y_address;
                                expMagnesisMovbeZAddress = (long)dchk.exp_magnesis_z_address;
                            }
                            else if (DateTime.Now - lastExpMagnesisSearchTime >= ExpMagnesisSearchInterval)
                            {
                                lastExpMagnesisSearchTime = DateTime.Now;
                                var (x, y, z) = FindExperimentalMagnesisMovbeAddresses();
                                if (x >= 0L && y >= 0L && z >= 0L)
                                {
                                    expMagnesisMovbeXAddress = x;
                                    expMagnesisMovbeYAddress = y;
                                    expMagnesisMovbeZAddress = z;
                                    var d = new SharedPositionData(); accessor.Read(0, out d);
                                    d.exp_magnesis_x_address = (ulong)x; d.exp_magnesis_x_valid = 1;
                                    d.exp_magnesis_y_address = (ulong)y; d.exp_magnesis_y_valid = 1;
                                    d.exp_magnesis_z_address = (ulong)z; d.exp_magnesis_z_valid = 1;
                                    d.ready_flags |= 1u << 4; // READY_MAGNESIS_EXP (optional)
                                    unchecked { d.shm_seq += 1; }
                                    accessor.Write(0, ref d);
                                    LogMessage("[BG] EXP Magnesis MOVBE X/Y/Z found and published to DLL");
                                }
                                else
                                {
                                    LogMessage("[BG] EXP Magnesis MOVBE not found this pass (will retry)");
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        LogMessage($"Magnesis periodic search error: {ex.Message}");
                    }

                    // Keep loop responsive
                    Thread.Sleep(50);
                    continue;
                }
                catch (Exception ex)
                {
                    LogMessage($"Error in main loop: {ex.Message}\n{ex.StackTrace}");
                    Thread.Sleep(2000);
                }
            }
            
            LogMessage("Main loop exited");
        }

        // Handle DLL requests: if request_flags bits are set, trigger immediate scans
        static void ProcessDllRequests()
        {
            try
            {
                var data = new SharedPositionData();
                accessor.Read(0, out data);
                uint requests = data.request_flags;
                if (requests == 0) return;

                // Clear requests after reading to avoid repeated immediate scans; bump seq
                data.request_flags = 0;
                unchecked { data.shm_seq += 1; }
                accessor.Write(0, ref data);

                // Process bits
                if ((requests & (1u << 0)) != 0) // REQ_POS
                {
                    LogMessage("[SYNC] DLL requested POS scan now");
                    if (coordinatesAddress < 0L)
                    {
                        coordinatesAddress = FindCoordinatesAddress();
                        if (coordinatesAddress >= 0L)
                        {
                            var d = new SharedPositionData(); accessor.Read(0, out d);
                            d.position_address = (ulong)coordinatesAddress; d.is_valid = 1; d.ready_flags |= 1u << 0; unchecked { d.shm_seq += 1; }
                            accessor.Write(0, ref d);
                            LogMessage($"[SYNC] POS sent to DLL: 0x{coordinatesAddress:X}");
                        }
                    }
                }
                if ((requests & (1u << 2)) != 0) // REQ_MENU_MOVBE
                {
                    LogMessage("[SYNC] DLL requested Menu MOVBE scan now");
                    if (menuMovbeAddress < 0L)
                    {
                        menuMovbeAddress = FindMenuMovbeAddress();
                        if (menuMovbeAddress >= 0L)
                        {
                            var d = new SharedPositionData(); accessor.Read(0, out d);
                            d.menu_movbe_address = (ulong)menuMovbeAddress; d.menu_movbe_valid = 1; d.ready_flags |= 1u << 2; unchecked { d.shm_seq += 1; }
                            accessor.Write(0, ref d);
                            LogMessage("[SYNC] Menu MOVBE sent to DLL");
                        }
                    }
                }
                if ((requests & (1u << 3)) != 0) // REQ_MAGNESIS_NORMAL
                {
                    LogMessage("[SYNC] DLL requested Magnesis MOVBE scan now");
                    if (magnesisMovbeAddress < 0L)
                    {
                        magnesisMovbeAddress = FindMagnesisMovbeAddress();
                        if (magnesisMovbeAddress >= 0L)
                        {
                            var d = new SharedPositionData(); accessor.Read(0, out d);
                            d.magnesis_instruction_address = (ulong)magnesisMovbeAddress; d.magnesis_instruction_valid = 1; d.ready_flags |= 1u << 3; unchecked { d.shm_seq += 1; }
                            accessor.Write(0, ref d);
                            LogMessage("[SYNC] Magnesis MOVBE sent to DLL");
                        }
                    }
                    // Also try to find EXPERIMENTAL magnesis MOVBE addresses for control
                    if (expMagnesisMovbeXAddress < 0L || expMagnesisMovbeYAddress < 0L || expMagnesisMovbeZAddress < 0L)
                    {
                        var (x, y, z) = FindExperimentalMagnesisMovbeAddresses();
                        if (x >= 0L && y >= 0L && z >= 0L)
                        {
                            expMagnesisMovbeXAddress = x; expMagnesisMovbeYAddress = y; expMagnesisMovbeZAddress = z;
                            var d = new SharedPositionData(); accessor.Read(0, out d);
                            d.exp_magnesis_x_address = (ulong)x; d.exp_magnesis_x_valid = 1;
                            d.exp_magnesis_y_address = (ulong)y; d.exp_magnesis_y_valid = 1;
                            d.exp_magnesis_z_address = (ulong)z; d.exp_magnesis_z_valid = 1;
                            // Optional: mark READY bit 4 for experimental
                            d.ready_flags |= 1u << 4;
                            unchecked { d.shm_seq += 1; }
                            accessor.Write(0, ref d);
                            LogMessage("[SYNC] EXP Magnesis MOVBE (X/Y/Z) sent to DLL");
                        }
                    }
                }
                if ((requests & (1u << 5)) != 0) // REQ_PHONECAMERA
                {
                    LogMessage("[SYNC] DLL requested PhoneCamera scan now");
                    if (cameraCmpxchgAddress < 0L)
                    {
                        cameraCmpxchgAddress = FindCameraCmpxchgAddress();
                        if (cameraCmpxchgAddress >= 0L)
                        {
                            var d = new SharedPositionData(); accessor.Read(0, out d);
                            d.camera_cmpxchg_address = (ulong)cameraCmpxchgAddress; d.camera_cmpxchg_valid = 1; d.ready_flags |= 1u << 5; unchecked { d.shm_seq += 1; }
                            accessor.Write(0, ref d);
                            LogMessage("[SYNC] PhoneCamera address sent to DLL");
                        }
                    }
                }
                if ((requests & (1u << 1)) != 0) // REQ_MOVZX
                {
                    LogMessage("[SYNC] DLL requested movzx pattern scan now");
                    if (playerStatePatternAddress < 0L)
                    {
                        playerStatePatternAddress = FindPlayerStateAddress();
                        if (playerStatePatternAddress >= 0L)
                        {
                            long movzxInstructionAddress = playerStatePatternAddress + 32;
                            var d = new SharedPositionData(); accessor.Read(0, out d);
                            d.movzx_instruction_address = (ulong)movzxInstructionAddress; d.movzx_instruction_valid = 1; d.ready_flags |= 1u << 1; unchecked { d.shm_seq += 1; }
                            accessor.Write(0, ref d);
                            LogMessage("[SYNC] movzx address sent to DLL");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage($"Error in ProcessDllRequests: {ex.Message}");
            }
        }

        static long FindCoordinatesAddress()
        {
            try
            {
                LogMessage("Starting coordinate address search...");
                
                // Find memory region similar to botw_editor approach
                long regionStart = 0L;
                long regionSize = 0L;
                
                // Try different known region sizes for different BOTW versions
                long[] possibleSizes = { 0x54720000, 0x55F20000, 0x4E000000, 0xE2000000 };
                
                LogMessage($"Searching for memory regions with known sizes: {string.Join(", ", possibleSizes.Select(s => $"0x{s:X}"))}");
                
                foreach (long size in possibleSizes)
                {
                    LogMessage($"Trying region size: 0x{size:X} ({size / 1024 / 1024}MB)");
                    if (mem.FindRegionBySize(size, out regionStart, out regionSize, IntPtr.Zero, 0L, true) && regionStart > 0L)
                    {
                        LogMessage($"Found memory region: 0x{regionStart:X} - 0x{(regionStart + regionSize):X} (size: 0x{regionSize:X})");
                        break;
                    }
                }

                if (regionStart <= 0L)
                {
                    LogMessage("Could not find suitable memory region");
                    return -1L;
                }

                // Use botw_editor's exact coordinate finding pattern
                LogMessage("Searching for coordinate pattern in found region...");
                return FindCoordinatesAddressInRegion(regionStart, regionSize);
            }
            catch (Exception ex)
            {
                LogMessage($"Error in FindCoordinatesAddress: {ex.Message}\n{ex.StackTrace}");
                return -1L;
            }
        }

        static long FindCoordinatesAddressInRegion(long startAddress, long regionSize)
        {
            try
            {
                LogMessage($"Scanning region 0x{startAddress:X} - 0x{(startAddress + regionSize):X} for coordinate pattern");
                
                // This is the exact pattern from botw_editor's findCoordinatesAddress method
                int[] searchPattern = new int[]
                {
                    3, 1, 61, 47, 206, 179, 16, -1, -1, -1, 255, 255, 0, 1, 7, 255
                };
                
                long offsetFromPattern = 102L;
                
                LogMessage($"Using pattern: [{string.Join(", ", searchPattern)}]");
                LogMessage($"Pattern offset: {offsetFromPattern} bytes");
                LogMessage("Executing memory pattern search...");
                
                long foundAddress = mem.pagedMemorySearchMatch(searchPattern, startAddress, regionSize);
                
                if (foundAddress >= 0L)
                {
                    foundAddress += offsetFromPattern;
                    LogMessage($"Pattern found at 0x{foundAddress - offsetFromPattern:X}, calculated coordinates address: 0x{foundAddress:X}");
                    return foundAddress;
                }
                
                LogMessage("Pattern not found in this region");
                return -1L;
            }
            catch (Exception ex)
            {
                LogMessage($"Error in FindCoordinatesAddressInRegion: {ex.Message}\n{ex.StackTrace}");
                return -1L;
            }
        }

        static bool ReadAndValidateCoordinates()
        {
            if (coordinatesAddress < 0L) 
            {
                LogMessage("ReadAndValidateCoordinates called but coordinatesAddress is invalid");
                return false;
            }

            try
            {
                float x = mem.GetSingleAt(coordinatesAddress);
                float y = mem.GetSingleAt(coordinatesAddress + 4L);
                float z = mem.GetSingleAt(coordinatesAddress + 8L);

                // Validate coordinates are reasonable (similar to botw_editor)
                if (IsReasonableCoordinate(x, y, z))
                {
                    // Log position occasionally to avoid spam
                    if (DateTime.Now.Second % 30 == 0)
                    {
                        LogMessage($"Current position: X={x:F2}, Y={y:F2}, Z={z:F2}");
                    }
                    return true;
                }
                else
                {
                    LogMessage($"Invalid coordinates: X={x:F2}, Y={y:F2}, Z={z:F2}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                LogMessage($"Error reading coordinates: {ex.Message}");
                return false;
            }
        }

        static bool IsReasonableCoordinate(float x, float y, float z)
        {
            // BOTW world coordinates are typically within these ranges
            return Math.Abs(x) < 10000f && Math.Abs(y) < 10000f && Math.Abs(z) < 10000f &&
                   !float.IsNaN(x) && !float.IsNaN(y) && !float.IsNaN(z) &&
                   !float.IsInfinity(x) && !float.IsInfinity(y) && !float.IsInfinity(z);
        }

        static void UpdateSharedMemory(ulong positionAddress, bool isValid)
        {
            try
            {
                // READ existing data first to preserve other fields
                var data = new SharedPositionData();
                accessor.Read(0, out data);

                // Only update position-related fields
                data.position_address = positionAddress;
                data.last_update = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                data.is_valid = isValid ? 1u : 0u;
                if (isValid) data.ready_flags |= 1u << 0; // READY_POS

                // bump sequence
                unchecked { data.shm_seq += 1; }
                accessor.Write(0, ref data);

                // Log all updates for debugging
                LogMessage($"Shared memory updated: Address=0x{positionAddress:X}, Valid={isValid}, Timestamp={data.last_update}");

                // Debug: Show if movzx data is preserved
                if (data.movzx_instruction_valid != 0)
                {
                    LogMessage($"Movzx data preserved: Address=0x{data.movzx_instruction_address:X}, Valid={data.movzx_instruction_valid}");
                }
            }
            catch (Exception ex)
            {
                LogMessage($"Error updating shared memory: {ex.Message}");
            }
        }

        // Menu MOVBE AOB pattern and search function
        static readonly byte[] MenuMovbeAob = new byte[]
        {
            0x24, 0xB8, 0x02, 0x00, 0x00, 0x80, 0xC6, 0xDA, 0x02, 0xBA, 0xC0, 0x21, 0xDE, 0x02, 0x41, 0xFF,
            0xA7, 0x80, 0x43, 0xBC, 0x25, 0x83, 0xAC, 0x24, 0xB0, 0x02, 0x00, 0x00, 0x04, 0x8B, 0x44, 0x24,
            0x08, 0x41, 0x0F, 0x38, 0xF0, 0x54, 0x05, 0x08, 0x8B, 0x5C, 0x24, 0x7C, 0x8B, 0x6C, 0x24, 0x78,
            0x41, 0x0F, 0x38, 0xF1, 0x6C, 0x1D, 0x00, 0x41, 0x0F, 0x38, 0xF0, 0x74, 0x1D, 0x00, 0x89, 0x74,
            0x24, 0x30, 0xE9, 0x6A, 0x00, 0x00, 0x00, 0x83, 0xAC, 0x24, 0xB0, 0x02, 0x00, 0x00, 0x04, 0xBD,
            0x03, 0x00, 0x00, 0x00, 0x48, 0x89, 0xD6, 0x83, 0xC6, 0x10, 0x89, 0x74, 0x24, 0x10, 0x41, 0x0F,
            0x38, 0xF1, 0x6C, 0x15, 0x10, 0x89, 0x54, 0x24, 0x08, 0x89, 0x6C, 0x24, 0x78, 0xC7, 0x84, 0x24
        };

        // Sub-sequence for the mem->reg MOVBE we want (41 0F 38 F0 74 1D 00)
        static readonly byte[] MovbeMemToRegSeq = new byte[] { 0x41, 0x0F, 0x38, 0xF0, 0x74, 0x1D, 0x00 };

        static long FindMenuMovbeAddress()
        {
            try
            {
                LogMessage("Scanning for menu MOVBE instruction...");

                // Find offset of MOVBE within pattern
                int movbeOffset = -1;
                for (int i = 0; i <= MenuMovbeAob.Length - MovbeMemToRegSeq.Length; i++)
                {
                    bool match = true;
                    for (int j = 0; j < MovbeMemToRegSeq.Length; j++)
                    {
                        if (MenuMovbeAob[i + j] != MovbeMemToRegSeq[j])
                        {
                            match = false;
                            break;
                        }
                    }
                    if (match)
                    {
                        movbeOffset = i;
                        LogMessage($"MOVBE sequence found at offset {i} in pattern");
                        break;
                    }
                }

                if (movbeOffset < 0)
                {
                    LogMessage("ERROR: MOVBE sequence not found in AOB pattern");
                    return -1L;
                }

                IntPtr hProcess = MemAPI.OpenProcess(MemAPI.ProcessAccessFlags.All, false, mem.p.Id);
                if (hProcess == IntPtr.Zero)
                {
                    LogMessage("Could not open process for menu MOVBE search");
                    return -1L;
                }

                try
                {
                    long currentAddress = 0x10000;
                    long maxAddress = 0x7FFFFFFFFFFF;
                    int regionsScanned = 0;

                    while (currentAddress < maxAddress)
                    {
                        MemAPI.MEMORY_BASIC_INFORMATION mbi;
                        int result = MemAPI.VirtualQueryEx(hProcess, (IntPtr)currentAddress, out mbi, (uint)Marshal.SizeOf(typeof(MemAPI.MEMORY_BASIC_INFORMATION)));

                        if (result == 0)
                        {
                            currentAddress += 0x10000;
                            continue;
                        }

                        regionsScanned++;
                        if (regionsScanned > 5000) break;

                        bool isScannable = (mbi.State == MemAPI.StateEnum.MEM_COMMIT) &&
                                          (mbi.Protect == MemAPI.AllocationProtectEnum.PAGE_EXECUTE ||
                                           mbi.Protect == MemAPI.AllocationProtectEnum.PAGE_EXECUTE_READ ||
                                           mbi.Protect == MemAPI.AllocationProtectEnum.PAGE_EXECUTE_READWRITE);

                        if (isScannable)
                        {
                            long regionSize = (long)mbi.RegionSize;
                            long patternAddr = SearchPatternInRegionFast(currentAddress, regionSize, MenuMovbeAob, hProcess);
                            if (patternAddr >= 0)
                            {
                            long movbeAddr = patternAddr + movbeOffset;
                            LogMessage($"Found menu MOVBE at 0x{movbeAddr:X} (pattern at 0x{patternAddr:X} + offset {movbeOffset})");
                            
                            // Verify the bytes at the MOVBE address
                            byte[] verifyBytes = new byte[7];
                            int verifyRead = MemAPI.ReadBytes(movbeAddr, verifyBytes, 7, mem.p, hProcess);
                            if (verifyRead == 7)
                            {
                                LogMessage($"Verification: Bytes at MOVBE address: {BitConverter.ToString(verifyBytes)}");
                                if (verifyBytes[0] == 0x41 && verifyBytes[1] == 0x0F)
                                {
                                    LogMessage($"SUCCESS: Confirmed 41 0F instruction at 0x{movbeAddr:X}");
                                }
                                else
                                {
                                    LogMessage($"WARNING: Expected 41 0F but found {verifyBytes[0]:X2} {verifyBytes[1]:X2} at 0x{movbeAddr:X}");
                                }
                            }
                            
                            return movbeAddr;
                            }
                        }

                        currentAddress += (long)mbi.RegionSize;
                    }

                    LogMessage($"Menu MOVBE not found after scanning {regionsScanned} regions");
                    return -1L;
                }
                finally
                {
                    MemAPI.CloseHandle(hProcess);
                }
            }
            catch (Exception ex)
            {
                LogMessage($"Error in FindMenuMovbeAddress: {ex.Message}");
                return -1L;
            }
        }

        // Normal magnesis detection MOVBE pattern (for detecting when magnesis is active)
        static readonly byte[] MagnesisMovbeAob = new byte[]
        {
            0xF3, 0x89, 0x74, 0x24, 0x04, 0x83, 0xAC, 0x24, 0xB0, 0x02, 0x00, 0x00, 0x09, 0x66, 0x0F, 0x10,
            0x84, 0xE4, 0x88, 0x00, 0x00, 0x00, 0xF2, 0x44, 0x0F, 0x5A, 0xF8, 0x66, 0x45, 0x0F, 0x7E, 0xFE,
            0x45, 0x0F, 0x38, 0xF1, 0x74, 0x1D, 0x00,  // The X MOVBE instruction at offset 32
            0x45, 0x0F, 0x38, 0xF0, 0x74, 0x2D, 0x04, 0x66, 0x41, 0x0F, 0x6E, 0xC6, 0x66, 0x41, 0x0F, 0x7E, 0xC6,
            0x45, 0x0F, 0x38, 0xF1, 0x74, 0x1D, 0x04, 0xF3, 0x0F, 0x5A, 0xC0, 0xF2, 0x0F, 0x12, 0xC0,
            0x45, 0x0F, 0x38, 0xF0, 0x74, 0x2D, 0x08, 0x66, 0x41, 0x0F, 0x6E, 0xC6, 0x66, 0x41, 0x0F, 0x7E, 0xC6,
            0x45, 0x0F, 0x38, 0xF1, 0x74, 0x1D, 0x08, 0x89
        };

        // Experimental magnesis control MOVBE pattern (for mouse control override)
        // Pattern contains three MOVBE instructions at offsets that write X, Y, Z coordinates
        static readonly byte[] ExperimentalMagnesisMovbeAob = new byte[]
        {
            0x45, 0x0F, 0x38, 0xF1, 0x74, 0x2D, 0x68, 0xF3, 0x0F, 0x5A, 0xF6, 0xF2, 0x0F, 0x12, 0xF6, 0x66,
            0x44, 0x0F, 0x10, 0x84, 0xE4, 0x68, 0x02, 0x00, 0x00, 0x66, 0x41, 0x0F, 0x2E, 0xD0, 0x0F, 0x9A,
            0x84, 0x24, 0x8F, 0x02, 0x00, 0x00, 0x7A, 0x1A, 0x0F, 0x92, 0x84, 0x24, 0x8C, 0x02, 0x00, 0x00,
            0x0F, 0x97, 0x84, 0x24, 0x8D, 0x02, 0x00, 0x00, 0x0F, 0x94, 0x84, 0x24, 0x8E, 0x02, 0x00, 0x00,
            0xEB, 0x18, 0xC6, 0x84, 0x24, 0x8C, 0x02, 0x00, 0x00, 0x00, 0xC6, 0x84, 0x24, 0x8D, 0x02, 0x00,
            0x00, 0x00, 0xC6, 0x84, 0x24, 0x8E, 0x02, 0x00, 0x00, 0x00, 0x41, 0x89, 0x54, 0x1D, 0x70, 0x66,
            0x44, 0x0F, 0x10, 0x8C, 0xE4, 0x58, 0x01, 0x00, 0x00, 0x45, 0x0F, 0x38, 0xF0, 0x74, 0x1D, 0x70,
            0x66, 0x45, 0x0F, 0x6E, 0xCE, 0x66, 0x41, 0x0F, 0x7E, 0xFE, 0x45, 0x0F, 0x38, 0xF1, 0x74, 0x2D,
            0x6C, 0xF3, 0x0F, 0x5A, 0xFF, 0xF2, 0x0F, 0x12, 0xFF, 0x66, 0x45, 0x0F, 0x7E, 0xCE, 0x45, 0x0F,
            0x38, 0xF1, 0x74, 0x2D, 0x70
        };

        static (long x, long y, long z) FindExperimentalMagnesisMovbeAddresses()
        {
            try
            {
                LogMessage("Scanning for Experimental Magnesis MOVBE instructions (for mouse control override)...");
                LogMessage("WARNING: Experimental magnesis AOB pattern is placeholder - needs real pattern!");
                LogMessage($"Experimental AOB pattern: {BitConverter.ToString(ExperimentalMagnesisMovbeAob)}");
                LogMessage($"Pattern length: {ExperimentalMagnesisMovbeAob.Length} bytes");

                // TODO: This is a placeholder implementation
                // The actual AOB pattern for experimental magnesis control needs to be provided
                // This pattern should identify the MOVBE instructions that write the coordinates
                // we want to override for mouse control
                
                // Now search for the pattern using the actual implementation
                IntPtr hProcess = MemAPI.OpenProcess(MemAPI.ProcessAccessFlags.All, false, mem.p.Id);
                if (hProcess == IntPtr.Zero)
                {
                    LogMessage("Could not open process for experimental magnesis MOVBE search");
                    return (-1L, -1L, -1L);
                }

                try
                {
                    long currentAddress = 0x10000;
                    long maxAddress = 0x7FFFFFFFFFFF;
                    int regionsScanned = 0;

                    while (currentAddress < maxAddress)
                    {
                        MemAPI.MEMORY_BASIC_INFORMATION mbi;
                        int result = MemAPI.VirtualQueryEx(hProcess, (IntPtr)currentAddress, out mbi, (uint)Marshal.SizeOf(typeof(MemAPI.MEMORY_BASIC_INFORMATION)));

                        if (result == 0)
                        {
                            currentAddress += 0x10000;
                            continue;
                        }

                        regionsScanned++;
                        if (regionsScanned > 5000) break;

                        bool isScannable = (mbi.State == MemAPI.StateEnum.MEM_COMMIT) &&
                                          (mbi.Protect == MemAPI.AllocationProtectEnum.PAGE_EXECUTE ||
                                           mbi.Protect == MemAPI.AllocationProtectEnum.PAGE_EXECUTE_READ ||
                                           mbi.Protect == MemAPI.AllocationProtectEnum.PAGE_EXECUTE_READWRITE);

                        if (isScannable)
                        {
                            long regionSize = (long)mbi.RegionSize;
                            long patternAddr = SearchPatternInRegionFast(currentAddress, regionSize, ExperimentalMagnesisMovbeAob, hProcess);
                            if (patternAddr >= 0)
                            {
                                // Calculate addresses for X, Y, Z MOVBE instructions based on pattern structure
                                // Analyzing the pattern to find exact offsets:
                                // First MOVBE (X): 45 0F 38 F1 74 2D 68 - at pattern start (offset 0)
                                // Second MOVBE (Y): 45 0F 38 F1 74 2D 6C - at offset 120 in pattern
                                // Third MOVBE (Z): 45 0F 38 F1 74 2D 70 - at offset 136 in pattern
                                
                                // Let's find the offsets by searching within the pattern
                                int yOffset = -1, zOffset = -1;
                                for (int i = 1; i < ExperimentalMagnesisMovbeAob.Length - 6; i++)
                                {
                                    if (ExperimentalMagnesisMovbeAob[i] == 0x45 && ExperimentalMagnesisMovbeAob[i+1] == 0x0F && 
                                        ExperimentalMagnesisMovbeAob[i+2] == 0x38 && ExperimentalMagnesisMovbeAob[i+3] == 0xF1 &&
                                        ExperimentalMagnesisMovbeAob[i+4] == 0x74 && ExperimentalMagnesisMovbeAob[i+5] == 0x2D)
                                    {
                                        if (ExperimentalMagnesisMovbeAob[i+6] == 0x6C && yOffset == -1) {
                                            yOffset = i; // Second MOVBE (Y)
                                        }
                                        else if (ExperimentalMagnesisMovbeAob[i+6] == 0x70 && zOffset == -1) {
                                            zOffset = i; // Third MOVBE (Z)
                                        }
                                    }
                                }
                                
                                long xMovbeAddr = patternAddr + 0;           // First MOVBE at pattern start
                                long yMovbeAddr = patternAddr + (yOffset >= 0 ? yOffset : 120); // Second MOVBE
                                long zMovbeAddr = patternAddr + (zOffset >= 0 ? zOffset : 136); // Third MOVBE
                                
                                LogMessage($"SUCCESS: Found Experimental Magnesis MOVBE pattern at 0x{patternAddr:X}");
                                LogMessage($"Calculated offsets - Y: {(yOffset >= 0 ? yOffset.ToString() : "fallback 120")}, Z: {(zOffset >= 0 ? zOffset.ToString() : "fallback 136")}");
                                LogMessage($"Experimental X MOVBE at: 0x{xMovbeAddr:X} (offset +0)");
                                LogMessage($"Experimental Y MOVBE at: 0x{yMovbeAddr:X} (offset +{(yOffset >= 0 ? yOffset : 120)})");
                                LogMessage($"Experimental Z MOVBE at: 0x{zMovbeAddr:X} (offset +{(zOffset >= 0 ? zOffset : 136)})");
                                
                                // Verify the MOVBE instructions
                                byte[] xVerifyBytes = new byte[7];
                                byte[] yVerifyBytes = new byte[7];
                                byte[] zVerifyBytes = new byte[7];
                                
                                int xRead = MemAPI.ReadBytes(xMovbeAddr, xVerifyBytes, 7, mem.p, hProcess);
                                int yRead = MemAPI.ReadBytes(yMovbeAddr, yVerifyBytes, 7, mem.p, hProcess);
                                int zRead = MemAPI.ReadBytes(zMovbeAddr, zVerifyBytes, 7, mem.p, hProcess);
                                
                                if (xRead == 7 && yRead == 7 && zRead == 7)
                                {
                                    LogMessage($"X MOVBE verification: {BitConverter.ToString(xVerifyBytes)}");
                                    LogMessage($"Y MOVBE verification: {BitConverter.ToString(yVerifyBytes)}");
                                    LogMessage($"Z MOVBE verification: {BitConverter.ToString(zVerifyBytes)}");
                                    
                                    // Check if they match expected MOVBE pattern
                                    bool xValid = xVerifyBytes[0] == 0x45 && xVerifyBytes[1] == 0x0F && xVerifyBytes[2] == 0x38 && xVerifyBytes[3] == 0xF1;
                                    bool yValid = yVerifyBytes[0] == 0x45 && yVerifyBytes[1] == 0x0F && yVerifyBytes[2] == 0x38 && yVerifyBytes[3] == 0xF1;
                                    bool zValid = zVerifyBytes[0] == 0x45 && zVerifyBytes[1] == 0x0F && zVerifyBytes[2] == 0x38 && zVerifyBytes[3] == 0xF1;
                                    
                                    if (xValid && yValid && zValid)
                                    {
                                        LogMessage($"SUCCESS: All three experimental MOVBE instructions verified!");
                                        return (xMovbeAddr, yMovbeAddr, zMovbeAddr);
                                    }
                                    else
                                    {
                                        LogMessage($"WARNING: Experimental MOVBE verification failed - X:{xValid}, Y:{yValid}, Z:{zValid}");
                                    }
                                }
                                
                                return (xMovbeAddr, yMovbeAddr, zMovbeAddr);
                            }
                        }

                        currentAddress += (long)mbi.RegionSize;
                    }

                    LogMessage($"Experimental Magnesis MOVBE not found after scanning {regionsScanned} regions");
                    return (-1L, -1L, -1L);
                }
                finally
                {
                    MemAPI.CloseHandle(hProcess);
                }
            }
            catch (Exception ex)
            {
                LogMessage($"Error in FindExperimentalMagnesisMovbeAddresses: {ex.Message}");
                return (-1L, -1L, -1L);
            }
        }

        static long FindMagnesisMovbeAddress()
        {
            try
            {
                LogMessage("Scanning for Magnesis X MOVBE instruction...");
                LogMessage($"Magnesis AOB pattern: {BitConverter.ToString(MagnesisMovbeAob)}");
                LogMessage($"Pattern length: {MagnesisMovbeAob.Length} bytes");

                // Use same approach as menu MOVBE - scan executable regions
                IntPtr hProcess = MemAPI.OpenProcess(MemAPI.ProcessAccessFlags.All, false, mem.p.Id);
                if (hProcess == IntPtr.Zero)
                {
                    LogMessage("Could not open process for magnesis MOVBE search");
                    return -1L;
                }

                try
                {
                    long currentAddress = 0x10000;
                    long maxAddress = 0x7FFFFFFFFFFF;
                    int regionsScanned = 0;

                    while (currentAddress < maxAddress)
                    {
                        MemAPI.MEMORY_BASIC_INFORMATION mbi;
                        int result = MemAPI.VirtualQueryEx(hProcess, (IntPtr)currentAddress, out mbi, (uint)Marshal.SizeOf(typeof(MemAPI.MEMORY_BASIC_INFORMATION)));

                        if (result == 0)
                        {
                            currentAddress += 0x10000;
                            continue;
                        }

                        regionsScanned++;
                        if (regionsScanned > 5000) break;

                        bool isScannable = (mbi.State == MemAPI.StateEnum.MEM_COMMIT) &&
                                          (mbi.Protect == MemAPI.AllocationProtectEnum.PAGE_EXECUTE ||
                                           mbi.Protect == MemAPI.AllocationProtectEnum.PAGE_EXECUTE_READ ||
                                           mbi.Protect == MemAPI.AllocationProtectEnum.PAGE_EXECUTE_READWRITE);

                        if (isScannable)
                        {
                            long regionSize = (long)mbi.RegionSize;
                            long patternAddr = SearchPatternInRegionFast(currentAddress, regionSize, MagnesisMovbeAob, hProcess);
                            if (patternAddr >= 0)
                            {
                                // All three MOVBE instructions from the same pattern
                                long xMovbeAddr = patternAddr + 32;  // X coordinate at offset 32
                                long yMovbeAddr = patternAddr + 56;  // Y coordinate at offset 56
                                long zMovbeAddr = patternAddr + 88;  // Z coordinate at offset 88
                                
                                LogMessage($"SUCCESS: Found Magnesis MOVBE pattern at 0x{patternAddr:X}");
                                LogMessage($"X MOVBE instruction at: 0x{xMovbeAddr:X} (offset +32)");
                                LogMessage($"Y MOVBE instruction at: 0x{yMovbeAddr:X} (offset +56)");
                                LogMessage($"Z MOVBE instruction at: 0x{zMovbeAddr:X} (offset +88)");
                                
                                // Verify all three MOVBE instructions
                                byte[] xVerifyBytes = new byte[7];
                                byte[] yVerifyBytes = new byte[7];
                                byte[] zVerifyBytes = new byte[7];
                                
                                int xRead = MemAPI.ReadBytes(xMovbeAddr, xVerifyBytes, 7, mem.p, hProcess);
                                int yRead = MemAPI.ReadBytes(yMovbeAddr, yVerifyBytes, 7, mem.p, hProcess);
                                int zRead = MemAPI.ReadBytes(zMovbeAddr, zVerifyBytes, 7, mem.p, hProcess);
                                
                                if (xRead == 7 && yRead == 7 && zRead == 7)
                                {
                                    LogMessage($"X MOVBE verification: {BitConverter.ToString(xVerifyBytes)}");
                                    LogMessage($"Y MOVBE verification: {BitConverter.ToString(yVerifyBytes)}");
                                    LogMessage($"Z MOVBE verification: {BitConverter.ToString(zVerifyBytes)}");
                                    
                                    bool xValid = xVerifyBytes[0] == 0x45 && xVerifyBytes[1] == 0x0F;
                                    bool yValid = yVerifyBytes[0] == 0x45 && yVerifyBytes[1] == 0x0F;
                                    bool zValid = zVerifyBytes[0] == 0x45 && zVerifyBytes[1] == 0x0F;
                                    
                                    if (xValid && yValid && zValid)
                                    {
                                        LogMessage($"SUCCESS: All three MOVBE instructions verified!");
                                        
                                        // Update shared memory with all three addresses
                                        var data = new SharedPositionData();
                                        accessor.Read(0, out data);
                                        
                                        // Set all three magnesis MOVBE addresses
                                        data.magnesis_instruction_address = (ulong)xMovbeAddr;  // X coordinate
                                        data.magnesis_instruction_valid = 1;
                                        data.magnesis_y_instruction_address = (ulong)yMovbeAddr; // Y coordinate
                                        data.magnesis_y_instruction_valid = 1;
                                        data.magnesis_z_instruction_address = (ulong)zMovbeAddr; // Z coordinate
                                        data.magnesis_z_instruction_valid = 1;
                                        
                                        accessor.Write(0, ref data);
                                        LogMessage($"All three Magnesis MOVBE addresses sent to Rust DLL:");
                                        LogMessage($"  X: 0x{xMovbeAddr:X}");
                                        LogMessage($"  Y: 0x{yMovbeAddr:X}");
                                        LogMessage($"  Z: 0x{zMovbeAddr:X}");
                                        
                                        return xMovbeAddr;  // Return X address for now
                                    }
                                    else
                                    {
                                        LogMessage($"WARNING: MOVBE verification failed - X:{xValid}, Y:{yValid}, Z:{zValid}");
                                    }
                                }
                                
                                return xMovbeAddr;  // Return X address even if verification fails
                            }
                        }

                        currentAddress += (long)mbi.RegionSize;
                    }

                    LogMessage($"Magnesis MOVBE not found after scanning {regionsScanned} regions");
                    return -1L;
                }
                finally
                {
                    MemAPI.CloseHandle(hProcess);
                }
            }
            catch (Exception ex)
            {
                LogMessage($"Error in FindMagnesisMovbeAddress: {ex.Message}");
                return -1L;
            }
        }

        // Helper function to convert byte array to int array for MemAPI
        static int[] ConvertToIntArray(byte[] bytes)
        {
            int[] result = new int[bytes.Length];
            for (int i = 0; i < bytes.Length; i++)
            {
                result[i] = bytes[i];
            }
            return result;
        }

        static long FindPlayerStateAddress()
        {
            try
            {
                LogMessage("=== STARTING FAST PLAYER STATE SEARCH (CHEAT ENGINE STYLE) ===");
                LogMessage("Starting comprehensive player state address search...");

                // AOB pattern for player state detection: Longer, more unique 76-byte pattern
                byte[] playerStatePattern = new byte[]
                {
                    0x18, 0x83, 0xF8, 0x00, 0x0F, 0x9C, 0x84, 0x24, 0x8C, 0x02, 0x00, 0x00, 0x0F, 0x9F, 0x84, 0x24,
                    0x8D, 0x02, 0x00, 0x00, 0x0F, 0x94, 0x84, 0x24, 0x8E, 0x02, 0x00, 0x00, 0x8B, 0x54, 0x24, 0x10,
                    0x41, 0x0F, 0xB6, 0x84, 0x15, 0x70, 0x07, 0x00, 0x00,  // movzx eax, byte ptr [r13+rdx+770h] <- TARGET
                    0x74, 0x2D, 0x0F, 0x1F, 0x40, 0x00, 0x83, 0xAC, 0x24, 0xB0, 0x02, 0x00, 0x00, 0x03, 0x8B, 0x5C,
                    0x24, 0x14, 0x09, 0xD8, 0x41, 0x88, 0x84, 0x15, 0x70, 0x07, 0x00, 0x00, 0x89, 0x44, 0x24, 0x04,
                    0x8B, 0x94, 0x24, 0xB8, 0x02, 0x00, 0x00
                };

                LogMessage($"Player state pattern: {BitConverter.ToString(playerStatePattern)}");
                LogMessage($"Pattern length: {playerStatePattern.Length} bytes");
                LogMessage($"Scanning ALL memory regions (like Cheat Engine) - not just executable...");

                IntPtr hProcess = MemAPI.OpenProcess(MemAPI.ProcessAccessFlags.All, false, mem.p.Id);
                if (hProcess == IntPtr.Zero)
                {
                    LogMessage("FAILED: Could not open process for player state search");
                    return -1L;
                }

                LogMessage("Process opened successfully for player state search");

                try
                {
                    // Search ALL memory regions comprehensively (like Cheat Engine)
                    long currentAddress = 0x10000; // Start from 64KB
                    long maxAddress = 0x7FFFFFFFFFFF; // Maximum user-mode address
                    int regionsScanned = 0;
                    int scannableRegionsFound = 0;
                    long totalBytesScanned = 0;

                    LogMessage("Starting comprehensive memory region enumeration...");

                    while (currentAddress < maxAddress)
                    {
                        MemAPI.MEMORY_BASIC_INFORMATION mbi;
                        int result = MemAPI.VirtualQueryEx(hProcess, (IntPtr)currentAddress, out mbi, (uint)Marshal.SizeOf(typeof(MemAPI.MEMORY_BASIC_INFORMATION)));

                        if (result == 0)
                        {
                            currentAddress += 0x10000; // Skip 64KB
                            continue;
                        }

                        regionsScanned++;

                        // Log first few regions for debugging
                        if (regionsScanned <= 10)
                        {
                            LogMessage($"Region #{regionsScanned}: 0x{currentAddress:X} size={mbi.RegionSize} protect={mbi.Protect} state={mbi.State}");
                        }

                        // Scan ONLY executable regions (same as MOVBE for maximum speed)
                        bool isScannable = (mbi.State == MemAPI.StateEnum.MEM_COMMIT) &&
                                          (mbi.Protect == MemAPI.AllocationProtectEnum.PAGE_EXECUTE ||
                                           mbi.Protect == MemAPI.AllocationProtectEnum.PAGE_EXECUTE_READ ||
                                           mbi.Protect == MemAPI.AllocationProtectEnum.PAGE_EXECUTE_READWRITE);

                        if (isScannable)
                        {
                            scannableRegionsFound++;
                            long regionSize = (long)mbi.RegionSize;
                            totalBytesScanned += regionSize;

                            if (scannableRegionsFound <= 10) // Log first 10 scannable regions
                            {
                                string protectStr = mbi.Protect.ToString();
                                LogMessage($"SCANNABLE region #{scannableRegionsFound}: 0x{currentAddress:X} size={regionSize / 1024}KB protect={protectStr}");
                            }

                            long patternAddr = SearchPatternInRegionFast(currentAddress, regionSize, playerStatePattern, hProcess);
                            if (patternAddr >= 0)
                            {
                                LogMessage($"SUCCESS: Found player state AOB pattern at 0x{patternAddr:X}");
                                LogMessage($"Total regions scanned: {regionsScanned}");
                                LogMessage($"Scannable regions found: {scannableRegionsFound}");
                                LogMessage($"Total bytes scanned: {totalBytesScanned / 1024 / 1024} MB");

                                // NEW: Just return the pattern address - Rust DLL will handle the calculation
                                LogMessage("Returning pattern address to main loop for Rust DLL processing");
                                return patternAddr;
                            }
                        }

                        currentAddress += (long)mbi.RegionSize;

                        // Increased safety limit for thorough scanning
                        if (regionsScanned > 5000)
                        {
                            LogMessage($"Reached scan limit of 5000 regions, stopping search");
                            LogMessage($"Total scannable regions found: {scannableRegionsFound}");
                            break;
                        }
                    }

                    LogMessage($"Player state AOB pattern not found after scanning {regionsScanned} regions ({scannableRegionsFound} scannable, {totalBytesScanned / 1024 / 1024} MB)");
                }
                finally
                {
                    MemAPI.CloseHandle(hProcess);
                }

                return -1L;
            }
            catch (Exception ex)
            {
                LogMessage($"Error in FindPlayerStateAddress: {ex.Message}");
                return -1L;
            }
        }

        static long SearchPatternInRegion(long baseAddress, long regionSize, byte[] pattern, IntPtr hProcess)
        {
            try
            {
                int chunkSize = (int)Math.Min(regionSize, 0x1000000); // Max 16MB chunks
                byte[] regionData = new byte[chunkSize];

                int bytesRead = MemAPI.ReadBytes(baseAddress, regionData, chunkSize, mem.p, hProcess);
                if (bytesRead == 0) return -1L;

                for (int i = 0; i <= bytesRead - pattern.Length; i++)
                {
                    bool found = true;
                    for (int j = 0; j < pattern.Length; j++)
                    {
                        if (regionData[i + j] != pattern[j])
                        {
                            found = false;
                            break;
                        }
                    }
                    if (found)
                    {
                        return baseAddress + i;
                    }
                }
                return -1L;
            }
            catch
            {
                return -1L;
            }
        }

        // New: paged scanner across an entire region with overlap (safe memory usage)
        static long SearchPatternAcrossRegionPaged(long baseAddress, long regionSize, byte[] pattern, IntPtr hProcess)
        {
            try
            {
                const int chunkSize = 4 * 1024 * 1024; // 4MB
                byte[] buffer = new byte[chunkSize];
                long end = baseAddress + regionSize;
                long step = chunkSize - pattern.Length;
                if (step <= 0) step = chunkSize / 2;

                for (long addr = baseAddress; addr < end; addr += step)
                {
                    int toRead = (int)Math.Min(chunkSize, end - addr);
                    int read = MemAPI.ReadBytes(addr, buffer, toRead, mem.p, hProcess);
                    if (read <= 0) continue;

                    for (int i = 0; i <= read - pattern.Length; i++)
                    {
                        bool found = true;
                        for (int j = 0; j < pattern.Length; j++)
                        {
                            if (buffer[i + j] != pattern[j]) { found = false; break; }
                        }
                        if (found)
                        {
                            return addr + i;
                        }
                    }
                }

                return -1L;
            }
            catch (Exception ex)
            {
                LogMessage($"Error in SearchPatternAcrossRegionPaged: {ex}");
                return -1L;
            }
        }

        static long SearchPatternInRegionFast(long baseAddress, long regionSize, byte[] pattern, IntPtr hProcess)
        {
            try
            {
                // Fast scanning without chunk limitations - scan entire region at once if possible
                int maxChunkSize = (int)Math.Min(regionSize, 0x10000000); // Max 256MB chunks (increased)
                byte[] regionData = new byte[maxChunkSize];

                int bytesRead = MemAPI.ReadBytes(baseAddress, regionData, maxChunkSize, mem.p, hProcess);
                if (bytesRead == 0) return -1L;

                // Use optimized pattern matching
                for (int i = 0; i <= bytesRead - pattern.Length; i++)
                {
                    // Quick first byte check before full pattern match
                    if (regionData[i] == pattern[0])
                    {
                        bool found = true;
                        for (int j = 1; j < pattern.Length; j++)
                        {
                            if (regionData[i + j] != pattern[j])
                            {
                                found = false;
                                break;
                            }
                        }
                        if (found)
                        {
                            return baseAddress + i;
                        }
                    }
                }
                return -1L;
            }
            catch
            {
                return -1L;
            }
        }

        static long CalculatePlayerStateDataAddress()
        {
            try
            {
                LogMessage("Starting one-time player state data address calculation...");

                IntPtr hProcess = MemAPI.OpenProcess(MemAPI.ProcessAccessFlags.All, false, mem.p.Id);
                if (hProcess == IntPtr.Zero) return -1;

                try
                {
                    // Analyze the code around the AOB pattern to find r13 and rdx values
                    long calculatedAddress = AnalyzePlayerStateInstruction(playerStatePatternAddress, hProcess);

                    if (calculatedAddress > 0)
                    {
                        LogMessage($"Successfully calculated player state data address: 0x{calculatedAddress:X}");
                        return calculatedAddress;
                    }
                    else
                    {
                        LogMessage("Could not calculate player state data address from instruction analysis");
                        return -1;
                    }
                }
                finally
                {
                    MemAPI.CloseHandle(hProcess);
                }
            }
            catch (Exception ex)
            {
                LogMessage($"Error in CalculatePlayerStateDataAddress: {ex.Message}");
                return -1;
            }
        }

        static long CalculatePlayerStateDataAddressFast(long patternAddress, IntPtr hProcess)
        {
            try
            {
                LogMessage($"=== TARGETED PLAYER STATE SEARCH ===");
                LogMessage($"movzx instruction at: 0x{patternAddress + 4:X}");
                LogMessage($"Known: rdx = 0x44E54200 (constant), r13 changes per session");
                LogMessage($"Searching for the single address that movzx constantly accesses");

                // Since rdx is constant (0x44E54200) but r13 changes, we need to find
                // the actual address by searching for player state behavior patterns

                // The movzx instruction constantly accesses [r13 + 0x44E54200 + 0x770]
                // We need to find this final calculated address directly

                return DirectPlayerStateSearch(hProcess);
            }
            catch (Exception ex)
            {
                LogMessage($"Error in CalculatePlayerStateDataAddressFast: {ex.Message}");
                return -1;
            }
        }

        static long FindR13ValueDirect(long movzxAddress, IntPtr hProcess)
        {
            try
            {
                LogMessage($"=== FINDING R13 VALUE DIRECTLY ===");

                // Read a large context around the instruction to find r13 setup
                int contextSize = 16384; // 16KB context
                long contextStart = movzxAddress - 8192; // Start 8KB before
                byte[] contextBuffer = new byte[contextSize];

                int bytesRead = MemAPI.ReadBytes(contextStart, contextBuffer, contextSize, mem.p, hProcess);
                if (bytesRead == 0)
                {
                    LogMessage("Failed to read instruction context");
                    return -1;
                }

                LogMessage($"Read {bytesRead} bytes of context for r13 analysis");

                // Look for lea r13, [rip+offset] instructions (4C 8B 2D xx xx xx xx)
                for (int i = 0; i < bytesRead - 7; i++)
                {
                    if (contextBuffer[i] == 0x4C && contextBuffer[i + 1] == 0x8B && contextBuffer[i + 2] == 0x2D)
                    {
                        // Found lea r13, [rip+offset]
                        int ripOffset = BitConverter.ToInt32(contextBuffer, i + 3);
                        long instructionAddress = contextStart + i + 7; // Address after the 7-byte instruction
                        long targetAddress = instructionAddress + ripOffset;

                        LogMessage($"Found lea r13, [rip+0x{ripOffset:X}] at 0x{contextStart + i:X}");
                        LogMessage($"Target address: 0x{targetAddress:X}");

                        // Read the pointer at the target address
                        byte[] ptrBuffer = new byte[8];
                        int ptrBytesRead = MemAPI.ReadBytes(targetAddress, ptrBuffer, 8, mem.p, hProcess);

                        if (ptrBytesRead == 8)
                        {
                            long r13Value = BitConverter.ToInt64(ptrBuffer, 0);
                            if (r13Value > 0x10000 && r13Value < 0x7FFFFFFFFFFF)
                            {
                                LogMessage($"Found potential r13 value: 0x{r13Value:X}");
                                return r13Value;
                            }
                        }
                    }
                }

                // Look for mov r13, [absolute_address] (4C 8B 2C 25 xx xx xx xx)
                for (int i = 0; i < bytesRead - 8; i++)
                {
                    if (contextBuffer[i] == 0x4C && contextBuffer[i + 1] == 0x8B &&
                        contextBuffer[i + 2] == 0x2C && contextBuffer[i + 3] == 0x25)
                    {
                        uint absoluteAddress = BitConverter.ToUInt32(contextBuffer, i + 4);

                        LogMessage($"Found mov r13, [0x{absoluteAddress:X}] at 0x{contextStart + i:X}");

                        byte[] ptrBuffer = new byte[8];
                        int ptrBytesRead = MemAPI.ReadBytes(absoluteAddress, ptrBuffer, 8, mem.p, hProcess);

                        if (ptrBytesRead == 8)
                        {
                            long r13Value = BitConverter.ToInt64(ptrBuffer, 0);
                            if (r13Value > 0x10000 && r13Value < 0x7FFFFFFFFFFF)
                            {
                                LogMessage($"Found potential r13 value: 0x{r13Value:X}");
                                return r13Value;
                            }
                        }
                    }
                }

                LogMessage("No r13 setup instructions found in context");
                return -1;
            }
            catch (Exception ex)
            {
                LogMessage($"Error finding r13 value: {ex.Message}");
                return -1;
            }
        }

        static long PatchAndCaptureAddress(long movzxAddress, IntPtr hProcess)
        {
            try
            {
                LogMessage($"=== PATCHING MOVZX INSTRUCTION FOR ADDRESS CAPTURE ===");
                LogMessage($"Target instruction at: 0x{movzxAddress:X}");

                // Read the original instruction bytes
                byte[] originalBytes = new byte[9]; // movzx instruction is 9 bytes
                int bytesRead = MemAPI.ReadBytes(movzxAddress, originalBytes, 9, mem.p, hProcess);

                if (bytesRead != 9)
                {
                    LogMessage("Failed to read original movzx instruction");
                    return -1;
                }

                LogMessage($"Original instruction: {BitConverter.ToString(originalBytes)}");

                // Create a simple hook: replace with INT3 (0xCC) to cause breakpoint
                // When the breakpoint hits, we can read the registers
                byte[] patchBytes = new byte[] { 0xCC }; // INT3 breakpoint

                // Change memory protection to allow writing
                uint oldProtect;
                bool protectResult = MemAPI.VirtualProtectEx(hProcess, (IntPtr)movzxAddress, (UIntPtr)1, 0x40, out oldProtect); // PAGE_EXECUTE_READWRITE

                if (!protectResult)
                {
                    LogMessage("Failed to change memory protection for patching");
                    return -1;
                }

                // Write the patch
                int bytesWritten = 0;
                bool writeResult = MemAPI.WriteProcessMemory(hProcess, movzxAddress, patchBytes, 1, ref bytesWritten);

                if (!writeResult || bytesWritten != 1)
                {
                    LogMessage("Failed to write patch bytes");
                    // Restore original protection
                    MemAPI.VirtualProtectEx(hProcess, (IntPtr)movzxAddress, (UIntPtr)1, oldProtect, out _);
                    return -1;
                }

                LogMessage("Instruction patched successfully, waiting for execution...");

                // Wait a short time for the instruction to be hit
                System.Threading.Thread.Sleep(100);

                // For now, let's try a different approach - monitor memory writes
                // Restore the original instruction
                MemAPI.WriteProcessMemory(hProcess, movzxAddress, originalBytes, 9, ref bytesWritten);
                MemAPI.VirtualProtectEx(hProcess, (IntPtr)movzxAddress, (UIntPtr)1, oldProtect, out _);

                LogMessage("Instruction patching approach needs refinement, falling back...");
                return -1;
            }
            catch (Exception ex)
            {
                LogMessage($"Error in PatchAndCaptureAddress: {ex.Message}");
                return -1;
            }
        }

        static long HardwareBreakpointCapture(long movzxAddress, IntPtr hProcess)
        {
            try
            {
                LogMessage($"=== MEMORY ACCESS PATTERN ANALYSIS ===");
                LogMessage($"Since movzx constantly executes, analyzing memory access patterns");

                // Alternative approach: Since the instruction constantly executes,
                // we can analyze which memory locations are being frequently accessed
                // in a pattern consistent with player state reads

                // Look for memory locations that:
                // 1. Are being read frequently (like every frame)
                // 2. Contain values 0, 1, or 3
                // 3. Are in reasonable memory regions

                return AnalyzeFrequentMemoryAccess(movzxAddress, hProcess);
            }
            catch (Exception ex)
            {
                LogMessage($"Error in HardwareBreakpointCapture: {ex.Message}");
                return -1;
            }
        }

        static long AnalyzeFrequentMemoryAccess(long movzxAddress, IntPtr hProcess)
        {
            try
            {
                LogMessage("=== ANALYZING FREQUENT MEMORY ACCESS PATTERNS ===");

                // Since we can't easily hook the instruction, let's use a smarter approach:
                // The movzx instruction accesses [r13+rdx+770h] constantly
                // We can search for memory locations that behave like they're being constantly read

                // Strategy: Look for addresses that contain valid player state values
                // and are in memory regions that would be accessed by game code

                Dictionary<long, List<uint>> addressHistory = new Dictionary<long, List<uint>>();

                // Sample multiple memory regions over time
                for (int sample = 0; sample < 10; sample++)
                {
                    // Search in a reasonable range around the instruction
                    long searchStart = movzxAddress - 0x10000000; // -256MB
                    long searchEnd = movzxAddress + 0x10000000;   // +256MB

                    for (long addr = searchStart; addr < searchEnd; addr += 0x1000) // Every 4KB
                    {
                        try
                        {
                            byte[] buffer = new byte[4];
                            int bytesRead = MemAPI.ReadBytes(addr, buffer, 4, mem.p, hProcess);

                            if (bytesRead == 4)
                            {
                                uint value = BitConverter.ToUInt32(buffer, 0);

                                // Only track addresses with valid player state values
                                if (value <= 3)
                                {
                                    if (!addressHistory.ContainsKey(addr))
                                        addressHistory[addr] = new List<uint>();

                                    addressHistory[addr].Add(value);
                                }
                            }
                        }
                        catch
                        {
                            continue;
                        }
                    }

                    LogMessage($"Sample {sample + 1}/10 completed, tracking {addressHistory.Count} addresses");
                    System.Threading.Thread.Sleep(50); // Wait between samples
                }

                // Analyze the collected data
                var candidates = addressHistory
                    .Where(kvp => kvp.Value.Count >= 5) // Address was readable in multiple samples
                    .Where(kvp => kvp.Value.All(v => v <= 3)) // All values are valid player states
                    .OrderByDescending(kvp => kvp.Value.Count) // Prefer addresses found in more samples
                    .Take(10)
                    .ToList();

                LogMessage($"Found {candidates.Count} candidate addresses");

                foreach (var candidate in candidates)
                {
                    var values = candidate.Value.Distinct().ToList();
                    LogMessage($"Candidate 0x{candidate.Key:X}: values [{string.Join(", ", values)}] (found {candidate.Value.Count} times)");

                    // Return the first good candidate
                    if (values.Count <= 3 && values.All(v => v <= 3))
                    {
                        LogMessage($"Selected candidate: 0x{candidate.Key:X}");
                        return candidate.Key;
                    }
                }

                return -1;
            }
            catch (Exception ex)
            {
                LogMessage($"Error analyzing frequent memory access: {ex.Message}");
                return -1;
            }
        }

        static long AnalyzeMemoryRegionsForPlayerState(long patternAddress, IntPtr hProcess)
        {
            try
            {
                LogMessage("=== ANALYZING MEMORY REGIONS FOR PLAYER STATE ===");

                List<long> candidates = new List<long>();
                long currentAddress = 0x10000;
                long maxAddress = 0x7FFFFFFFFFFF;
                int regionsAnalyzed = 0;

                while (currentAddress < maxAddress && regionsAnalyzed < 1000)
                {
                    MemAPI.MEMORY_BASIC_INFORMATION mbi;
                    int result = MemAPI.VirtualQueryEx(hProcess, (IntPtr)currentAddress, out mbi, (uint)Marshal.SizeOf(typeof(MemAPI.MEMORY_BASIC_INFORMATION)));

                    if (result == 0)
                    {
                        currentAddress += 0x10000;
                        continue;
                    }

                    regionsAnalyzed++;

                    // Focus on data regions (readable/writable, committed)
                    if (mbi.State == MemAPI.StateEnum.MEM_COMMIT &&
                        mbi.Protect == MemAPI.AllocationProtectEnum.PAGE_READWRITE)
                    {
                        long regionSize = (long)mbi.RegionSize;

                        // Skip very small regions and very large regions
                        if (regionSize >= 0x1000 && regionSize <= 0x10000000) // 4KB to 256MB
                        {
                            LogMessage($"Scanning data region: 0x{currentAddress:X} size={regionSize / 1024}KB");

                            // Scan this region for player state candidates
                            var regionCandidates = ScanRegionForPlayerState(currentAddress, regionSize, hProcess);
                            candidates.AddRange(regionCandidates);

                            // If we found some candidates, validate them
                            if (candidates.Count > 0)
                            {
                                var validatedAddress = ValidateBestCandidate(candidates, hProcess);
                                if (validatedAddress > 0)
                                {
                                    return validatedAddress;
                                }
                            }
                        }
                    }

                    currentAddress += (long)mbi.RegionSize;
                }

                LogMessage($"Analyzed {regionsAnalyzed} memory regions, found {candidates.Count} candidates");

                // Final validation of all candidates
                if (candidates.Count > 0)
                {
                    return ValidateBestCandidate(candidates, hProcess);
                }

                return -1;
            }
            catch (Exception ex)
            {
                LogMessage($"Error analyzing memory regions: {ex.Message}");
                return -1;
            }
        }

        static long DirectPlayerStateSearch(IntPtr hProcess)
        {
            try
            {
                LogMessage($"=== DIRECT PLAYER STATE ADDRESS SEARCH ===");
                LogMessage($"Searching for addresses containing player state values (0, 1, 3)");

                List<long> candidates = new List<long>();

                // Search in focused memory ranges where game data is typically located
                List<(long start, long size, string description)> searchRanges = new List<(long, long, string)>
                {
                    (0x100000000, 0x100000000, "Low range (4GB-8GB)"),      // 4GB to 8GB
                    (0x200000000, 0x100000000, "Mid range (8GB-12GB)"),     // 8GB to 12GB
                    (0x300000000, 0x100000000, "High range (12GB-16GB)")    // 12GB to 16GB
                };

                foreach (var (start, size, description) in searchRanges)
                {
                    LogMessage($"Searching {description}: 0x{start:X} to 0x{start + size:X}");

                    var rangeCandidates = SearchRangeForPlayerState(start, size, hProcess);
                    candidates.AddRange(rangeCandidates);

                    LogMessage($"Found {rangeCandidates.Count} candidates in {description}");

                    // If we found good candidates, validate them immediately
                    if (rangeCandidates.Count > 0)
                    {
                        var validatedAddress = ValidatePlayerStateCandidates(rangeCandidates, hProcess);
                        if (validatedAddress > 0)
                        {
                            LogMessage($"SUCCESS: Found validated player state address: 0x{validatedAddress:X}");
                            return validatedAddress;
                        }
                    }
                }

                LogMessage($"Total candidates found: {candidates.Count}");

                // Final validation of all candidates if none were found in individual ranges
                if (candidates.Count > 0)
                {
                    return ValidatePlayerStateCandidates(candidates, hProcess);
                }

                LogMessage("No valid player state address found");
                return -1;
            }
            catch (Exception ex)
            {
                LogMessage($"Error in DirectPlayerStateSearch: {ex.Message}");
                return -1;
            }
        }

        static List<long> SearchRangeForPlayerState(long start, long size, IntPtr hProcess)
        {
            List<long> candidates = new List<long>();

            try
            {
                long currentAddress = start;
                long endAddress = start + size;

                while (currentAddress < endAddress)
                {
                    MemAPI.MEMORY_BASIC_INFORMATION mbi;
                    int result = MemAPI.VirtualQueryEx(hProcess, (IntPtr)currentAddress, out mbi, (uint)Marshal.SizeOf(typeof(MemAPI.MEMORY_BASIC_INFORMATION)));

                    if (result == 0)
                    {
                        currentAddress += 0x10000;
                        continue;
                    }

                    // Focus on readable/writable committed memory
                    if (mbi.State == MemAPI.StateEnum.MEM_COMMIT &&
                        (mbi.Protect == MemAPI.AllocationProtectEnum.PAGE_READWRITE ||
                         mbi.Protect == MemAPI.AllocationProtectEnum.PAGE_READONLY))
                    {
                        long regionSize = Math.Min((long)mbi.RegionSize, 0x1000000); // Max 16MB per region

                        // Scan this region for player state values
                        for (long offset = 0; offset < regionSize; offset += 4)
                        {
                            try
                            {
                                long testAddress = currentAddress + offset;
                                byte[] buffer = new byte[4];
                                int bytesRead = MemAPI.ReadBytes(testAddress, buffer, 4, mem.p, hProcess);

                                if (bytesRead == 4)
                                {
                                    uint value = BitConverter.ToUInt32(buffer, 0);

                                    // Look for valid player state values
                                    if (value <= 3)
                                    {
                                        candidates.Add(testAddress);

                                        // Limit candidates to avoid memory issues
                                        if (candidates.Count >= 1000) break;
                                    }
                                }
                            }
                            catch
                            {
                                continue;
                            }
                        }

                        if (candidates.Count >= 1000) break;
                    }

                    currentAddress += (long)mbi.RegionSize;
                }
            }
            catch (Exception ex)
            {
                LogMessage($"Error searching range 0x{start:X}: {ex.Message}");
            }

            return candidates;
        }

        static long ValidatePlayerStateCandidates(List<long> candidates, IntPtr hProcess)
        {
            try
            {
                LogMessage($"Validating {candidates.Count} player state candidates...");

                var scoredCandidates = new List<(long address, double score)>();

                // Test up to 100 candidates for performance
                foreach (long candidate in candidates.Take(100))
                {
                    double score = ScorePlayerStateCandidate(candidate, hProcess);
                    if (score > 50) // Only consider candidates with decent scores
                    {
                        scoredCandidates.Add((candidate, score));
                        LogMessage($"Candidate 0x{candidate:X} scored {score:F1}");
                    }
                }

                if (scoredCandidates.Count > 0)
                {
                    // Return the highest scoring candidate
                    var best = scoredCandidates.OrderByDescending(c => c.score).First();
                    LogMessage($"Best candidate: 0x{best.address:X} with score {best.score:F1}");
                    return best.address;
                }

                LogMessage("No candidates passed validation");
                return -1;
            }
            catch (Exception ex)
            {
                LogMessage($"Error validating candidates: {ex.Message}");
                return -1;
            }
        }

        static long AnalyzeR13Setup(byte[] contextBuffer, long contextStart, long patternAddress, IntPtr hProcess)
        {
            try
            {
                LogMessage("=== ANALYZING R13 REGISTER SETUP ===");

                // Look for common x64 instruction patterns that set up r13
                // Common patterns:
                // 4C 8B 2D xx xx xx xx = lea r13, [rip+offset]
                // 4C 8B 6C 24 xx = mov r13, [rsp+offset]
                // 49 8B xx = mov reg, r13 (indicates r13 is already set)

                for (int i = 0; i < contextBuffer.Length - 8; i++)
                {
                    // Look for lea r13, [rip+offset] (4C 8B 2D xx xx xx xx)
                    if (contextBuffer[i] == 0x4C && contextBuffer[i + 1] == 0x8B && contextBuffer[i + 2] == 0x2D)
                    {
                        // Extract the RIP-relative offset
                        int ripOffset = BitConverter.ToInt32(contextBuffer, i + 3);
                        long instructionAddress = contextStart + i + 7; // Address after the instruction
                        long targetAddress = instructionAddress + ripOffset;

                        LogMessage($"Found lea r13, [rip+0x{ripOffset:X}] at 0x{contextStart + i:X}");
                        LogMessage($"Target address: 0x{targetAddress:X}");

                        // Read the pointer at the target address
                        byte[] ptrBuffer = new byte[8];
                        int ptrBytesRead = MemAPI.ReadBytes(targetAddress, ptrBuffer, 8, mem.p, hProcess);

                        if (ptrBytesRead == 8)
                        {
                            long basePointer = BitConverter.ToInt64(ptrBuffer, 0);
                            if (basePointer > 0x10000 && basePointer < 0x7FFFFFFFFFFF)
                            {
                                LogMessage($"Found potential r13 base pointer: 0x{basePointer:X}");
                                return basePointer;
                            }
                        }
                    }

                    // Look for mov r13, [address] patterns
                    if (contextBuffer[i] == 0x4C && contextBuffer[i + 1] == 0x8B && contextBuffer[i + 2] == 0x2C && contextBuffer[i + 3] == 0x25)
                    {
                        // mov r13, [absolute_address] (4C 8B 2C 25 xx xx xx xx)
                        long absoluteAddress = BitConverter.ToUInt32(contextBuffer, i + 4);

                        LogMessage($"Found mov r13, [0x{absoluteAddress:X}] at 0x{contextStart + i:X}");

                        byte[] ptrBuffer = new byte[8];
                        int ptrBytesRead = MemAPI.ReadBytes(absoluteAddress, ptrBuffer, 8, mem.p, hProcess);

                        if (ptrBytesRead == 8)
                        {
                            long basePointer = BitConverter.ToInt64(ptrBuffer, 0);
                            if (basePointer > 0x10000 && basePointer < 0x7FFFFFFFFFFF)
                            {
                                LogMessage($"Found potential r13 base pointer: 0x{basePointer:X}");
                                return basePointer;
                            }
                        }
                    }
                }

                LogMessage("No r13 setup instructions found in context");
                return -1;
            }
            catch (Exception ex)
            {
                LogMessage($"Error analyzing r13 setup: {ex.Message}");
                return -1;
            }
        }

        static void MonitorPlayerState()
        {
            try
            {
                // Simply read the 4-byte value from the pre-calculated address
                IntPtr hProcess = MemAPI.OpenProcess(MemAPI.ProcessAccessFlags.All, false, mem.p.Id);
                if (hProcess == IntPtr.Zero) return;

                try
                {
                    byte[] buffer = new byte[4];
                    int bytesRead = MemAPI.ReadBytes(playerStateDataAddress, buffer, 4, mem.p, hProcess);

                    if (bytesRead == 4)
                    {
                        uint playerStateValue = BitConverter.ToUInt32(buffer, 0);

                        // Check if this looks like a valid player state (0, 1, 3)
                        if (playerStateValue <= 10) // Reasonable range for player state
                        {
                            if (playerStateValue != lastPlayerState)
                            {
                                LogMessage($"Player state changed: {lastPlayerState} -> {playerStateValue} (address: 0x{playerStateDataAddress:X})");
                                lastPlayerState = (byte)playerStateValue;

                                // Update shared memory with the new value
                                accessor.Write(28, playerStateValue); // player_state_value
                            }
                        }
                        else
                        {
                            // Only log unreasonable values occasionally to avoid spam
                            if (playerStateValue != lastPlayerState)
                            {
                                LogMessage($"Player state value {playerStateValue} seems unreasonable");
                            }
                        }
                    }
                    else
                    {
                        LogMessage("Failed to read player state value from data address");
                    }
                }
                finally
                {
                    MemAPI.CloseHandle(hProcess);
                }
            }
            catch (Exception ex)
            {
                LogMessage($"Error in MonitorPlayerState: {ex.Message}");
            }
        }

        static long AnalyzePlayerStateInstruction(long patternAddress, IntPtr hProcess)
        {
            try
            {
                LogMessage($"Analyzing instruction at 0x{patternAddress:X} to extract r13 and rdx values");

                // Read a larger chunk of code around the pattern to analyze the context
                int analysisSize = 1024; // Read 1KB around the pattern
                long analysisStart = patternAddress - 512;
                byte[] codeBuffer = new byte[analysisSize];

                int bytesRead = MemAPI.ReadBytes(analysisStart, codeBuffer, analysisSize, mem.p, hProcess);
                if (bytesRead == 0)
                {
                    LogMessage("Failed to read code for instruction analysis");
                    return -1;
                }

                LogMessage($"Read {bytesRead} bytes of code for analysis");

                // Look for patterns that might set up r13 and rdx
                // This is a heuristic approach - we'll look for common instruction patterns

                // Strategy 1: Look for mov r13, [address] or similar instructions
                long r13Value = FindRegisterValue(codeBuffer, analysisStart, patternAddress, "r13", hProcess);
                long rdxValue = FindRegisterValue(codeBuffer, analysisStart, patternAddress, "rdx", hProcess);

                if (r13Value > 0 && rdxValue >= 0)
                {
                    long calculatedAddress = r13Value + rdxValue + 0x770;
                    LogMessage($"Found r13=0x{r13Value:X}, rdx=0x{rdxValue:X}");
                    LogMessage($"Calculated address: 0x{r13Value:X} + 0x{rdxValue:X} + 0x770 = 0x{calculatedAddress:X}");
                    return calculatedAddress;
                }

                // Strategy 2: Heuristic search - try common base addresses
                LogMessage("Direct register analysis failed, trying heuristic approach...");
                return HeuristicPlayerStateSearch(patternAddress, hProcess);
            }
            catch (Exception ex)
            {
                LogMessage($"Error in AnalyzePlayerStateInstruction: {ex.Message}");
                return -1;
            }
        }

        static long FindRegisterValue(byte[] codeBuffer, long bufferStart, long patternAddress, string register, IntPtr hProcess)
        {
            try
            {
                // This is a simplified approach - in a real implementation, we'd need a proper x64 disassembler
                // For now, we'll try some heuristic approaches

                LogMessage($"Searching for {register} value setup near pattern address");

                // Look for potential pointer dereferences that might give us base addresses
                // We'll scan memory regions that could contain the base pointers

                if (register == "r13")
                {
                    // r13 is often used as a base pointer to data structures
                    // Try to find memory regions that could contain such pointers
                    return FindPotentialBasePointer(patternAddress, hProcess);
                }
                else if (register == "rdx")
                {
                    // rdx is often an offset, which could be smaller values
                    // For player state, this might be 0, 4, 8, etc. (structure offsets)
                    return FindPotentialOffset(patternAddress, hProcess);
                }

                return -1;
            }
            catch (Exception ex)
            {
                LogMessage($"Error finding {register} value: {ex.Message}");
                return -1;
            }
        }

        static long FindPotentialBasePointer(long patternAddress, IntPtr hProcess)
        {
            try
            {
                // Look for memory regions that could contain base pointers
                // These are typically in data sections of the executable

                LogMessage("Searching for potential base pointer (r13 value)");

                // Try reading from memory regions near the pattern address
                // Base pointers are often stored in static memory locations

                for (long offset = -0x100000; offset <= 0x100000; offset += 0x1000) // Search ±1MB in 4KB steps
                {
                    long testAddress = patternAddress + offset;

                    try
                    {
                        byte[] buffer = new byte[8];
                        int bytesRead = MemAPI.ReadBytes(testAddress, buffer, 8, mem.p, hProcess);

                        if (bytesRead == 8)
                        {
                            long potentialPointer = BitConverter.ToInt64(buffer, 0);

                            // Check if this looks like a valid pointer (reasonable address range)
                            if (potentialPointer > 0x10000 && potentialPointer < 0x7FFFFFFFFFFF)
                            {
                                // Test if this pointer + some offset + 0x770 gives us reasonable data
                                if (TestPotentialPlayerStateAddress(potentialPointer, hProcess))
                                {
                                    LogMessage($"Found potential base pointer: 0x{potentialPointer:X} at address 0x{testAddress:X}");
                                    return potentialPointer;
                                }
                            }
                        }
                    }
                    catch
                    {
                        continue;
                    }
                }

                LogMessage("No suitable base pointer found");
                return -1;
            }
            catch (Exception ex)
            {
                LogMessage($"Error in FindPotentialBasePointer: {ex.Message}");
                return -1;
            }
        }

        static long FindPotentialOffset(long patternAddress, IntPtr hProcess)
        {
            try
            {
                LogMessage("Determining potential offset (rdx value)");

                // For player state, rdx is likely a small offset (0, 4, 8, 12, etc.)
                // We'll try common structure offsets

                long[] commonOffsets = { 0, 4, 8, 12, 16, 20, 24, 28, 32, 64, 128, 256 };

                foreach (long offset in commonOffsets)
                {
                    LogMessage($"Testing offset: 0x{offset:X}");
                    // We'll return the first reasonable offset
                    // The actual validation will happen when we test the full address
                    return offset;
                }

                return 0; // Default to 0 offset
            }
            catch (Exception ex)
            {
                LogMessage($"Error in FindPotentialOffset: {ex.Message}");
                return 0;
            }
        }

        static bool TestPotentialPlayerStateAddress(long basePointer, IntPtr hProcess)
        {
            try
            {
                // Test various combinations of basePointer + offset + 0x770
                long[] testOffsets = { 0, 4, 8, 12, 16, 20, 24, 28, 32 };

                foreach (long offset in testOffsets)
                {
                    long testAddress = basePointer + offset + 0x770;

                    try
                    {
                        byte[] buffer = new byte[4];
                        int bytesRead = MemAPI.ReadBytes(testAddress, buffer, 4, mem.p, hProcess);

                        if (bytesRead == 4)
                        {
                            uint value = BitConverter.ToUInt32(buffer, 0);

                            // Check if this looks like a player state value
                            if (value <= 10) // Reasonable range for player state
                            {
                                LogMessage($"Found potential player state value {value} at 0x{testAddress:X}");
                                return true;
                            }
                        }
                    }
                    catch
                    {
                        continue;
                    }
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        static long HeuristicPlayerStateSearch(long patternAddress, IntPtr hProcess)
        {
            try
            {
                LogMessage("Starting heuristic player state search...");

                // Since direct register analysis is complex, we'll use a smarter heuristic approach
                // Look for memory locations that contain values that change in patterns consistent with player state

                // Search in a reasonable range around the pattern address
                long searchStart = patternAddress - 0x50000; // 320KB before
                long searchEnd = patternAddress + 0x50000;   // 320KB after

                LogMessage($"Searching range 0x{searchStart:X} to 0x{searchEnd:X} for player state candidates");

                for (long addr = searchStart; addr < searchEnd; addr += 4)
                {
                    try
                    {
                        byte[] buffer = new byte[4];
                        int bytesRead = MemAPI.ReadBytes(addr, buffer, 4, mem.p, hProcess);

                        if (bytesRead == 4)
                        {
                            uint value = BitConverter.ToUInt32(buffer, 0);

                            // Look for values that could be player state
                            if (value <= 3) // Player state is typically 0, 1, or 3
                            {
                                LogMessage($"Found potential player state candidate: value={value} at 0x{addr:X}");

                                // For now, return the first reasonable candidate
                                // In a more sophisticated implementation, we'd monitor multiple candidates
                                return addr;
                            }
                        }
                    }
                    catch
                    {
                        continue;
                    }
                }

                LogMessage("Heuristic search found no suitable candidates");
                return -1;
            }
            catch (Exception ex)
            {
                LogMessage($"Error in HeuristicPlayerStateSearch: {ex.Message}");
                return -1;
            }
        }

        static void TestCoordinatePattern()
        {
            try
            {
                LogMessage("=== TESTING COORDINATE PATTERN ===");

                // Test if we can read coordinates from the calculated address
                if (coordinatesAddress > 0)
                {
                    LogMessage($"Testing coordinate address: 0x{coordinatesAddress:X}");

                    IntPtr hProcess = MemAPI.OpenProcess(MemAPI.ProcessAccessFlags.All, false, mem.p.Id);
                    if (hProcess != IntPtr.Zero)
                    {
                        try
                        {
                            // Try to read 12 bytes (3 floats) from the coordinate address
                            byte[] buffer = new byte[12];
                            int bytesRead = MemAPI.ReadBytes(coordinatesAddress, buffer, 12, mem.p, hProcess);

                            if (bytesRead == 12)
                            {
                                float x = BitConverter.ToSingle(buffer, 0);
                                float y = BitConverter.ToSingle(buffer, 4);
                                float z = BitConverter.ToSingle(buffer, 8);

                                LogMessage($"Read coordinates: X={x:F2}, Y={y:F2}, Z={z:F2}");

                                // Check if these look like reasonable coordinates
                                if (Math.Abs(x) < 10000 && Math.Abs(y) < 10000 && Math.Abs(z) < 10000 &&
                                    !float.IsNaN(x) && !float.IsNaN(y) && !float.IsNaN(z) &&
                                    !float.IsInfinity(x) && !float.IsInfinity(y) && !float.IsInfinity(z))
                                {
                                    LogMessage("✓ Coordinate pattern appears CORRECT - values look reasonable");
                                }
                                else
                                {
                                    LogMessage("✗ Coordinate pattern appears WRONG - values look unreasonable");
                                    LogMessage("This suggests the coordinate AOB pattern or offset is incorrect");
                                }
                            }
                            else
                            {
                                LogMessage("✗ Failed to read coordinates from calculated address");
                            }
                        }
                        finally
                        {
                            MemAPI.CloseHandle(hProcess);
                        }
                    }
                }
                else
                {
                    LogMessage("No coordinate address to test yet");
                }

                LogMessage("=== END COORDINATE PATTERN TEST ===");
            }
            catch (Exception ex)
            {
                LogMessage($"Error in TestCoordinatePattern: {ex.Message}");
            }
        }

        static long FindCameraCmpxchgAddress()
        {
            try
            {
                // New PhoneCamera AOB and target instruction provided by user
                LogMessage("Scanning for PhoneCamera write instruction (mov [r13+rdx+0x0C], bl)...");
                
                // Full AOB pattern (provided by user)
                byte[] fullCameraAob = new byte[]
                {
                    0x00, 0x83, 0xAC, 0x24, 0xB0, 0x02, 0x00, 0x00, 0x01, 0x8B, 0x94, 0x24, 0xB8, 0x02, 0x00, 0x00,
                    0x41, 0xFF, 0xA4, 0x57, 0x00, 0x00, 0x00, 0x20, 0x83, 0xAC, 0x24, 0xB0, 0x02, 0x00, 0x00, 0x02,
                    0x41, 0x88, 0x5C, 0x15, 0x0C, 0xBA, 0xA4, 0x56, 0xAA, 0x03, 0x41, 0xFF, 0xA7, 0x48, 0xAD, 0x54,
                    0x27, 0x90, 0x90, 0x83, 0xAC, 0x24, 0xB0, 0x02, 0x00, 0x00, 0x27, 0x8B, 0x44, 0x24, 0x08, 0x49,
                    0x89, 0xC6, 0x45, 0x0F, 0x38, 0xF1, 0xB4, 0x05, 0x60, 0xFF, 0xFF, 0xFF, 0x05, 0x60, 0xFF
                };
                
                // Target sub-sequence: mov [r13+rdx+0x0C], bl
                byte[] movSubSequence = new byte[] { 0x41, 0x88, 0x5C, 0x15, 0x0C };
                
                // Calculate offset of target sequence within full pattern
                int movOffset = -1;
                for (int i = 0; i <= fullCameraAob.Length - movSubSequence.Length; i++)
                {
                    bool match = true;
                    for (int j = 0; j < movSubSequence.Length; j++)
                    {
                        if (fullCameraAob[i + j] != movSubSequence[j])
                        {
                            match = false;
                            break;
                        }
                    }
                    if (match)
                    {
                        movOffset = i;
                        LogMessage($"PhoneCamera mov sequence found at offset {i} in pattern");
                        break;
                    }
                }

                if (movOffset < 0)
                {
                    LogMessage("ERROR: PhoneCamera mov sequence not found in AOB pattern");
                    return -1L;
                }

                IntPtr hProcess = MemAPI.OpenProcess(MemAPI.ProcessAccessFlags.All, false, mem.p.Id);
                if (hProcess == IntPtr.Zero)
                {
                    LogMessage("Could not open process for phonecamera search");
                    return -1L;
                }

                try
                {
                    long currentAddress = 0x10000;
                    long maxAddress = 0x7FFFFFFFFFFF;
                    int regionsScanned = 0;

                    while (currentAddress < maxAddress)
                    {
                        MemAPI.MEMORY_BASIC_INFORMATION mbi;
                        int result = MemAPI.VirtualQueryEx(hProcess, (IntPtr)currentAddress, out mbi, (uint)Marshal.SizeOf(typeof(MemAPI.MEMORY_BASIC_INFORMATION)));

                        if (result == 0)
                        {
                            currentAddress += 0x10000;
                            continue;
                        }

                        regionsScanned++;
                        if (regionsScanned > 5000) break;

                        // Scan ALL committed regions including non-writable ones
                        bool isScannable = (mbi.State == MemAPI.StateEnum.MEM_COMMIT) &&
                                          (mbi.Protect == MemAPI.AllocationProtectEnum.PAGE_EXECUTE ||
                                           mbi.Protect == MemAPI.AllocationProtectEnum.PAGE_EXECUTE_READ ||
                                           mbi.Protect == MemAPI.AllocationProtectEnum.PAGE_EXECUTE_READWRITE ||
                                           mbi.Protect == MemAPI.AllocationProtectEnum.PAGE_READONLY ||
                                           mbi.Protect == MemAPI.AllocationProtectEnum.PAGE_READWRITE);

                        if (isScannable)
                        {
                            long regionSize = (long)mbi.RegionSize;
                            long patternAddr = SearchPatternInRegionFast(currentAddress, regionSize, fullCameraAob, hProcess);
                            if (patternAddr >= 0)
                            {
                                long movAddr = patternAddr + movOffset;
                                LogMessage($"Found PhoneCamera AOB at 0x{patternAddr:X}, mov at 0x{movAddr:X} (offset +{movOffset})");
                                
                                // Verify the bytes at the mov address
                                byte[] verifyBytes = new byte[5];
                                int verifyRead = MemAPI.ReadBytes(movAddr, verifyBytes, 5, mem.p, hProcess);
                                if (verifyRead == 5)
                                {
                                    LogMessage($"Verification: Bytes at mov address: {BitConverter.ToString(verifyBytes)}");
                                    // Expect 41 88 5C 15 0C
                                    if (verifyBytes[0] == 0x41 && verifyBytes[1] == 0x88 && verifyBytes[2] == 0x5C && verifyBytes[3] == 0x15 && verifyBytes[4] == 0x0C)
                                    {
                                        LogMessage($"SUCCESS: Confirmed mov [r13+rdx+0x0C], bl at 0x{movAddr:X}");
                                    }
                                    else
                                    {
                                        LogMessage($"WARNING: Expected 41 88 5C 15 0C but found {verifyBytes[0]:X2} {verifyBytes[1]:X2} {verifyBytes[2]:X2} {verifyBytes[3]:X2} {verifyBytes[4]:X2} at 0x{movAddr:X}");
                                    }
                                }
                                
                                return movAddr;
                            }
                        }

                        currentAddress += (long)mbi.RegionSize;
                    }

                    LogMessage($"PhoneCamera mov not found after scanning {regionsScanned} regions");
                    return -1L;
                }
                finally
                {
                    MemAPI.CloseHandle(hProcess);
                }
            }
            catch (Exception ex)
            {
                LogMessage($"Error in FindCameraCmpxchgAddress: {ex.Message}");
                return -1L;
            }
        }

        static void CleanupResources()
        {
            try
            {
                LogMessage("Cleaning up resources...");
                
                if (accessor != null)
                {
                    accessor.Dispose();
                    LogMessage("Shared memory accessor disposed");
                }
                
                if (mmf != null)
                {
                    mmf.Dispose();
                    LogMessage("Memory mapped file disposed");
                }
                
                if (logWriter != null)
                {
                    LogMessage("Position finder cleanup completed");
                    logWriter.Dispose();
                }
                
                if (!silentMode)
                {
                    Console.WriteLine("Resources cleaned up");
                }
            }
            catch (Exception ex)
            {
                string errorMsg = $"Error during cleanup: {ex.Message}";
                if (!silentMode)
                {
                    Console.WriteLine(errorMsg);
                }
                try
                {
                    logWriter?.WriteLine($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {errorMsg}");
                    logWriter?.Dispose();
                }
                catch
                {
                    // Ignore cleanup errors
                }
            }
        }

        static long FindR13BasePointer(IntPtr hProcess)
        {
            try
            {
                LogMessage("=== SEARCHING FOR R13 BASE POINTER ===");

                // Strategy: Scan memory regions that typically contain base pointers
                // Look for pointers in data sections of the main executable

                long currentAddress = 0x140000000; // Typical base address for 64-bit executables
                long maxAddress = currentAddress + 0x10000000; // Search within 256MB of base

                while (currentAddress < maxAddress)
                {
                    MemAPI.MEMORY_BASIC_INFORMATION mbi;
                    int result = MemAPI.VirtualQueryEx(hProcess, (IntPtr)currentAddress, out mbi, (uint)Marshal.SizeOf(typeof(MemAPI.MEMORY_BASIC_INFORMATION)));

                    if (result == 0)
                    {
                        currentAddress += 0x10000;
                        continue;
                    }

                    // Look in readable data sections
                    if (mbi.State == MemAPI.StateEnum.MEM_COMMIT &&
                        (mbi.Protect == MemAPI.AllocationProtectEnum.PAGE_READONLY ||
                         mbi.Protect == MemAPI.AllocationProtectEnum.PAGE_READWRITE))
                    {
                        long regionSize = Math.Min((long)mbi.RegionSize, 0x100000); // Max 1MB per region

                        for (long offset = 0; offset < regionSize; offset += 8)
                        {
                            try
                            {
                                byte[] buffer = new byte[8];
                                int bytesRead = MemAPI.ReadBytes(currentAddress + offset, buffer, 8, mem.p, hProcess);

                                if (bytesRead == 8)
                                {
                                    long potentialPointer = BitConverter.ToInt64(buffer, 0);

                                    // Check if this looks like a valid base pointer
                                    if (potentialPointer > 0x100000 && potentialPointer < 0x7FFFFFFFFFFF)
                                    {
                                        // Test if this could be the r13 base by checking for valid player state data
                                        if (TestPotentialR13Base(potentialPointer, hProcess))
                                        {
                                            LogMessage($"Found potential r13 base: 0x{potentialPointer:X} at 0x{currentAddress + offset:X}");
                                            return potentialPointer;
                                        }
                                    }
                                }
                            }
                            catch
                            {
                                continue;
                            }
                        }
                    }

                    currentAddress += (long)mbi.RegionSize;
                }

                LogMessage("No r13 base pointer found");
                return -1;
            }
            catch (Exception ex)
            {
                LogMessage($"Error finding r13 base pointer: {ex.Message}");
                return -1;
            }
        }

        static long FindRdxOffset(IntPtr hProcess)
        {
            // rdx is typically a small offset (0, 4, 8, 12, etc.)
            // We'll test these values when we have the r13 base
            return 0; // Default to 0, will be tested in calculation
        }

        static bool TestPotentialR13Base(long basePointer, IntPtr hProcess)
        {
            try
            {
                // Test if basePointer + small_offset + 0x770 contains valid player state values
                for (int offset = 0; offset <= 32; offset += 4)
                {
                    long testAddress = basePointer + offset + 0x770;

                    if (TestPlayerStateAddress(testAddress, hProcess))
                    {
                        return true;
                    }
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        static bool ValidatePlayerStateAddress(long address, IntPtr hProcess)
        {
            try
            {
                // Enhanced validation - check multiple times to ensure stability
                List<uint> values = new List<uint>();

                for (int i = 0; i < 3; i++)
                {
                    byte[] buffer = new byte[4];
                    int bytesRead = MemAPI.ReadBytes(address, buffer, 4, mem.p, hProcess);

                    if (bytesRead == 4)
                    {
                        uint value = BitConverter.ToUInt32(buffer, 0);
                        values.Add(value);
                    }
                    else
                    {
                        return false;
                    }

                    if (i < 2) System.Threading.Thread.Sleep(10); // Small delay between reads
                }

                // Check if all values are valid player states (0, 1, or 3)
                bool allValid = values.All(v => v <= 3);

                if (allValid)
                {
                    LogMessage($"VALIDATED player state address 0x{address:X} with values: [{string.Join(", ", values)}]");
                    return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        static List<long> ScanRegionForPlayerState(long regionStart, long regionSize, IntPtr hProcess)
        {
            List<long> candidates = new List<long>();

            try
            {
                // Scan in 64KB chunks to avoid memory issues
                long chunkSize = Math.Min(regionSize, 0x10000);
                byte[] buffer = new byte[chunkSize];

                for (long offset = 0; offset < regionSize; offset += chunkSize)
                {
                    long currentAddress = regionStart + offset;
                    long actualChunkSize = Math.Min(chunkSize, regionSize - offset);

                    int bytesRead = MemAPI.ReadBytes(currentAddress, buffer, (int)actualChunkSize, mem.p, hProcess);
                    if (bytesRead == 0) continue;

                    // Look for potential player state values (0, 1, 3) in the buffer
                    for (int i = 0; i <= bytesRead - 4; i += 4) // Check every 4 bytes (aligned)
                    {
                        uint value = BitConverter.ToUInt32(buffer, i);

                        // Player state should be 0, 1, or 3
                        if (value <= 3)
                        {
                            long candidateAddress = currentAddress + i;
                            candidates.Add(candidateAddress);

                            // Don't collect too many candidates from one region
                            if (candidates.Count >= 100) break;
                        }
                    }

                    if (candidates.Count >= 100) break;
                }
            }
            catch (Exception ex)
            {
                LogMessage($"Error scanning region 0x{regionStart:X}: {ex.Message}");
            }

            return candidates;
        }

        static long ValidateBestCandidate(List<long> candidates, IntPtr hProcess)
        {
            try
            {
                LogMessage($"Validating {candidates.Count} player state candidates...");

                var validCandidates = new List<(long address, double score)>();

                foreach (long candidate in candidates.Take(50)) // Limit to first 50 for performance
                {
                    double score = ScorePlayerStateCandidate(candidate, hProcess);
                    if (score > 0)
                    {
                        validCandidates.Add((candidate, score));
                        LogMessage($"Candidate 0x{candidate:X} scored {score:F2}");
                    }
                }

                if (validCandidates.Count > 0)
                {
                    // Return the highest scoring candidate
                    var best = validCandidates.OrderByDescending(c => c.score).First();
                    LogMessage($"Best candidate: 0x{best.address:X} with score {best.score:F2}");
                    return best.address;
                }

                return -1;
            }
            catch (Exception ex)
            {
                LogMessage($"Error validating candidates: {ex.Message}");
                return -1;
            }
        }

        static double ScorePlayerStateCandidate(long address, IntPtr hProcess)
        {
            try
            {
                List<uint> values = new List<uint>();

                // Read the value multiple times over a short period
                for (int i = 0; i < 5; i++)
                {
                    byte[] buffer = new byte[4];
                    int bytesRead = MemAPI.ReadBytes(address, buffer, 4, mem.p, hProcess);

                    if (bytesRead != 4) return 0; // Invalid address

                    uint value = BitConverter.ToUInt32(buffer, 0);
                    values.Add(value);

                    if (i < 4) System.Threading.Thread.Sleep(20); // Small delay between reads
                }

                // Score based on validity and stability
                double score = 0;

                // All values must be valid player states (0, 1, 2, 3)
                if (values.All(v => v <= 3))
                {
                    score += 50; // Base score for valid values

                    // Bonus for stability (values don't change rapidly)
                    var uniqueValues = values.Distinct().Count();
                    if (uniqueValues == 1) score += 30; // Very stable
                    else if (uniqueValues == 2) score += 20; // Somewhat stable
                    else if (uniqueValues <= 3) score += 10; // Acceptable

                    // Bonus for common player state values
                    if (values.Contains(0)) score += 10; // Normal state
                    if (values.Contains(1)) score += 5;  // Menu state

                    // Penalty for invalid values
                    if (values.Any(v => v > 3)) score = 0;
                }

                return score;
            }
            catch
            {
                return 0;
            }
        }

        static long BehavioralPlayerStateSearch(long patternAddress, IntPtr hProcess)
        {
            try
            {
                LogMessage("=== BEHAVIORAL PLAYER STATE SEARCH ===");

                // Search in expanding ranges around the pattern
                List<(long start, long end, string description)> searchRanges = new List<(long, long, string)>
                {
                    (patternAddress - 0x100000, patternAddress + 0x100000, "Near pattern (±1MB)"),
                    (patternAddress - 0x1000000, patternAddress + 0x1000000, "Medium range (±16MB)"),
                    (patternAddress - 0x10000000, patternAddress + 0x10000000, "Wide range (±256MB)")
                };

                foreach (var (start, end, description) in searchRanges)
                {
                    LogMessage($"Behavioral search {description}: 0x{start:X} to 0x{end:X}");

                    List<long> candidates = new List<long>();

                    // Scan for candidates in this range
                    for (long addr = start; addr < end; addr += 4)
                    {
                        try
                        {
                            byte[] buffer = new byte[4];
                            int bytesRead = MemAPI.ReadBytes(addr, buffer, 4, mem.p, hProcess);

                            if (bytesRead == 4)
                            {
                                uint value = BitConverter.ToUInt32(buffer, 0);
                                if (value <= 3)
                                {
                                    candidates.Add(addr);
                                    if (candidates.Count >= 1000) break; // Limit candidates
                                }
                            }
                        }
                        catch
                        {
                            continue;
                        }
                    }

                    LogMessage($"Found {candidates.Count} candidates in {description}");

                    // Validate candidates in this range
                    if (candidates.Count > 0)
                    {
                        long validatedAddress = ValidateBestCandidate(candidates, hProcess);
                        if (validatedAddress > 0)
                        {
                            LogMessage($"SUCCESS: Found validated player state at 0x{validatedAddress:X} in {description}");
                            return validatedAddress;
                        }
                    }
                }

                LogMessage("Behavioral search found no valid player state addresses");
                return -1;
            }
            catch (Exception ex)
            {
                LogMessage($"Error in behavioral player state search: {ex.Message}");
                return -1;
            }
        }

        static bool TestPlayerStateAddress(long address, IntPtr hProcess)
        {
            try
            {
                byte[] buffer = new byte[4];
                int bytesRead = MemAPI.ReadBytes(address, buffer, 4, mem.p, hProcess);

                if (bytesRead == 4)
                {
                    uint value = BitConverter.ToUInt32(buffer, 0);

                    // Player state should be 0 (normal), 1 (menu/paused), or 3 (loading/cutscene)
                    if (value <= 3)
                    {
                        LogMessage($"Found potential player state value {value} at 0x{address:X}");
                        return true;
                    }
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Check if the mod DLL is still loaded and responsive by checking shared memory updates
        /// </summary>
        static bool CheckModuleStillLoaded()
        {
            try
            {
                // Ensure shared memory mapping is available
                if (mmf == null || accessor == null)
                    return false;

                // Read the shared memory to check if it's still being updated
                var data = new SharedPositionData();
                accessor.Read(0, out data);

                // Check if the shared memory contains valid data and has been updated recently
                if (data.is_valid == 1 && data.last_update > 0)
                {
                    // Convert Unix timestamp to DateTime
                    var lastUpdate = DateTimeOffset.FromUnixTimeSeconds((long)data.last_update).DateTime;
                    var timeSinceUpdate = DateTime.UtcNow - lastUpdate;
                    
                    // If the shared memory hasn't been updated in the last 15 seconds, assume the DLL crashed
                    if (timeSinceUpdate.TotalSeconds > 15)
                    {
                        LogMessage($"Shared memory hasn't been updated for {timeSinceUpdate.TotalSeconds:F1} seconds. DLL may have crashed.");
                        return false;
                    }
                    return true;
                }
                
                return false;
            }
            catch (Exception ex)
            {
                LogMessage($"Error checking module status: {ex.Message}");
                return false;
            }
        }
    }
}
