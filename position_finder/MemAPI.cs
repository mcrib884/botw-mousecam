using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace PositionFinder
{
    internal class MemAPI
    {
        // Windows API imports
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern int CloseHandle(IntPtr hProcess);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, long lpBaseAddress, byte[] buffer, int size, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, long lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        private Process _p;
        private string _processName;
        private IntPtr hProc = IntPtr.Zero;

        public Process p
        {
            get
            {
                if (this._p == null && this.ProcessName != "")
                {
                    this._p = Process.GetProcessesByName(this.ProcessName).FirstOrDefault<Process>();
                }
                return this._p;
            }
            set
            {
                this._p = value;
            }
        }

        public string ProcessName
        {
            get
            {
                if (this._processName == null)
                {
                    return "";
                }
                return this._processName;
            }
            set
            {
                if (value == "" || value == null)
                {
                    this.p = null;
                    return;
                }
                this._processName = value;
                this.p = Process.GetProcessesByName(this.ProcessName).FirstOrDefault<Process>();
            }
        }

        public IntPtr Handle
        {
            get
            {
                return this.hProc;
            }
            set
            {
                this.hProc = value;
            }
        }

        public void UpdateProcess(string processName = "")
        {
            processName = ((processName == "") ? this._processName : processName);
            this.ProcessName = processName;
        }

        public bool CheckOpenProcess()
        {
            bool result = false;
            if (this.p == null)
            {
                return result;
            }
            IntPtr intPtr = OpenProcess(ProcessAccessFlags.All, false, this.p.Id);
            if (intPtr != IntPtr.Zero)
            {
                result = true;
                CloseHandle(intPtr);
            }
            return result;
        }

        public float GetSingleAt(long address)
        {
            float result = 0f;
            if (this.p == null)
            {
                return result;
            }
            IntPtr hProcess = OpenProcess(ProcessAccessFlags.All, false, this.p.Id);
            result = ReadSingle(address, this.p, hProcess);
            CloseHandle(hProcess);
            return result;
        }

        public static float ReadSingle(long address, Process p, IntPtr hProc)
        {
            IntPtr hProcess = (hProc == IntPtr.Zero) ? OpenProcess(ProcessAccessFlags.All, false, p.Id) : hProc;
            byte[] array = new byte[4];
            int num = 0;
            ReadProcessMemory(hProcess, address, array, array.Length, ref num);
            if (hProc == IntPtr.Zero)
            {
                CloseHandle(hProcess);
            }
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(array);
            }
            return BitConverter.ToSingle(array, 0);
        }

        public static int ReadBytes(long address, byte[] buffer, int count, Process p, IntPtr hProc)
        {
            IntPtr hProcess = (hProc == IntPtr.Zero) ? OpenProcess(ProcessAccessFlags.All, false, p.Id) : hProc;
            int result = 0;
            ReadProcessMemory(hProcess, address, buffer, count, ref result);
            if (hProc == IntPtr.Zero)
            {
                CloseHandle(hProcess);
            }
            return result;
        }

        public bool FindRegionBySize(long size, out long regionStart, out long regionSize, IntPtr hProc, long startAddress = 0L, bool needReadWrite = true)
        {
            bool result = false;
            regionStart = 0L;
            regionSize = 0L;
            IntPtr hProcess;
            if (hProc == IntPtr.Zero)
            {
                if (this.p == null)
                {
                    return false;
                }
                hProcess = OpenProcess(ProcessAccessFlags.All, false, this.p.Id);
            }
            else
            {
                hProcess = hProc;
            }
            long maxValue = long.MaxValue;
            long num = startAddress;
            MEMORY_BASIC_INFORMATION memory_BASIC_INFORMATION;
            do
            {
                VirtualQueryEx(hProcess, (IntPtr)num, out memory_BASIC_INFORMATION, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
                if ((long)memory_BASIC_INFORMATION.RegionSize == size)
                {
                    if (!needReadWrite)
                    {
                        goto IL_F3;
                    }
                    if (memory_BASIC_INFORMATION.Protect == AllocationProtectEnum.PAGE_READWRITE && memory_BASIC_INFORMATION.State == StateEnum.MEM_COMMIT)
                    {
                        goto IL_D3;
                    }
                }
                if (num == (long)memory_BASIC_INFORMATION.BaseAddress + (long)memory_BASIC_INFORMATION.RegionSize)
                {
                    break;
                }
                num = (long)memory_BASIC_INFORMATION.BaseAddress + (long)memory_BASIC_INFORMATION.RegionSize;
            }
            while (num <= maxValue);
            goto IL_111;
            IL_D3:
            regionStart = (long)memory_BASIC_INFORMATION.BaseAddress;
            regionSize = (long)memory_BASIC_INFORMATION.RegionSize;
            result = true;
            goto IL_111;
            IL_F3:
            regionStart = (long)memory_BASIC_INFORMATION.BaseAddress;
            regionSize = (long)memory_BASIC_INFORMATION.RegionSize;
            result = true;
            IL_111:
            if (hProc == IntPtr.Zero)
            {
                CloseHandle(hProcess);
            }
            return result;
        }

        public long pagedMemorySearchMatch(int[] search, long startAddress, long regionSize)
        {
            long result = -1L;
            int val = 20480;
            int num = Math.Max(search.Length * 20, val);
            if (this.p == null)
            {
                return result;
            }
            IntPtr hProcess = OpenProcess(ProcessAccessFlags.All, false, this.p.Id);
            byte[] array = new byte[num];
            long num2 = startAddress + regionSize;
            for (long num3 = startAddress; num3 < num2; num3 += (long)(array.Length - search.Length))
            {
                ReadBytes(num3, array, num, this.p, hProcess);
                int num4;
                if ((num4 = findSequenceMatch(array, 0, search, true, false)) >= 0)
                {
                    result = num3 + (long)num4;
                    break;
                }
            }
            CloseHandle(hProcess);
            return result;
        }

        public static int findSequenceMatch(byte[] array, int start, int[] sequence, bool loop = true, bool debug = false)
        {
            int num1 = array.Length - sequence.Length;
            int num2 = sequence[0];
            for (; start < num1; ++start)
            {
                switch (num2)
                {
                    case -2:
                        if (array[start] != (byte)0)
                            goto case -1;
                        else
                            goto default;
                    case -1:
                        for (int index = 1; index <= sequence.Length; ++index)
                        {
                            if (index >= sequence.Length)
                                return start;
                            if (sequence[index] != -1 && (sequence[index] != -2 || array[start + index] == (byte)0))
                            {
                                if ((int)array[start + index] == (int)(byte)sequence[index])
                                {
                                    if (index == sequence.Length - 1)
                                        return start;
                                }
                                else
                                    break;
                            }
                        }
                        break;
                    default:
                        if (num2 <= -1 || (int)array[start] != (int)(byte)num2)
                            break;
                        goto case -1;
                }
                if (!loop)
                    break;
            }
            return -1;
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 2035711U,
            Terminate = 1U,
            CreateThread = 2U,
            VMOperation = 8U,
            VMRead = 16U,
            VMWrite = 32U,
            DupHandle = 64U,
            SetInformation = 512U,
            QueryInformation = 1024U,
            Synchronize = 1048576U
        }

        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public AllocationProtectEnum AllocationProtect;
            public IntPtr RegionSize;
            public StateEnum State;
            public AllocationProtectEnum Protect;
            public TypeEnum Type;
        }

        public enum AllocationProtectEnum : uint
        {
            PAGE_EXECUTE = 16U,
            PAGE_EXECUTE_READ = 32U,
            PAGE_EXECUTE_READWRITE = 64U,
            PAGE_EXECUTE_WRITECOPY = 128U,
            PAGE_NOACCESS = 1U,
            PAGE_READONLY,
            PAGE_READWRITE = 4U,
            PAGE_WRITECOPY = 8U,
            PAGE_GUARD = 256U,
            PAGE_NOCACHE = 512U,
            PAGE_WRITECOMBINE = 1024U
        }

        public enum StateEnum : uint
        {
            MEM_COMMIT = 4096U,
            MEM_FREE = 65536U,
            MEM_RESERVE = 8192U
        }

        public enum TypeEnum : uint
        {
            MEM_IMAGE = 16777216U,
            MEM_MAPPED = 262144U,
            MEM_PRIVATE = 131072U
        }
    }
}
