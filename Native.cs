using System;
using System.Runtime.InteropServices;

namespace ActiveMark.Native
{
    internal static class Kernel32
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WaitForDebugEvent(out DEBUG_EVENT lpDebugEvent, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ContinueDebugEvent(uint dwProcessId, uint dwThreadId, uint dwContinueStatus);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DebugActiveProcessStop(uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] int[] lpBuffer,
            int dwSize,
            out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int dwSize,
            out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            int[] lpBuffer,
            int dwSize,
            out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetThreadSelectorEntry(IntPtr hThread, uint dwSelector, out LDT_ENTRY lpSelectorEntry);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint GetVersion();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("psapi.dll", SetLastError = true)]
        public static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded, uint dwFilterFlag);

        [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, System.Text.StringBuilder lpBaseName, uint nSize);

        [DllImport("psapi.dll", SetLastError = true)]
        public static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out MODULEINFO lpmodinfo, uint cb);

        public const uint LIST_MODULES_32BIT = 0x00000001;
        public const uint LIST_MODULES_64BIT = 0x00000002;
        public const uint LIST_MODULES_ALL = 0x00000003;

        [StructLayout(LayoutKind.Sequential)]
        public struct MODULEINFO
        {
            public IntPtr lpBaseOfDll;
            public uint SizeOfImage;
            public IntPtr EntryPoint;
        }
    }

    public static class Constants
    {
        public const uint DEBUG_PROCESS = 0x00000001;
        public const uint DEBUG_ONLY_THIS_PROCESS = 0x00000002;

        public const uint DBG_CONTINUE = 0x00010002;
        public const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;

        public const uint EXCEPTION_DEBUG_EVENT = 1;
        public const uint CREATE_THREAD_DEBUG_EVENT = 2;
        public const uint CREATE_PROCESS_DEBUG_EVENT = 3;
        public const uint EXIT_THREAD_DEBUG_EVENT = 4;
        public const uint EXIT_PROCESS_DEBUG_EVENT = 5;
        public const uint LOAD_DLL_DEBUG_EVENT = 6;
        public const uint UNLOAD_DLL_DEBUG_EVENT = 7;
        public const uint OUTPUT_DEBUG_STRING_DEBUG_EVENT = 8;
        public const uint RIP_EVENT = 9;

        public const uint EXCEPTION_ACCESS_VIOLATION = 0xC0000005;
        public const uint EXCEPTION_BREAKPOINT = 0x80000003;
        public const uint EXCEPTION_SINGLE_STEP = 0x80000004;
        public const uint CPP_EXCEPTION = 0xE06D7363;

        public const uint CONTEXT_FULL = 0x00010007;
        public const uint CONTEXT_CONTROL = 0x00010001;
        public const uint CONTEXT_SEGMENTS = 0x00010004;

        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_RESERVE = 0x2000;
        public const uint MEM_RELEASE = 0x8000;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;

        public const uint INFINITE = 0xFFFFFFFF;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct DEBUG_EVENT
    {
        public uint dwDebugEventCode;
        public uint dwProcessId;
        public uint dwThreadId;
        public DEBUG_EVENT_UNION u;
    }

    [StructLayout(LayoutKind.Explicit, Pack = 4)]
    public struct DEBUG_EVENT_UNION
    {
        [FieldOffset(0)]
        public EXCEPTION_DEBUG_INFO Exception;
        [FieldOffset(0)]
        public CREATE_THREAD_DEBUG_INFO CreateThread;
        [FieldOffset(0)]
        public CREATE_PROCESS_DEBUG_INFO CreateProcessInfo;
        [FieldOffset(0)]
        public EXIT_THREAD_DEBUG_INFO ExitThread;
        [FieldOffset(0)]
        public EXIT_PROCESS_DEBUG_INFO ExitProcess;
        [FieldOffset(0)]
        public LOAD_DLL_DEBUG_INFO LoadDll;
        [FieldOffset(0)]
        public UNLOAD_DLL_DEBUG_INFO UnloadDll;
        [FieldOffset(0)]
        public OUTPUT_DEBUG_STRING_INFO DebugString;
        [FieldOffset(0)]
        public RIP_INFO RipInfo;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct EXCEPTION_DEBUG_INFO
    {
        public EXCEPTION_RECORD ExceptionRecord;
        public uint dwFirstChance;
    }

    [StructLayout(LayoutKind.Explicit, Pack = 4)]
    public struct EXCEPTION_RECORD
    {
        [FieldOffset(0)]
        public uint ExceptionCode;
        [FieldOffset(4)]
        public uint ExceptionFlags;
        [FieldOffset(8)]
        public IntPtr ExceptionRecord;
        [FieldOffset(12)]
        public IntPtr ExceptionAddress;
        [FieldOffset(16)]
        public uint NumberParameters;
        [FieldOffset(20)]
        public uint ExceptionInformation0;
        [FieldOffset(24)]
        public uint ExceptionInformation1;
        [FieldOffset(28)]
        public uint ExceptionInformation2;
        [FieldOffset(32)]
        public uint ExceptionInformation3;
        [FieldOffset(36)]
        public uint ExceptionInformation4;
        [FieldOffset(40)]
        public uint ExceptionInformation5;
        [FieldOffset(44)]
        public uint ExceptionInformation6;
        [FieldOffset(48)]
        public uint ExceptionInformation7;
        [FieldOffset(52)]
        public uint ExceptionInformation8;
        [FieldOffset(56)]
        public uint ExceptionInformation9;
        [FieldOffset(60)]
        public uint ExceptionInformation10;
        [FieldOffset(64)]
        public uint ExceptionInformation11;
        [FieldOffset(68)]
        public uint ExceptionInformation12;
        [FieldOffset(72)]
        public uint ExceptionInformation13;
        [FieldOffset(76)]
        public uint ExceptionInformation14;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct CREATE_THREAD_DEBUG_INFO
    {
        public IntPtr hThread;
        public IntPtr lpThreadLocalBase;
        public IntPtr lpStartAddress;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct CREATE_PROCESS_DEBUG_INFO
    {
        public IntPtr hFile;
        public IntPtr hProcess;
        public IntPtr hThread;
        public IntPtr lpBaseOfImage;
        public uint dwDebugInfoFileOffset;
        public uint nDebugInfoSize;
        public IntPtr lpThreadLocalBase;
        public IntPtr lpStartAddress;
        public IntPtr lpImageName;
        public ushort fUnicode;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct EXIT_THREAD_DEBUG_INFO
    {
        public uint dwExitCode;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct EXIT_PROCESS_DEBUG_INFO
    {
        public uint dwExitCode;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct LOAD_DLL_DEBUG_INFO
    {
        public IntPtr hFile;
        public IntPtr lpBaseOfDll;
        public uint dwDebugInfoFileOffset;
        public uint nDebugInfoSize;
        public IntPtr lpImageName;
        public ushort fUnicode;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct UNLOAD_DLL_DEBUG_INFO
    {
        public IntPtr lpBaseOfDll;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct OUTPUT_DEBUG_STRING_INFO
    {
        public IntPtr lpDebugStringData;
        public ushort fUnicode;
        public ushort nDebugStringLength;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct RIP_INFO
    {
        public uint dwError;
        public uint dwType;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct CONTEXT
    {
        public uint ContextFlags;
        public uint Dr0;
        public uint Dr1;
        public uint Dr2;
        public uint Dr3;
        public uint Dr6;
        public uint Dr7;
        public FLOATING_SAVE_AREA FloatSave;
        public uint SegGs;
        public uint SegFs;
        public uint SegEs;
        public uint SegDs;
        public uint Edi;
        public uint Esi;
        public uint Ebx;
        public uint Edx;
        public uint Ecx;
        public uint Eax;
        public uint Ebp;
        public uint Eip;
        public uint SegCs;
        public uint EFlags;
        public uint Esp;
        public uint SegSs;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
        public byte[] ExtendedRegisters;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct FLOATING_SAVE_AREA
    {
        public uint ControlWord;
        public uint StatusWord;
        public uint TagWord;
        public uint ErrorOffset;
        public uint ErrorSelector;
        public uint DataOffset;
        public uint DataSelector;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
        public byte[] RegisterArea;
        public uint Cr0NpxState;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct LDT_ENTRY
    {
        public ushort LimitLow;
        public ushort BaseLow;
        public LDT_ENTRY_HIGHWORD HighWord;
        public ushort BaseMid;
        public byte Flags1;
        public byte Flags2;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct LDT_ENTRY_HIGHWORD
    {
        public byte BaseMid;
        public byte Flags1;
        public byte Flags2;
        public byte BaseHi;
    }
}