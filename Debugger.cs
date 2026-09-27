using ActiveMark.Hook;
using ActiveMark.Native;
using System;
using System.IO;
using static ActiveMark.Native.Constants;
using Kernel32 = ActiveMark.Native.Kernel32;

namespace ActiveMark.Debugger
{
    public static class Memory
    {
        public static IntPtr ResolveTargetAddress(IntPtr hProcess, string moduleName, string functionName)
        {
            IntPtr[] modules = new IntPtr[1024];
            uint cbNeeded = 0;
            if (!Kernel32.EnumProcessModulesEx(hProcess, modules, (uint)(modules.Length * IntPtr.Size), out cbNeeded, Kernel32.LIST_MODULES_32BIT))
            {
                int error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                Console.WriteLine($"[Memory] EnumProcessModulesEx failed: 0x{error:X8}");
                return IntPtr.Zero;
            }

            int moduleCount = (int)(cbNeeded / (uint)IntPtr.Size);
            var sb = new System.Text.StringBuilder(260);

            for (int i = 0; i < moduleCount; i++)
            {
                if (Kernel32.GetModuleFileNameEx(hProcess, modules[i], sb, (uint)sb.Capacity) > 0)
                {
                    string fullPath = sb.ToString();
                    string name = System.IO.Path.GetFileName(fullPath);
                    if (string.Equals(name, moduleName, StringComparison.OrdinalIgnoreCase))
                    {
                        IntPtr funcAddr = Kernel32.GetProcAddress(modules[i], functionName);
                        if (funcAddr != IntPtr.Zero)
                        {
                            Kernel32.MODULEINFO modInfo = new Kernel32.MODULEINFO();
                            if (Kernel32.GetModuleInformation(Kernel32.GetCurrentProcess(), modules[i], out modInfo, (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(Kernel32.MODULEINFO))))
                            {
                                long offset = funcAddr.ToInt64() - modInfo.lpBaseOfDll.ToInt64();
                                IntPtr targetBase = modules[i];
                                return new IntPtr(targetBase.ToInt64() + offset);
                            }
                        }
                    }
                }
            }
            return IntPtr.Zero;
        }
    }

    public sealed class ActiveMarkFile
    {
        private readonly byte[] _scanByte = new byte[] { 0x00, 0x68 };
        private readonly byte[] _replByte = new byte[] { 0xCC };
        private readonly uint[] _dwordFInst = new uint[] { 0x8D006AF9, 0x8B575653 };
        private readonly uint[] _dwordFRepl = new uint[] { 0x900008C2, 0x90000CC2, 0x900004C2, 0x90000CC2, 0x900008C2 };
        private readonly uint[] _dwordPInst = new uint[] { 0x74617453, 0x64616F4C };
        private readonly uint[] _dwordPRepl = new uint[] { 0x909090C3 };

        public bool VerboseLogging { get; set; } = false;
        public HookManager HookManager { get; private set; } = new HookManager();

        public delegate void WhenLoadFinishedDelegate(IntPtr hProcess, IntPtr hThread, uint processId, uint threadId);
        public WhenLoadFinishedDelegate WhenLoadFinished;

        private void Log(string message)
        {
            if (VerboseLogging)
                Console.WriteLine($"[ActiveMark] {message}");
        }

        private void LogAlways(string message)
        {
            Console.WriteLine($"[ActiveMark] {message}");
        }

        public void RunLoader(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || filePath == "*.exe")
            {
                LogAlways("Invalid file path");
                return;
            }

            if (!File.Exists(filePath))
            {
                LogAlways($"File not found: {filePath}");
                return;
            }

            LogAlways($"Starting: {filePath}");

            string workingDir = Path.GetDirectoryName(filePath);
            if (string.IsNullOrEmpty(workingDir))
                workingDir = null;

            STARTUPINFO si = new STARTUPINFO { cb = (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(STARTUPINFO)) };
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            Log("Calling CreateProcess with DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS");

            if (!Kernel32.CreateProcess(filePath, null, IntPtr.Zero, IntPtr.Zero, false,
                DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS, IntPtr.Zero, workingDir, ref si, out pi))
            {
                int error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                LogAlways($"CreateProcess failed: 0x{error:X8} ({error})");
                return;
            }

            LogAlways($"Process created: PID={pi.dwProcessId}, TID={pi.dwThreadId}");

            bool continueAfterPatch = false;
            bool breaknow = false;
            bool setBP = false;
            bool fpatched = false;
            bool ppatched = false;
            IntPtr hModule = IntPtr.Zero;
            IntPtr procAddr = IntPtr.Zero;

            uint[] ExceptionAddress = new uint[1];
            uint[] AddressOfOffset = new uint[1];
            uint[] AddressOfSrch = new uint[1];
            uint[] AddressOfBase = new uint[1];
            uint[] DwordFAddr = new uint[1];
            uint[] DwordPAddr = new uint[1];

            byte[] byteRead = new byte[1];
            int dwRead = 0, dwWritten = 0;
            int i = 0, j = 0, k = 0;

            HookManager.Initialize(pi.hProcess);

            DEBUG_EVENT debugEv = new DEBUG_EVENT();
            bool contproc = true;
            uint dwContinueStatus = DBG_CONTINUE;
            uint dwTime = 1000;

            Log("Entering main debug loop");

            while (contproc)
            {
                if (!Kernel32.WaitForDebugEvent(out debugEv, dwTime))
                    continue;

                Log($"DebugEvent: Code={debugEv.dwDebugEventCode}, PID={debugEv.dwProcessId}, TID={debugEv.dwThreadId}");

                if (breaknow && IsWinXpPlus())
                {
                    if (setBP)
                    {
                        Kernel32.WriteProcessMemory(pi.hProcess, new IntPtr(ExceptionAddress[j]), new byte[] { _scanByte[j] }, 1, out dwWritten);
                        Log("Restored original byte at breakpoint");
                    }

                    if (HookManager.HasActiveHooks())
                    {
                        Log("Active hooks detected - continuing with extended debug loop");
                        continueAfterPatch = true;
                        contproc = true;
                        dwContinueStatus = DBG_CONTINUE;
                        dwTime = INFINITE;
                        breaknow = false;
                    }
                    else
                    {
                        Log("No active hooks - exiting debugger");
                        contproc = false;
                        breaknow = false;
                    }
                }

                if (!ProcessDebugEvent(ref debugEv, pi, ref contproc, ref dwContinueStatus, ref dwTime,
                    ref breaknow, ref setBP, ref fpatched, ref ppatched, ref i, ref j, ref k,
                    ref hModule, ref procAddr, ref ExceptionAddress, ref AddressOfOffset,
                    ref AddressOfSrch, ref AddressOfBase, ref DwordFAddr, ref DwordPAddr,
                    ref byteRead, ref dwRead, ref dwWritten))
                {
                    break;
                }

                Log($"Continuing debug event (status=0x{dwContinueStatus:X8})");
                Kernel32.ContinueDebugEvent(debugEv.dwProcessId, debugEv.dwThreadId, dwContinueStatus);
            }

            if (continueAfterPatch)
            {
                LogAlways("Entering extended debug loop for hooks");
                RunExtendedDebugLoop(pi);
            }

            Log("Cleaning up handles");
            Kernel32.CloseHandle(pi.hProcess);
            Kernel32.CloseHandle(pi.hThread);
            HookManager.Cleanup();

            if (ppatched && IsWinXpPlus() && hModule != IntPtr.Zero)
            {
                procAddr = Kernel32.GetProcAddress(hModule, "DebugActiveProcessStop");
                if (procAddr != IntPtr.Zero)
                {
                    var stopFunc = (Action<uint>)System.Runtime.InteropServices.Marshal
                        .GetDelegateForFunctionPointer(procAddr, typeof(Action<uint>));
                    stopFunc(pi.dwProcessId);
                    Log("Called DebugActiveProcessStop");
                }
            }

            LogAlways("Done");
        }

        private bool ProcessDebugEvent(
            ref DEBUG_EVENT debugEv,
            PROCESS_INFORMATION pi,
            ref bool contproc,
            ref uint dwContinueStatus,
            ref uint dwTime,
            ref bool breaknow,
            ref bool setBP,
            ref bool fpatched,
            ref bool ppatched,
            ref int i,
            ref int j,
            ref int k,
            ref IntPtr hModule,
            ref IntPtr procAddr,
            ref uint[] ExceptionAddress,
            ref uint[] AddressOfOffset,
            ref uint[] AddressOfSrch,
            ref uint[] AddressOfBase,
            ref uint[] DwordFAddr,
            ref uint[] DwordPAddr,
            ref byte[] byteRead,
            ref int dwRead,
            ref int dwWritten)
        {
            switch (debugEv.dwDebugEventCode)
            {
                case EXCEPTION_DEBUG_EVENT:
                    return HandleException(debugEv, pi, ref contproc, ref dwContinueStatus,
                        ref breaknow, ref setBP, ref fpatched, ref ppatched, ref i, ref j, ref k,
                        ref hModule, ref procAddr, ref ExceptionAddress, ref AddressOfOffset,
                        ref AddressOfSrch, ref AddressOfBase, ref DwordFAddr, ref DwordPAddr,
                        ref byteRead, ref dwRead, ref dwWritten);

                case CREATE_PROCESS_DEBUG_EVENT:
                    Log("CREATE_PROCESS_DEBUG_EVENT");
                    AddressOfBase[j] = (uint)debugEv.u.CreateProcessInfo.lpBaseOfImage.ToInt32();
                    ExceptionAddress[j] = (uint)debugEv.u.CreateProcessInfo.lpStartAddress.ToInt32();
                    Kernel32.ReadProcessMemory(pi.hProcess, debugEv.u.CreateProcessInfo.lpStartAddress, byteRead, 1, out dwRead);
                    _scanByte[j] = byteRead[0];
                    Kernel32.WriteProcessMemory(pi.hProcess, debugEv.u.CreateProcessInfo.lpStartAddress, _replByte, 1, out dwWritten);
                    Log($"Initial BP set at EP: 0x{ExceptionAddress[j]:X8}, original byte=0x{_scanByte[j]:X2}");
                    contproc = true;
                    dwContinueStatus = DBG_CONTINUE;
                    break;

                case LOAD_DLL_DEBUG_EVENT:
                    Log($"LOAD_DLL_DEBUG_EVENT: Base=0x{debugEv.u.LoadDll.lpBaseOfDll.ToInt32():X8}");
                    Kernel32.CloseHandle(debugEv.u.LoadDll.hFile);
                    contproc = true;
                    dwContinueStatus = DBG_CONTINUE;
                    break;

                case UNLOAD_DLL_DEBUG_EVENT:
                    Log($"UNLOAD_DLL_DEBUG_EVENT: Base=0x{debugEv.u.UnloadDll.lpBaseOfDll.ToInt32():X8}");
                    contproc = true;
                    dwContinueStatus = DBG_CONTINUE;
                    break;

                case OUTPUT_DEBUG_STRING_DEBUG_EVENT:
                    contproc = true;
                    dwContinueStatus = DBG_CONTINUE;
                    break;

                case CREATE_THREAD_DEBUG_EVENT:
                    Log($"CREATE_THREAD_DEBUG_EVENT: StartAddr=0x{debugEv.u.CreateThread.lpStartAddress.ToInt32():X8}");
                    contproc = true;
                    dwContinueStatus = DBG_CONTINUE;
                    break;

                case EXIT_THREAD_DEBUG_EVENT:
                    Log($"EXIT_THREAD_DEBUG_EVENT: ExitCode=0x{debugEv.u.ExitThread.dwExitCode:X8}");
                    contproc = true;
                    dwContinueStatus = DBG_CONTINUE;
                    break;

                case EXIT_PROCESS_DEBUG_EVENT:
                    LogAlways($"EXIT_PROCESS_DEBUG_EVENT: ExitCode=0x{debugEv.u.ExitProcess.dwExitCode:X8}");
                    contproc = false;
                    break;

                case RIP_EVENT:
                    LogAlways("RIP_EVENT: Fatal error");
                    contproc = false;
                    dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                    break;

                default:
                    Log($"UNKNOWN_DEBUG_EVENT: Code={debugEv.dwDebugEventCode}");
                    contproc = true;
                    dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                    break;
            }
            return contproc;
        }

        private bool HandleException(
            DEBUG_EVENT debugEv,
            PROCESS_INFORMATION pi,
            ref bool contproc,
            ref uint dwContinueStatus,
            ref bool breaknow,
            ref bool setBP,
            ref bool fpatched,
            ref bool ppatched,
            ref int i,
            ref int j,
            ref int k,
            ref IntPtr hModule,
            ref IntPtr procAddr,
            ref uint[] ExceptionAddress,
            ref uint[] AddressOfOffset,
            ref uint[] AddressOfSrch,
            ref uint[] AddressOfBase,
            ref uint[] DwordFAddr,
            ref uint[] DwordPAddr,
            ref byte[] byteRead,
            ref int dwRead,
            ref int dwWritten)
        {
            uint exceptionCode = debugEv.u.Exception.ExceptionRecord.ExceptionCode;
            uint firstChance = debugEv.u.Exception.dwFirstChance;
            IntPtr exceptionAddress = debugEv.u.Exception.ExceptionRecord.ExceptionAddress;

            Log($"Exception: Code=0x{exceptionCode:X8}, Addr=0x{exceptionAddress.ToInt32():X8}, FirstChance={firstChance}, i={i}, k={k}");

            HookManager.CheckHooks(debugEv, pi, ref contproc, ref dwContinueStatus);
            if (!contproc)
                return false;

            if (exceptionCode == CPP_EXCEPTION)
            {
                Log("C++ Exception (0xE06D7363) - passing to app handler");
                contproc = true;
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                return true;
            }

            switch (exceptionCode)
            {
                case EXCEPTION_ACCESS_VIOLATION:
                    Log($"ACCESS_VIOLATION: FirstChance={firstChance}");
                    if (firstChance != 0)
                    {
                        contproc = true;
                        dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                    }
                    else
                    {
                        contproc = false;
                    }
                    break;

                case EXCEPTION_BREAKPOINT:
                    k++;
                    Log($"BREAKPOINT #{k} at 0x{exceptionAddress.ToInt32():X8} (expected=0x{ExceptionAddress[j]:X8}, i={i})");

                    if (firstChance != 0)
                    {
                        contproc = true;

                        if (k > 1 && (uint)exceptionAddress.ToInt32() == ExceptionAddress[j])
                        {
                            Log($"Our breakpoint hit (stage i={i})");
                            CONTEXT context = new CONTEXT { ContextFlags = CONTEXT_FULL };
                            Kernel32.GetThreadContext(pi.hThread, ref context);
                            Kernel32.WriteProcessMemory(pi.hProcess, new IntPtr(ExceptionAddress[j]), new byte[] { _scanByte[j] }, 1, out dwWritten);
                            context.Eip = context.Eip - 1;
                            Kernel32.SetThreadContext(pi.hThread, ref context);

                            if (i == 0)
                            {
                                Log("Stage 0: Hit initial EP, switching to kernel32!GetVersion+6");
                                hModule = Kernel32.GetModuleHandle("kernel32.dll");
                                if (hModule == IntPtr.Zero) { Log("GetModuleHandle failed"); contproc = false; break; }

                                procAddr = Kernel32.GetProcAddress(hModule, "GetVersion");
                                if (procAddr == IntPtr.Zero) { Log("GetProcAddress failed"); contproc = false; break; }

                                ExceptionAddress[j] = (uint)procAddr.ToInt32() + 6;
                                Kernel32.ReadProcessMemory(pi.hProcess, new IntPtr(ExceptionAddress[j]), byteRead, 1, out dwRead);
                                _scanByte[j] = byteRead[0];
                                Kernel32.WriteProcessMemory(pi.hProcess, new IntPtr(ExceptionAddress[j]), _replByte, 1, out dwWritten);
                                Log($"BP moved to GetVersion+6: 0x{ExceptionAddress[j]:X8}, byte=0x{_scanByte[j]:X2}");
                                i++;
                                dwContinueStatus = DBG_CONTINUE;
                            }
                            else if (i == 1)
                            {
                                Log("Stage 1: Hit GetVersion+6, analyzing stack for 2nd layer EP");
                                setBP = false;
                                AddressOfOffset[j] = context.Esp + 4;
                                int[] dwordRead = new int[1];
                                Kernel32.ReadProcessMemory(pi.hProcess, new IntPtr(AddressOfOffset[j]), dwordRead, 4, out dwRead);

                                if (dwordRead[0] == (int)context.Edi)
                                {
                                    Kernel32.ReadProcessMemory(pi.hProcess, new IntPtr(context.Esp), dwordRead, 4, out dwRead);
                                    AddressOfOffset[j] = (uint)dwordRead[0];
                                    Log($"Stack check passed: ReturnAddr=0x{AddressOfOffset[j]:X8}, EDI=0x{context.Edi:X8}");

                                    if (AddressOfOffset[j] != 0)
                                    {
                                        AddressOfOffset[j] -= 44;
                                        AddressOfSrch[j] = AddressOfOffset[j];
                                        int n = (int)((AddressOfSrch[j] - AddressOfBase[j]) + 4096);
                                        Log($"2nd Layer EP estimated: 0x{AddressOfOffset[j]:X8}, search range: {n} bytes");

                                        for (int m = 0; m < 5; m++)
                                        {
                                            Log($"Searching dialog func {m + 1}/5");
                                            for (int l = 0; l < n; l++)
                                            {
                                                if (l >= n) { m = 5; break; }
                                                AddressOfSrch[j]--;
                                                Kernel32.ReadProcessMemory(pi.hProcess, new IntPtr(AddressOfSrch[j]), dwordRead, 4, out dwRead);

                                                if (dwordRead[0] == (int)_dwordFInst[0])
                                                {
                                                    AddressOfSrch[j] -= 4;
                                                    Kernel32.ReadProcessMemory(pi.hProcess, new IntPtr(AddressOfSrch[j]), dwordRead, 4, out dwRead);
                                                    if (dwordRead[0] == (int)_dwordFInst[1])
                                                    {
                                                        l = n;
                                                        AddressOfSrch[j] -= 16;
                                                        int[] repl = new int[] { (int)_dwordFRepl[m] };
                                                        Kernel32.WriteProcessMemory(pi.hProcess, new IntPtr(AddressOfSrch[j]), repl, 4, out dwWritten);
                                                        Log($"Patched dialog func {m + 1} at 0x{AddressOfSrch[j] + 16:X8} with 0x{_dwordFRepl[m]:X8}");
                                                        AddressOfSrch[j] -= 50;
                                                        fpatched = true;
                                                        DwordFAddr[j] = AddressOfSrch[j];
                                                    }
                                                }
                                            }
                                        }

                                        if (fpatched)
                                        {
                                            Log("All 5 dialog functions patched, searching for LoadStatePool...");
                                            AddressOfSrch[j] = DwordFAddr[j];
                                            n = (int)((AddressOfSrch[j] - AddressOfBase[j]) + 4096);

                                            for (int l = 0; l < n; l++)
                                            {
                                                AddressOfSrch[j]--;
                                                int[] dwordRead2 = new int[1];
                                                Kernel32.ReadProcessMemory(pi.hProcess, new IntPtr(AddressOfSrch[j]), dwordRead2, 4, out dwRead);

                                                if (dwordRead2[0] == (int)_dwordPInst[0])
                                                {
                                                    AddressOfSrch[j] -= 4;
                                                    Kernel32.ReadProcessMemory(pi.hProcess, new IntPtr(AddressOfSrch[j]), dwordRead2, 4, out dwRead);
                                                    if (dwordRead2[0] == (int)_dwordPInst[1])
                                                    {
                                                        l = n;
                                                        DwordPAddr[j] = AddressOfSrch[j];
                                                        Log($"Found LoadStatePool at 0x{DwordPAddr[j]:X8}");
                                                    }
                                                }
                                            }

                                            if (DwordPAddr[j] != 0)
                                            {
                                                Log($"Searching for PUSH LoadStatePool (0x{DwordPAddr[j]:X8})");
                                                n = (int)(AddressOfOffset[j] - AddressOfSrch[j]);
                                                for (int l = 0; l < n; l++)
                                                {
                                                    AddressOfSrch[j]++;
                                                    int[] dwordRead3 = new int[1];
                                                    Kernel32.ReadProcessMemory(pi.hProcess, new IntPtr(AddressOfSrch[j]), dwordRead3, 4, out dwRead);

                                                    if (dwordRead3[0] == (int)DwordPAddr[j])
                                                    {
                                                        AddressOfSrch[j]--;
                                                        Kernel32.ReadProcessMemory(pi.hProcess, new IntPtr(AddressOfSrch[j]), byteRead, 1, out dwRead);
                                                        if (byteRead[0] == _scanByte[1])
                                                        {
                                                            Log($"Found PUSH LoadStatePool at 0x{AddressOfSrch[j]:X8}");
                                                            l = n;
                                                            ExceptionAddress[j] = AddressOfSrch[j];
                                                            _scanByte[j] = byteRead[0];
                                                            Kernel32.WriteProcessMemory(pi.hProcess, new IntPtr(ExceptionAddress[j]), _replByte, 1, out dwWritten);
                                                            i++;
                                                            goto CONTINUE_EXCEPTION;
                                                        }
                                                    }
                                                }
                                                Log("PUSH LoadStatePool not found");
                                            }
                                            else
                                            {
                                                Log("LoadStatePool address not found");
                                                contproc = false;
                                            }
                                        }
                                        else
                                        {
                                            Log("Dialog functions not found - not ActiveMARK v5.x");
                                            contproc = false;
                                        }
                                    }
                                    else
                                    {
                                        Log("AddressOfOffset is 0, single stepping");
                                        SetSingleStep(pi.hThread);
                                    }
                                }
                                else
                                {
                                    Log($"Stack check failed: [ESP+4]=0x{dwordRead[0]:X8} != EDI=0x{context.Edi:X8}");
                                    SetSingleStep(pi.hThread);
                                }

                                dwContinueStatus = DBG_CONTINUE;
                            }
                            else if (i == 2)
                            {
                                Log("Stage 2: Hit PUSH LoadStatePool, patching to RET");
                                int[] dwordRead = new int[1];
                                Kernel32.ReadProcessMemory(pi.hProcess, new IntPtr(context.Esp), dwordRead, 4, out dwRead);

                                if (dwordRead[0] != 0)
                                {
                                    int[] repl = new int[] { (int)_dwordPRepl[0] };
                                    Kernel32.WriteProcessMemory(pi.hProcess, new IntPtr(dwordRead[0]), repl, 4, out dwWritten);
                                    Log($"Patched LoadStatePool at 0x{dwordRead[0]:X8} with RET (0x{_dwordPRepl[0]:X8})");
                                    ppatched = true; // patch finished
                                    breaknow = true;
                                }
                                else
                                {
                                    Log("LoadStatePool address not found on stack");
                                    contproc = false;
                                }
                            }

                            WhenLoadFinished?.Invoke(pi.hProcess, pi.hThread, pi.dwProcessId, pi.dwThreadId);

                        CONTINUE_EXCEPTION:
                            dwContinueStatus = DBG_CONTINUE;
                        }
                        else
                        {
                            HideDebugger(pi);
                            dwContinueStatus = DBG_CONTINUE;
                        }
                    }
                    else
                    {
                        contproc = false;
                    }
                    break;

                case EXCEPTION_SINGLE_STEP:
                    Log($"SINGLE_STEP: FirstChance={firstChance}, setBP={setBP}");
                    if (firstChance != 0)
                    {
                        ClearSingleStep(pi.hThread);
                        if (!setBP)
                        {
                            Kernel32.WriteProcessMemory(pi.hProcess, new IntPtr(ExceptionAddress[j]), _replByte, 1, out dwWritten);
                            setBP = true;
                        }
                        contproc = true;
                        dwContinueStatus = DBG_CONTINUE;
                    }
                    else
                    {
                        contproc = false;
                    }
                    break;

                default:
                    Log($"UNKNOWN_EXCEPTION: Code=0x{exceptionCode:X8}");
                    contproc = true;
                    dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                    break;
            }

            return contproc;
        }

        private void RunExtendedDebugLoop(PROCESS_INFORMATION pi)
        {
            DEBUG_EVENT debugEv = new DEBUG_EVENT();
            bool contproc = true;
            uint dwContinueStatus = DBG_CONTINUE;
            uint dwTime = INFINITE;

            while (contproc && HookManager.HasActiveHooks())
            {
                if (!Kernel32.WaitForDebugEvent(out debugEv, dwTime))
                    continue;

                Log($"[Extended] DebugEvent: Code={debugEv.dwDebugEventCode}");

                switch (debugEv.dwDebugEventCode)
                {
                    case EXCEPTION_DEBUG_EVENT:
                        HookManager.CheckHooks(debugEv, pi, ref contproc, ref dwContinueStatus);
                        if (!contproc) break;

                        uint exceptionCode = debugEv.u.Exception.ExceptionRecord.ExceptionCode;
                        uint firstChance = debugEv.u.Exception.dwFirstChance;

                        if (exceptionCode == EXCEPTION_ACCESS_VIOLATION)
                        {
                            if (firstChance != 0)
                            {
                                contproc = true;
                                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                            }
                            else
                            {
                                contproc = false;
                            }
                        }
                        else if (exceptionCode == CPP_EXCEPTION || exceptionCode == EXCEPTION_SINGLE_STEP)
                        {
                            contproc = true;
                            dwContinueStatus = DBG_CONTINUE;
                        }
                        else
                        {
                            contproc = true;
                            dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                        }
                        break;

                    case EXIT_PROCESS_DEBUG_EVENT:
                        LogAlways($"[Extended] EXIT_PROCESS: ExitCode=0x{debugEv.u.ExitProcess.dwExitCode:X8}");
                        contproc = false;
                        break;

                    case EXIT_THREAD_DEBUG_EVENT:
                        contproc = true;
                        dwContinueStatus = DBG_CONTINUE;
                        break;

                    case CREATE_THREAD_DEBUG_EVENT:
                        Log($"[Extended] CREATE_THREAD: StartAddr=0x{debugEv.u.CreateThread.lpStartAddress.ToInt32():X8}");
                        contproc = true;
                        dwContinueStatus = DBG_CONTINUE;
                        break;

                    case LOAD_DLL_DEBUG_EVENT:
                        Log($"[Extended] LOAD_DLL: Base=0x{debugEv.u.LoadDll.lpBaseOfDll.ToInt32():X8}");
                        contproc = true;
                        dwContinueStatus = DBG_CONTINUE;
                        Kernel32.CloseHandle(debugEv.u.LoadDll.hFile);
                        break;

                    case UNLOAD_DLL_DEBUG_EVENT:
                        Log($"[Extended] UNLOAD_DLL: Base=0x{debugEv.u.UnloadDll.lpBaseOfDll.ToInt32():X8}");
                        contproc = true;
                        dwContinueStatus = DBG_CONTINUE;
                        break;

                    default:
                        contproc = true;
                        dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                        break;
                }

                if (contproc)
                    Kernel32.ContinueDebugEvent(debugEv.dwProcessId, debugEv.dwThreadId, dwContinueStatus);
            }
            LogAlways("Extended debug loop ended");
        }

        private static bool SetSingleStep(IntPtr hThread)
        {
            CONTEXT context = new CONTEXT { ContextFlags = CONTEXT_CONTROL };
            if (!Kernel32.GetThreadContext(hThread, ref context))
                return false;
            context.EFlags |= 0x100;
            return Kernel32.SetThreadContext(hThread, ref context);
        }

        private static bool ClearSingleStep(IntPtr hThread)
        {
            CONTEXT context = new CONTEXT { ContextFlags = CONTEXT_CONTROL };
            if (!Kernel32.GetThreadContext(hThread, ref context))
                return false;
            context.EFlags = 0;
            return Kernel32.SetThreadContext(hThread, ref context);
        }

        private static void HideDebugger(PROCESS_INFORMATION pi)
        {
            Console.WriteLine("[ActiveMark] Hiding debugger (PEB.BeingDebugged = 0)");
            CONTEXT context = new CONTEXT { ContextFlags = CONTEXT_SEGMENTS };
            if (!Kernel32.GetThreadContext(pi.hThread, ref context))
                return;

            LDT_ENTRY sel;
            if (!Kernel32.GetThreadSelectorEntry(pi.hThread, context.SegFs, out sel))
                return;

            uint fsbase = (uint)(((sel.HighWord.BaseHi << 8) | sel.HighWord.BaseMid) << 16 | sel.BaseLow);
            int[] pebAddr = new int[1];
            int numRead = 0;
            if (!Kernel32.ReadProcessMemory(pi.hProcess, new IntPtr(fsbase + 0x30), pebAddr, 4, out numRead) || numRead != 4)
                return;

            byte[] beingDebugged = new byte[2];
            if (!Kernel32.ReadProcessMemory(pi.hProcess, new IntPtr(pebAddr[0] + 2), beingDebugged, 2, out numRead) || numRead != 2)
                return;

            beingDebugged[0] = 0;
            beingDebugged[1] = 0;

            int numWritten = 0;
            Kernel32.WriteProcessMemory(pi.hProcess, new IntPtr(pebAddr[0] + 2), beingDebugged, 2, out numWritten);
            Console.WriteLine("[ActiveMark] Debugger hidden");
        }

        private static bool IsWinXpPlus()
        {
            uint version = Kernel32.GetVersion();
            byte major = (byte)(version & 0xFF);
            return major >= 5 && (version & 0xFFFF) != 5;
        }
    }
}