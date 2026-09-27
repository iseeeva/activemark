using ActiveMark.Native;
using System;
using System.Collections.Generic;
using static ActiveMark.Native.Constants;

namespace ActiveMark.Hook
{
    public delegate void HookCallback(uint hookAddress, CONTEXT context, PROCESS_INFORMATION pi);

    public sealed class DetourHook
    {
        public uint TargetAddress { get; }
        public byte[] OriginalBytes { get; }
        public byte[] DetourBytes { get; }
        public HookCallback HookCallback { get; }
        public bool IsEnabled { get; private set; }
        public IntPtr TrampolineAddress { get; }
        public int OriginalLength { get; }

        internal DetourHook(uint address, byte[] originalBytes, byte[] detourBytes, HookCallback callback, IntPtr trampoline, int originalLength)
        {
            TargetAddress = address;
            OriginalBytes = originalBytes;
            DetourBytes = detourBytes;
            HookCallback = callback;
            TrampolineAddress = trampoline;
            OriginalLength = originalLength;
            IsEnabled = false;
        }

        public void Enable(IntPtr hProcess)
        {
            if (IsEnabled) return;
            int dwWritten;
            Kernel32.WriteProcessMemory(hProcess, new IntPtr(TargetAddress), DetourBytes, DetourBytes.Length, out dwWritten);
            IsEnabled = true;
        }

        public void Disable(IntPtr hProcess)
        {
            if (!IsEnabled) return;
            int dwWritten;
            Kernel32.WriteProcessMemory(hProcess, new IntPtr(TargetAddress), OriginalBytes, OriginalBytes.Length, out dwWritten);
            IsEnabled = false;
        }

        public void Remove(IntPtr hProcess)
        {
            Disable(hProcess);
            if (TrampolineAddress != IntPtr.Zero)
            {
                Kernel32.VirtualFreeEx(hProcess, TrampolineAddress, 0, MEM_RELEASE);
            }
        }
    }

    public class HookManager
    {
        private readonly Dictionary<uint, DetourHook> _hooks = new Dictionary<uint, DetourHook>();
        private readonly object _lock = new object();
        private IntPtr _hProcess = IntPtr.Zero;

        public void Initialize(IntPtr hProcess)
        {
            _hProcess = hProcess;
        }

        public DetourHook AddHook(uint address, HookCallback callback, int minLength = 5)
        {
            lock (_lock)
            {
                if (_hooks.ContainsKey(address))
                    return _hooks[address];

                if (_hProcess == IntPtr.Zero)
                    return null;

                byte[] originalBytes = new byte[minLength];
                int dwRead;
                if (!Kernel32.ReadProcessMemory(_hProcess, new IntPtr(address), originalBytes, minLength, out dwRead) || dwRead != minLength)
                    return null;

                IntPtr trampoline = Kernel32.VirtualAllocEx(_hProcess, IntPtr.Zero, 0x1000,
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

                if (trampoline == IntPtr.Zero)
                    return null;

                var trampolineCode = new List<byte>();
                trampolineCode.AddRange(originalBytes);

                uint returnAddr = address + (uint)minLength;
                uint trampolineEnd = (uint)trampoline.ToInt32() + (uint)trampolineCode.Count;
                int relOffset = (int)(returnAddr - trampolineEnd - 5);

                trampolineCode.Add(0xE9);
                trampolineCode.AddRange(BitConverter.GetBytes(relOffset));

                int dwWritten;
                if (!Kernel32.WriteProcessMemory(_hProcess, trampoline, trampolineCode.ToArray(), trampolineCode.Count, out dwWritten))
                {
                    Kernel32.VirtualFreeEx(_hProcess, trampoline, 0, MEM_RELEASE);
                    return null;
                }

                byte[] detourBytes = new byte[minLength];
                uint detourTarget = (uint)trampoline.ToInt32();
                int detourOffset = (int)(detourTarget - address - 5);

                detourBytes[0] = 0xE9;
                Array.Copy(BitConverter.GetBytes(detourOffset), 0, detourBytes, 1, 4);
                for (int i = 5; i < minLength; i++)
                    detourBytes[i] = 0x90;

                var hook = new DetourHook(address, originalBytes, detourBytes, callback, trampoline, minLength);
                _hooks[address] = hook;
                return hook;
            }
        }

        public bool Enable(uint address)
        {
            lock (_lock)
            {
                if (_hooks.TryGetValue(address, out var hook))
                {
                    hook.Enable(_hProcess);
                    return true;
                }
                return false;
            }
        }

        public bool Disable(uint address)
        {
            lock (_lock)
            {
                if (_hooks.TryGetValue(address, out var hook))
                {
                    hook.Disable(_hProcess);
                    return true;
                }
                return false;
            }
        }

        public bool Remove(uint address)
        {
            lock (_lock)
            {
                if (_hooks.TryGetValue(address, out var hook))
                {
                    hook.Remove(_hProcess);
                    _hooks.Remove(address);
                    return true;
                }
                return false;
            }
        }

        public DetourHook Get(uint address)
        {
            lock (_lock)
            {
                _hooks.TryGetValue(address, out var hook);
                return hook;
            }
        }

        internal void CheckHooks(DEBUG_EVENT debugEv, PROCESS_INFORMATION pi, ref bool contproc, ref uint dwContinueStatus)
        {
            lock (_lock)
            {
                uint addr = (uint)debugEv.u.Exception.ExceptionRecord.ExceptionAddress.ToInt32();

                foreach (var kvp in _hooks)
                {
                    var hook = kvp.Value;
                    if (hook.IsEnabled && addr == hook.TargetAddress)
                    {
                        CONTEXT context = new CONTEXT { ContextFlags = CONTEXT_FULL };
                        Kernel32.GetThreadContext(pi.hThread, ref context);

                        try
                        {
                            hook.HookCallback(hook.TargetAddress, context, pi);
                        }
                        catch { }

                        context.Eip = (uint)hook.TrampolineAddress.ToInt32();
                        Kernel32.SetThreadContext(pi.hThread, ref context);

                        dwContinueStatus = DBG_CONTINUE;
                        contproc = true;
                        break;
                    }
                }
            }
        }

        public bool HasActiveHooks()
        {
            lock (_lock)
            {
                foreach (var hook in _hooks.Values)
                    if (hook.IsEnabled)
                        return true;
                return false;
            }
        }

        public void Cleanup()
        {
            lock (_lock)
            {
                foreach (var hook in _hooks.Values)
                    hook.Remove(_hProcess);
                _hooks.Clear();
            }
        }
    }
}