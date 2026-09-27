using ActiveMark.Debugger;
using System;

namespace ActiveMark.Program
{
    internal static class Program
    {
        // ActiveMark File
        private readonly static ActiveMarkFile activeMarkFile = new ActiveMarkFile();

        private static void Main(string[] args)
        {
            Console.WriteLine("ActiveMARK v5.x Loader");
            Console.WriteLine("by iseeeva (based on ArTeam project)");
            Console.WriteLine("");

            string filePath = args.Length > 0 ? args[0] : PromptForPath();
            if (string.IsNullOrEmpty(filePath) || filePath == "*.exe")
            {
                Console.WriteLine("No valid file specified.");
                return;
            }

            activeMarkFile.VerboseLogging = false;
            activeMarkFile.WhenLoadFinished += OnPostPatchComplete;
            activeMarkFile.RunLoader(filePath);

            Console.WriteLine("Press any key to exit...");
            try { Console.ReadKey(); } catch { Console.ReadLine(); }
        }

        private static string PromptForPath()
        {
            Console.Write("Enter path to target: ");
            return Console.ReadLine();
        }

        private static void OnPostPatchComplete(IntPtr hProcess, IntPtr hThread, uint processId, uint threadId)
        {
            Console.WriteLine("[PostPatch] Loader patching complete. Adding hooks/patches...");
            //Kernel32.WriteProcessMemory(hProcess, new IntPtr(0x0047a0e1), new byte[] { 0x6F, 0x74, 0x75, 0x7A }, 4, out _);

            //IntPtr createFileAddr = Memory.ResolveTargetAddress(hProcess, "kernel32.dll", "CreateFileW");
            //if (createFileAddr != IntPtr.Zero)
            //{
            //    Console.WriteLine($"[PostPatch] CreateFileA @ 0x{createFileAddr.ToInt64():X8}");
            //    var hook = activeMarkFile.HookManager.AddHook((uint)createFileAddr.ToInt32(), OnCreateFileA, 6);
            //    if (hook != null)
            //        activeMarkFile.HookManager.Enable((uint)createFileAddr.ToInt32());
            //}
            //else
            //{
            //    Console.WriteLine("[PostPatch] Failed to resolve CreateFileA");
            //}

            Console.WriteLine("[PostPatch] All hooks/patches installed.");
        }

        //private static void OnCreateFileA(uint hookAddr, CONTEXT ctx, PROCESS_INFORMATION pi)
        //{
        //    int[] stack = new int[7];
        //    int dwRead;
        //    Kernel32.ReadProcessMemory(pi.hProcess, new IntPtr(ctx.Esp), stack, 28, out dwRead);
        //    string fileName = ReadString(pi.hProcess, (IntPtr)stack[0]);
        //    Console.WriteLine($"[Hook] CreateFileA: {fileName}");
        //}

        //private static string ReadString(IntPtr hProcess, IntPtr addr)
        //{
        //    byte[] buffer = new byte[260];
        //    int dwRead;
        //    Kernel32.ReadProcessMemory(hProcess, addr, buffer, buffer.Length, out dwRead);
        //    int nullIndex = Array.IndexOf(buffer, (byte)0);
        //    return nullIndex >= 0 ? Encoding.ASCII.GetString(buffer, 0, nullIndex) : Encoding.ASCII.GetString(buffer);
        //}
    }
}