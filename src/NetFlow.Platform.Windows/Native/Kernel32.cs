using System.Runtime.InteropServices;
using System.Text;

namespace NetFlow.Platform.Windows.Native;

public static class Kernel32
{
    public const uint PROCESS_TERMINATE = 0x0001;
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_SET_INFORMATION = 0x0200;

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool QueryFullProcessImageName(
        IntPtr hProcess,
        int dwFlags,
        [Out] StringBuilder lpExeName,
        ref int lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetProcessIoCounters(IntPtr ProcessHandle, out IO_COUNTERS IoCounters);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetPriorityClass(IntPtr hProcess, uint dwPriorityClass);

    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern int NtSetInformationProcess(IntPtr hProcess, int processInformationClass, ref int processInformation, int processInformationLength);

    [DllImport("wininet.dll", SetLastError = true)]
    public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

    public const int INTERNET_OPTION_SETTINGS_CHANGED = 39;
    public const int INTERNET_OPTION_REFRESH = 37;

    public const uint HIGH_PRIORITY_CLASS = 0x00000080;
    public const uint ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000;
    public const uint NORMAL_PRIORITY_CLASS = 0x00000020;
    public const uint BELOW_NORMAL_PRIORITY_CLASS = 0x00004000;
    public const uint IDLE_PRIORITY_CLASS = 0x00000040;

    public const int ProcessIoPriorityClass = 33;
    public const int IoPriorityVeryLow = 0;
    public const int IoPriorityLow = 1;
    public const int IoPriorityNormal = 2;
    public const int IoPriorityHigh = 3;

    public static string GetProcessExecutablePath(int pid)
    {
        if (pid <= 0) return "System Idle Process";
        if (pid == 4) return "Windows Kernel (ntoskrnl.exe)";

        IntPtr hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProc == IntPtr.Zero)
        {
            hProc = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
        }

        if (hProc != IntPtr.Zero)
        {
            try
            {
                var sb = new StringBuilder(1024);
                int size = sb.Capacity;
                if (QueryFullProcessImageName(hProc, 0, sb, ref size))
                {
                    return sb.ToString();
                }
            }
            finally
            {
                CloseHandle(hProc);
            }
        }

        return string.Empty;
    }

    public static bool QueryProcessIo(int pid, out ulong readBytes, out ulong writeBytes)
    {
        readBytes = 0;
        writeBytes = 0;
        if (pid <= 4) return false;

        IntPtr hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProc == IntPtr.Zero)
        {
            hProc = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
        }

        if (hProc != IntPtr.Zero)
        {
            try
            {
                if (GetProcessIoCounters(hProc, out IO_COUNTERS counters))
                {
                    readBytes = counters.ReadTransferCount;
                    writeBytes = counters.WriteTransferCount;
                    return true;
                }
            }
            finally
            {
                CloseHandle(hProc);
            }
        }

        return false;
    }

    public static (bool Success, int Win32Error, string? Error) TerminateProcessById(int pid, uint exitCode = 1)
    {
        if (pid <= 0)
        {
            return (false, 87, "Invalid process ID.");
        }

        if (pid <= 4)
        {
            return (false, 5, "Cannot terminate critical system kernel process.");
        }

        if (pid == Environment.ProcessId)
        {
            return (false, 87, "Cannot terminate NetFlow host process.");
        }

        IntPtr hProc = OpenProcess(PROCESS_TERMINATE, false, pid);
        if (hProc == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            return (false, err, $"Failed to open process PID {pid} for termination (Win32 error {err}).");
        }

        try
        {
            if (TerminateProcess(hProc, exitCode))
            {
                return (true, 0, null);
            }

            int err = Marshal.GetLastWin32Error();
            return (false, err, $"TerminateProcess failed for PID {pid} (Win32 error {err}).");
        }
        finally
        {
            CloseHandle(hProc);
        }
    }
}
