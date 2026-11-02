using System.Diagnostics;
using System.Net;
using System.Security.Principal;
using NetFlow.Platform.Windows.Firewall;
using NetFlow.Platform.Windows.Native;

namespace NetFlow.Platform.Windows.Defense;

public class KillProcessResult
{
    public bool Success { get; set; }
    public int Pid { get; set; }
    public string? ProcessName { get; set; }
    public string? Error { get; set; }
    public bool ElevationRequired { get; set; }
    public int? Win32Error { get; set; }
}

public class SeverConnectionResult
{
    public bool Success { get; set; }
    public int SeveredCount { get; set; }
    public string? RemoteIp { get; set; }
    public int? RemotePort { get; set; }
    public string? Error { get; set; }
    public bool ElevationRequired { get; set; }
    public uint? Win32Error { get; set; }
}

public class BlockIpResult
{
    public bool Success { get; set; }
    public string RuleName { get; set; } = string.Empty;
    public string Ip { get; set; } = string.Empty;
    public int SeveredConnectionCount { get; set; }
    public string? Error { get; set; }
    public bool ElevationRequired { get; set; }
}

public class UnblockIpResult
{
    public bool Success { get; set; }
    public string Ip { get; set; } = string.Empty;
    public string? Error { get; set; }
    public bool ElevationRequired { get; set; }
}

public class DefenseStatusResult
{
    public bool IsAdmin { get; set; }
    public bool ElevationRequired { get; set; }
    public string UserIdentity { get; set; } = string.Empty;
}

public interface IActiveDefenseManager
{
    bool IsElevated();
    DefenseStatusResult GetStatus();
    KillProcessResult KillProcess(int pid, uint exitCode = 1);
    SeverConnectionResult SeverConnection(string? remoteIp, int? remotePort, string? localIp = null, int? localPort = null, int? pid = null);
    BlockIpResult BlockIp(string ip, string? reason = null);
    UnblockIpResult UnblockIp(string ip);
}

public class ActiveDefenseManager : IActiveDefenseManager
{
    private readonly WindowsFirewallEngine _firewallEngine;

    public ActiveDefenseManager(WindowsFirewallEngine firewallEngine)
    {
        _firewallEngine = firewallEngine ?? throw new ArgumentNullException(nameof(firewallEngine));
    }

    public static bool IsAdmin()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    public bool IsElevated() => IsAdmin();

    public DefenseStatusResult GetStatus()
    {
        bool isAdmin = IsAdmin();
        string name = string.Empty;
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            name = id.Name;
        }
        catch { }

        return new DefenseStatusResult
        {
            IsAdmin = isAdmin,
            ElevationRequired = !isAdmin,
            UserIdentity = name
        };
    }

    public KillProcessResult KillProcess(int pid, uint exitCode = 1)
    {
        if (pid <= 0)
        {
            return new KillProcessResult
            {
                Success = false,
                Pid = pid,
                Error = "Invalid process ID. PID must be greater than zero.",
                ElevationRequired = false,
                Win32Error = 87 // ERROR_INVALID_PARAMETER
            };
        }

        if (pid <= 4)
        {
            return new KillProcessResult
            {
                Success = false,
                Pid = pid,
                ProcessName = "System",
                Error = "Cannot terminate critical system kernel process (PID <= 4).",
                ElevationRequired = false,
                Win32Error = 5 // ERROR_ACCESS_DENIED
            };
        }

        if (pid == Environment.ProcessId)
        {
            return new KillProcessResult
            {
                Success = false,
                Pid = pid,
                Error = "Cannot terminate NetFlow host process.",
                ElevationRequired = false,
                Win32Error = 87
            };
        }

        string procName = string.Empty;
        try
        {
            string exePath = Kernel32.GetProcessExecutablePath(pid);
            procName = Path.GetFileName(exePath);
            if (string.IsNullOrEmpty(procName))
            {
                using var p = Process.GetProcessById(pid);
                procName = p.ProcessName;
            }
        }
        catch { }

        // Genuine P/Invoke termination attempt
        var (success, win32Error, error) = Kernel32.TerminateProcessById(pid, exitCode);

        if (success)
        {
            return new KillProcessResult
            {
                Success = true,
                Pid = pid,
                ProcessName = procName,
                Error = null,
                ElevationRequired = false
            };
        }

        bool elevationReq = !IsAdmin() && (win32Error == 5 || win32Error == 0);
        string detailedError;

        if (elevationReq)
        {
            detailedError = $"Administrator privileges required to terminate process '{procName}' (PID {pid}). Win32 error code 5 (Access Denied).";
        }
        else if (win32Error == 5)
        {
            detailedError = $"Access denied (Win32 error 5). Process '{procName}' (PID {pid}) is protected by Windows Security or anti-malware service.";
        }
        else
        {
            detailedError = error ?? $"Failed to terminate process PID {pid} (Win32 error {win32Error}).";
        }

        return new KillProcessResult
        {
            Success = false,
            Pid = pid,
            ProcessName = procName,
            Error = detailedError,
            ElevationRequired = elevationReq,
            Win32Error = win32Error
        };
    }

    public SeverConnectionResult SeverConnection(
        string? remoteIp,
        int? remotePort,
        string? localIp = null,
        int? localPort = null,
        int? pid = null)
    {
        try
        {
            var (severedCount, lastError) = IpHlpApi.SeverSockets(remoteIp, remotePort, localIp, localPort, pid);

            if (severedCount > 0)
            {
                return new SeverConnectionResult
                {
                    Success = true,
                    SeveredCount = severedCount,
                    RemoteIp = remoteIp,
                    RemotePort = remotePort,
                    Error = null,
                    ElevationRequired = false
                };
            }

            if (lastError == 5 || (!IsAdmin() && lastError != 0))
            {
                return new SeverConnectionResult
                {
                    Success = false,
                    SeveredCount = 0,
                    RemoteIp = remoteIp,
                    RemotePort = remotePort,
                    Error = "Administrator privileges required to sever active network sockets via SetTcpEntry.",
                    ElevationRequired = true,
                    Win32Error = lastError
                };
            }

            if (lastError != 0)
            {
                return new SeverConnectionResult
                {
                    Success = false,
                    SeveredCount = 0,
                    RemoteIp = remoteIp,
                    RemotePort = remotePort,
                    Error = $"SetTcpEntry returned Win32 error {lastError}.",
                    ElevationRequired = false,
                    Win32Error = lastError
                };
            }

            return new SeverConnectionResult
            {
                Success = true,
                SeveredCount = 0,
                RemoteIp = remoteIp,
                RemotePort = remotePort,
                Error = null,
                ElevationRequired = false
            };
        }
        catch (Exception ex)
        {
            return new SeverConnectionResult
            {
                Success = false,
                SeveredCount = 0,
                RemoteIp = remoteIp,
                RemotePort = remotePort,
                Error = $"Exception while severing socket: {ex.Message}",
                ElevationRequired = !IsAdmin()
            };
        }
    }

    public BlockIpResult BlockIp(string ip, string? reason = null)
    {
        if (string.IsNullOrWhiteSpace(ip) || !IPAddress.TryParse(ip.Trim(), out var parsedIp))
        {
            return new BlockIpResult
            {
                Success = false,
                RuleName = string.Empty,
                Ip = ip,
                SeveredConnectionCount = 0,
                Error = $"Invalid IP address format: '{ip}'.",
                ElevationRequired = false
            };
        }

        string cleanIp = parsedIp.ToString();

        // 1. Automatically sever any active connections to this IP
        int severedCount = 0;
        try
        {
            var (count, _) = IpHlpApi.SeverSockets(remoteIp: cleanIp);
            severedCount = count;
        }
        catch { }

        // 2. Add firewall block rule
        var res = _firewallEngine.BlockIp(cleanIp, reason);
        bool elevationRequired = res.ElevationRequired || (!IsAdmin() && !res.Success);

        return new BlockIpResult
        {
            Success = res.Success,
            RuleName = res.RuleName,
            Ip = cleanIp,
            SeveredConnectionCount = severedCount,
            Error = res.Error,
            ElevationRequired = elevationRequired
        };
    }

    public UnblockIpResult UnblockIp(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip) || !IPAddress.TryParse(ip.Trim(), out var parsedIp))
        {
            return new UnblockIpResult
            {
                Success = false,
                Ip = ip,
                Error = $"Invalid IP address format: '{ip}'.",
                ElevationRequired = false
            };
        }

        string cleanIp = parsedIp.ToString();
        var res = _firewallEngine.UnblockIp(cleanIp);
        bool elevationRequired = res.ElevationRequired || (!IsAdmin() && !res.Success);

        return new UnblockIpResult
        {
            Success = res.Success,
            Ip = cleanIp,
            Error = res.Error,
            ElevationRequired = elevationRequired
        };
    }
}
