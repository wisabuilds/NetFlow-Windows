using System.Collections.Concurrent;
using System.Diagnostics;
using NetFlow.Core.Models;
using NetFlow.Core.Services;
using NetFlow.Platform.Windows.Native;

namespace NetFlow.Platform.Windows.Services;

public class WindowsSocketProvider : ISocketProvider
{
    public List<SocketInfo> GetEnrichedSockets() => WindowsProcessReader.GetEnrichedSockets();

    public bool TryGetProcessIo(int pid, out ulong readBytes, out ulong writeBytes)
    {
        return Kernel32.QueryProcessIo(pid, out readBytes, out writeBytes);
    }

    public bool TryGetProcessNetworkBytes(int pid, out ulong rxBytes, out ulong txBytes)
    {
        return WindowsKernelNetworkEtwSession.Instance.TryGetProcessNetworkBytes(pid, out rxBytes, out txBytes);
    }

    public bool IsEtwElevated => WindowsKernelNetworkEtwSession.Instance.IsElevatedAndActive;
}

public class WindowsProcessReader
{
    private static readonly ConcurrentDictionary<int, (string Name, string Path, DateTime Expiry)> _processCache = new();
    private static readonly TimeSpan CacheDuration = TimeSpan.FromSeconds(30);

    public static (string Name, string Path) GetProcessDetails(int pid)
    {
        if (pid <= 0) return ("System Idle Process", "System");
        if (pid == 4) return ("System", "Windows Kernel (ntoskrnl.exe)");

        if (_processCache.TryGetValue(pid, out var cached) && DateTime.UtcNow < cached.Expiry)
        {
            return (cached.Name, cached.Path);
        }

        string name = $"pid:{pid}";
        string path = "";

        // First attempt via Kernel32 QueryFullProcessImageName (works across security boundaries)
        string fullPath = Kernel32.GetProcessExecutablePath(pid);
        if (!string.IsNullOrEmpty(fullPath))
        {
            path = fullPath;
            name = Path.GetFileNameWithoutExtension(fullPath);
        }
        else
        {
            try
            {
                using var proc = Process.GetProcessById(pid);
                name = proc.ProcessName;
                try
                {
                    path = proc.MainModule?.FileName ?? "";
                }
                catch
                {
                    path = name;
                }
            }
            catch
            {
                name = $"exited:{pid}";
            }
        }

        _processCache[pid] = (name, path, DateTime.UtcNow.Add(CacheDuration));
        return (name, path);
    }

    public static List<SocketInfo> GetEnrichedSockets()
    {
        var rawSockets = IpHlpApi.GetAllSockets();
        var resolver = DnsResolver.Instance;

        foreach (var s in rawSockets)
        {
            if (s.Pid.HasValue)
            {
                var (name, path) = GetProcessDetails(s.Pid.Value);
                s.ProcessName = name;
                s.Cmdline = path;
            }

            s.Scope = DnsResolver.ClassifyScope(s.RemoteIp);
            if (s.Scope == "WAN" && !string.IsNullOrEmpty(s.RemoteIp))
            {
                s.ResolvedHostname = resolver.Resolve(s.RemoteIp);
            }
            else
            {
                s.ResolvedHostname = s.RemoteIp;
            }

            // Milestone 2 GeoIP & ASN Enrichment
            NetFlow.Core.Telemetry.GeoIpService.Instance.Enrich(s);
        }

        return rawSockets;
    }
}
