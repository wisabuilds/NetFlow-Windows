using System.Diagnostics;
using NetFlow.Core.Models;
using NetFlow.Core.Services;
using NetFlow.Core.Storage;
using NetFlow.Platform.Windows.Native;
using NetFlow.Platform.Windows.Services;

namespace NetFlow.Platform.Windows.Firewall;

public class WindowsFirewallEngine : IFirewallEngine
{
    private readonly NetflowStorage _storage;
    private readonly object _lock = new();
    private Dictionary<string, string> _policies = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, double> _lastNotification = new(StringComparer.OrdinalIgnoreCase);
    private int _totalBlocked;

    public bool IsEnabled { get; private set; } = true;

    public WindowsFirewallEngine(NetflowStorage storage)
    {
        _storage = storage;
        LoadRules();
    }

    public void LoadRules()
    {
        lock (_lock)
        {
            _policies = _storage.GetFirewallPolicies();
        }
    }

    public bool ToggleFirewall(bool? enabled = null)
    {
        lock (_lock)
        {
            IsEnabled = enabled ?? !IsEnabled;
            return IsEnabled;
        }
    }

    public static string SanitizeProcessName(string processName)
    {
        if (string.IsNullOrWhiteSpace(processName)) return string.Empty;
        string trimmed = processName.Trim().Trim('\"', '\'');
        string clean = Path.GetFileNameWithoutExtension(trimmed);

        // Stop at any command separator, redirect, or quote metacharacter
        int sepIdx = clean.IndexOfAny(new[] { '"', '\'', '&', '|', ';', '<', '>', '^', '`', '\n', '\r' });
        if (sepIdx >= 0)
        {
            clean = clean.Substring(0, sepIdx);
        }

        var sb = new System.Text.StringBuilder();
        foreach (char c in clean)
        {
            if (char.IsLetterOrDigit(c) || c == '-' || c == '_' || c == '.' || c == ' ')
            {
                sb.Append(c);
            }
        }
        return sb.ToString().Trim();
    }

    public string GetAppPolicy(string processName)
    {
        if (!IsEnabled) return "allow";
        string clean = SanitizeProcessName(processName);
        if (string.IsNullOrEmpty(clean)) return "allow";
        lock (_lock)
        {
            return _policies.TryGetValue(clean, out var pol) ? pol : "allow";
        }
    }

    public bool IsAppBlocked(string processName)
    {
        var pol = GetAppPolicy(processName);
        return pol is "block" or "lan_only";
    }

    public string SetAppPolicy(string processName, string policy)
    {
        string clean = SanitizeProcessName(processName);
        if (string.IsNullOrEmpty(clean)) return policy;

        lock (_lock)
        {
            bool blocked = policy is "block" or "lan_only";
            _policies[clean] = policy;
            _storage.SetFirewallRule(clean, blocked, policy);

            // Optional OS firewall sync
            SyncWindowsFirewallRule(clean, policy);

            return policy;
        }
    }

    public int ClearAllBlocks()
    {
        List<string> procNames;
        lock (_lock)
        {
            procNames = new List<string>(_policies.Keys);
            _policies.Clear();
            _storage.ClearFirewallRules();
        }

        Task.Run(() =>
        {
            try
            {
                foreach (var name in procNames)
                {
                    string safeName = SanitizeProcessName(name);
                    if (string.IsNullOrEmpty(safeName)) continue;
                    RunNetsh($"advfirewall firewall delete rule name=\"NetFlow_{safeName}\"");
                    RunNetsh($"advfirewall firewall delete rule name=\"NetFlow_{safeName}_in\"");
                    RunNetsh($"advfirewall firewall delete rule name=\"NetFlow_{safeName}.exe\"");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error during ClearAllBlocks netsh execution: {ex.Message}");
            }
        });

        return procNames.Count;
    }

    public Dictionary<string, object> GetStatus()
    {
        lock (_lock)
        {
            return new Dictionary<string, object>
            {
                ["enabled"] = IsEnabled,
                ["total_blocked"] = _totalBlocked,
                ["rules_count"] = _policies.Count,
                ["policies"] = new Dictionary<string, string>(_policies)
            };
        }
    }

    public List<Dictionary<string, object>> Enforce(List<SocketInfo> activeSockets, List<ProcessBandwidth> activeProcesses)
    {
        double now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var interceptions = new List<Dictionary<string, object>>();

        // 1. First-Seen Detection
        foreach (var p in activeProcesses)
        {
            if (string.IsNullOrWhiteSpace(p.Name) || p.Name == "System") continue;
            string clean = Path.GetFileNameWithoutExtension(p.Name);
            bool isFirstSeen = _storage.MarkOrCheckFirstSeen(clean, p.Cmdline);
            if (isFirstSeen)
            {
                _storage.LogFirewallEvent(clean, p.Pid, "first-connection", "FIRST_SEEN");
                WindowsNotifier.SendNotification("NetFlow: New Application", $"Discovered '{clean}' (PID: {p.Pid}) connecting for the first time.");
            }
        }

        if (!IsEnabled) return interceptions;

        Dictionary<string, string> policiesCopy;
        lock (_lock)
        {
            policiesCopy = new Dictionary<string, string>(_policies, StringComparer.OrdinalIgnoreCase);
        }

        if (policiesCopy.Count == 0) return interceptions;

        foreach (var s in activeSockets)
        {
            if (string.IsNullOrWhiteSpace(s.ProcessName) || s.ProcessName == "System") continue;

            string clean = Path.GetFileNameWithoutExtension(s.ProcessName);
            if (!policiesCopy.TryGetValue(clean, out string? pol) || pol == "allow")
            {
                continue;
            }

            string remoteIp = s.RemoteIp;
            string remoteStr = $"{remoteIp}:{s.RemotePort}";
            bool shouldBlock = false;
            string action = "BLOCKED";

            if (pol == "block")
            {
                shouldBlock = true;
                action = "BLOCKED";
            }
            else if (pol == "lan_only")
            {
                if (!string.IsNullOrEmpty(remoteIp) && !DnsResolver.IsLanOrLocal(remoteIp))
                {
                    shouldBlock = true;
                    action = "BLOCKED_WAN";
                }
            }

            if (shouldBlock)
            {
                IpHlpApi.SeverTcpConnection(s.RemoteIp, s.RemotePort);
                Interlocked.Increment(ref _totalBlocked);

                var evt = new Dictionary<string, object>
                {
                    ["process_name"] = clean,
                    ["pid"] = s.Pid ?? 0,
                    ["remote_endpoint"] = remoteStr,
                    ["timestamp"] = now,
                    ["action"] = action
                };
                interceptions.Add(evt);
                _storage.LogFirewallEvent(clean, s.Pid, remoteStr, action);

                lock (_lock)
                {
                    if (!_lastNotification.TryGetValue(clean, out double lastTime) || (now - lastTime > 10))
                    {
                        _lastNotification[clean] = now;
                        string reason = action == "BLOCKED_WAN" ? "WAN Restricted (LAN Only)" : "Firewall Blocked";
                        WindowsNotifier.SendNotification($"Firewall: {reason}", $"Severed {clean} stream to {remoteStr}");
                    }
                }
            }
        }

        return interceptions;
    }

    public static string? ResolveProcessExecutablePath(string processName)
    {
        if (string.IsNullOrWhiteSpace(processName)) return null;

        string cleanName = Path.GetFileNameWithoutExtension(processName.Trim().Trim('\"', '\''));

        // 1. If it's already an existing full path
        string directPath = processName.Trim().Trim('\"', '\'');
        if (File.Exists(directPath))
        {
            return Path.GetFullPath(directPath);
        }

        // 2. Try looking up in currently running processes (using Kernel32 cross-boundary check first)
        try
        {
            var procs = Process.GetProcessesByName(cleanName);
            foreach (var p in procs)
            {
                try
                {
                    string kPath = Kernel32.GetProcessExecutablePath(p.Id);
                    if (!string.IsNullOrEmpty(kPath) && File.Exists(kPath))
                    {
                        return kPath;
                    }

                    string? path = p.MainModule?.FileName;
                    if (!string.IsNullOrEmpty(path) && File.Exists(path))
                    {
                        return path;
                    }
                }
                catch { }
                finally
                {
                    p.Dispose();
                }
            }
        }
        catch { }

        // 3. Search App Paths registry keys (handling quoted registry values)
        try
        {
            using var hklmKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{cleanName}.exe");
            string? appPath = (hklmKey?.GetValue(null) as string)?.Trim('\"', ' ');
            if (!string.IsNullOrEmpty(appPath) && File.Exists(appPath))
            {
                return appPath;
            }

            using var hkcuKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey($@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{cleanName}.exe");
            string? cuAppPath = (hkcuKey?.GetValue(null) as string)?.Trim('\"', ' ');
            if (!string.IsNullOrEmpty(cuAppPath) && File.Exists(cuAppPath))
            {
                return cuAppPath;
            }
        }
        catch { }

        // 4. Search PATH environment variable directories
        try
        {
            string? pathEnv = Environment.GetEnvironmentVariable("PATH");
            if (!string.IsNullOrEmpty(pathEnv))
            {
                foreach (var p in pathEnv.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
                {
                    try
                    {
                        string candidate = Path.Combine(p.Trim('\"', ' '), $"{cleanName}.exe");
                        if (File.Exists(candidate)) return candidate;
                    }
                    catch { }
                }
            }
        }
        catch { }

        // 5. Check standard system directories
        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64"),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs")
        };

        foreach (var dir in searchDirs)
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;

            string candidate = Path.Combine(dir, $"{cleanName}.exe");
            if (File.Exists(candidate)) return candidate;

            string subCandidate = Path.Combine(dir, cleanName, $"{cleanName}.exe");
            if (File.Exists(subCandidate)) return subCandidate;
        }

        return null;
    }

    private void SyncWindowsFirewallRule(string processName, string policy)
    {
        Task.Run(() =>
        {
            try
            {
                string safeName = SanitizeProcessName(processName);
                if (string.IsNullOrEmpty(safeName)) return;

                string ruleName = $"NetFlow_{safeName}";
                // Remove existing outbound and inbound rules
                RunNetsh($"advfirewall firewall delete rule name=\"{ruleName}\"");
                RunNetsh($"advfirewall firewall delete rule name=\"{ruleName}_in\"");

                if (policy == "block")
                {
                    string? exePath = ResolveProcessExecutablePath(safeName);
                    if (!string.IsNullOrEmpty(exePath))
                    {
                        exePath = exePath.Trim('\"', ' ');
                    }

                    string programArg = !string.IsNullOrEmpty(exePath)
                        ? $"program=\"{exePath}\""
                        : $"program=\"{safeName}.exe\"";

                    // Add outbound and inbound block rules for the process
                    RunNetsh($"advfirewall firewall add rule name=\"{ruleName}\" dir=out action=block {programArg}");
                    RunNetsh($"advfirewall firewall add rule name=\"{ruleName}_in\" dir=in action=block {programArg}");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error during SyncWindowsFirewallRule: {ex.Message}");
            }
        });
    }

    public static string GetIpRuleName(string ip) => $"NetFlow_Block_IP_{ip.Trim()}";

    public (bool Success, string RuleName, string? Error, bool ElevationRequired) BlockIp(string ip, string? reason = null)
    {
        if (string.IsNullOrWhiteSpace(ip) || !System.Net.IPAddress.TryParse(ip.Trim(), out var parsedIp))
        {
            return (false, string.Empty, $"Invalid IP address format: '{ip}'", false);
        }

        string cleanIp = parsedIp.ToString();
        string ruleName = GetIpRuleName(cleanIp);

        // Remove existing rule first to prevent duplicate accumulation
        ExecuteNetsh($"advfirewall firewall delete rule name=\"{ruleName}\"");

        // Add outbound block rule
        var resOut = ExecuteNetsh($"advfirewall firewall add rule name=\"{ruleName}\" dir=out action=block remoteip=\"{cleanIp}\"");
        // Add inbound block rule
        var resIn = ExecuteNetsh($"advfirewall firewall add rule name=\"{ruleName}\" dir=in action=block remoteip=\"{cleanIp}\"");

        bool success = resOut.Success && resIn.Success;
        bool elevationRequired = false;
        string? error = null;

        if (!success)
        {
            string outErr = string.IsNullOrWhiteSpace(resOut.Error) ? resOut.Output : resOut.Error;
            string inErr = string.IsNullOrWhiteSpace(resIn.Error) ? resIn.Output : resIn.Error;
            string combinedErr = $"{outErr} {inErr}".Trim();

            elevationRequired = IsElevationRequiredError(resOut.Output, resOut.Error) ||
                                IsElevationRequiredError(resIn.Output, resIn.Error);

            error = elevationRequired
                ? "Administrator privileges required to create Windows Firewall rules via netsh."
                : $"Failed to configure firewall rule for IP {cleanIp}: {combinedErr}";
        }
        else
        {
            lock (_lock)
            {
                _storage.LogFirewallEvent("IP_BLOCK", 0, cleanIp, reason ?? "ACTIVE_DEFENSE_BLOCK");
            }
        }

        return (success, ruleName, error, elevationRequired);
    }

    public (bool Success, string? Error, bool ElevationRequired) UnblockIp(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip) || !System.Net.IPAddress.TryParse(ip.Trim(), out var parsedIp))
        {
            return (false, $"Invalid IP address format: '{ip}'", false);
        }

        string cleanIp = parsedIp.ToString();
        string ruleName = GetIpRuleName(cleanIp);

        var res = ExecuteNetsh($"advfirewall firewall delete rule name=\"{ruleName}\"");
        bool elevationRequired = IsElevationRequiredError(res.Output, res.Error);

        bool success = res.Success || res.Output.Contains("No rules match") || res.Output.Contains("0 rule(s) deleted");
        string? error = null;

        if (!success)
        {
            error = elevationRequired
                ? "Administrator privileges required to delete Windows Firewall rules via netsh."
                : $"Failed to remove firewall rule: {res.Error} {res.Output}".Trim();
        }
        else
        {
            lock (_lock)
            {
                _storage.LogFirewallEvent("IP_UNBLOCK", 0, cleanIp, "ACTIVE_DEFENSE_UNBLOCK");
            }
        }

        return (success, error, elevationRequired);
    }

    public static bool IsElevationRequiredError(string output, string error)
    {
        string combined = $"{output} {error}".ToLowerInvariant();
        return combined.Contains("elevation") ||
               combined.Contains("administrator") ||
               combined.Contains("access is denied") ||
               combined.Contains("run as administrator");
    }

    public static (bool Success, int ExitCode, string Output, string Error) ExecuteNetsh(string args)
    {
        try
        {
            var psi = new ProcessStartInfo("netsh", args)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var p = Process.Start(psi);
            if (p == null)
            {
                return (false, -1, string.Empty, "Failed to start netsh process.");
            }

            string stdout = p.StandardOutput.ReadToEnd();
            string stderr = p.StandardError.ReadToEnd();
            bool exited = p.WaitForExit(3000);
            if (!exited)
            {
                try { p.Kill(); } catch { }
                return (false, -1, stdout, "netsh command timed out.");
            }

            bool success = p.ExitCode == 0;
            return (success, p.ExitCode, stdout.Trim(), stderr.Trim());
        }
        catch (Exception ex)
        {
            return (false, -1, string.Empty, ex.Message);
        }
    }

    private static void RunNetsh(string args)
    {
        ExecuteNetsh(args);
    }
}
