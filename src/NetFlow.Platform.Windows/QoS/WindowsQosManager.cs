using System.Diagnostics;
using System.Security.Principal;
using Microsoft.Win32;
using NetFlow.Core.Models;
using NetFlow.Core.Services;
using NetFlow.Platform.Windows.Native;

namespace NetFlow.Platform.Windows.QoS;

public class WindowsQosManager : IQosManager
{
    private const string QOS_REGISTRY_PATH = @"SOFTWARE\Policies\Microsoft\Windows\QoS";
    private const string RULE_PREFIX = "NetFlow_";

    private const string TCPIP_QOS_PATH = @"SYSTEM\CurrentControlSet\Services\Tcpip\QoS";
    private const string NLA_VALUE_NAME = "Do not use NLA";

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

    public static bool ConfigureNlaBypass()
    {
        if (!IsAdmin()) return false;
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var tcpipQosKey = baseKey.CreateSubKey(TCPIP_QOS_PATH);
            if (tcpipQosKey != null)
            {
                tcpipQosKey.SetValue(NLA_VALUE_NAME, "1", RegistryValueKind.String);
                return true;
            }
        }
        catch { }
        return false;
    }

    public List<QosPolicyInfo> GetActivePolicies()
    {
        var policies = new List<QosPolicyInfo>();

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var qosKey = baseKey.OpenSubKey(QOS_REGISTRY_PATH, false);
            if (qosKey == null) return policies;

            foreach (string subName in qosKey.GetSubKeyNames())
            {
                if (!subName.StartsWith(RULE_PREFIX, StringComparison.OrdinalIgnoreCase)) continue;

                using var ruleKey = qosKey.OpenSubKey(subName, false);
                if (ruleKey == null) continue;

                var info = new QosPolicyInfo
                {
                    RuleName = subName,
                    ApplicationName = (ruleKey.GetValue("Application Name") as string) ?? subName[RULE_PREFIX.Length..],
                    Protocol = (ruleKey.GetValue("Protocol") as string) ?? "*"
                };

                object? dscpVal = ruleKey.GetValue("DSCP Value");
                if (dscpVal != null && int.TryParse(dscpVal.ToString(), out int d))
                {
                    info.Dscp = d;
                }

                object? throttleVal = ruleKey.GetValue("Throttle Rate");
                if (throttleVal != null && long.TryParse(throttleVal.ToString(), out long t))
                {
                    info.ThrottleBytesPerSec = t > 0 ? t * 1024L : -1L;
                }

                policies.Add(info);
            }
        }
        catch { }

        return policies;
    }

    public (bool Success, string Message) SetPolicy(string appExeName, int dscp, long throttleBytesPerSec = -1)
    {
        if (string.IsNullOrWhiteSpace(appExeName))
        {
            return (false, "Invalid application executable name.");
        }

        if (!IsAdmin())
        {
            return (false, "Administrator privileges are required to configure Windows QoS policies.");
        }

        try
        {
            // Configure NLA bypass for standalone / non-domain Windows 10/11 machines
            ConfigureNlaBypass();

            string fileName = Path.GetFileName(appExeName);
            string ruleName = RULE_PREFIX + fileName;

            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var qosKey = baseKey.CreateSubKey(QOS_REGISTRY_PATH);
            if (qosKey == null)
            {
                return (false, "Failed to open or create Windows QoS policy registry key.");
            }

            using var ruleKey = qosKey.CreateSubKey(ruleName);
            if (ruleKey == null)
            {
                return (false, $"Failed to create rule subkey: {ruleName}");
            }

            long throttleKbps = throttleBytesPerSec > 0 ? Math.Max(1L, throttleBytesPerSec / 1024L) : -1L;

            ruleKey.SetValue("Version", "1.0", RegistryValueKind.String);
            ruleKey.SetValue("Application Name", fileName, RegistryValueKind.String);
            ruleKey.SetValue("Protocol", "*", RegistryValueKind.String);
            ruleKey.SetValue("Local Port", "*", RegistryValueKind.String);
            ruleKey.SetValue("Local IP", "*", RegistryValueKind.String);
            ruleKey.SetValue("Local IP Prefix Length", "*", RegistryValueKind.String);
            ruleKey.SetValue("Remote Port", "*", RegistryValueKind.String);
            ruleKey.SetValue("Remote IP", "*", RegistryValueKind.String);
            ruleKey.SetValue("Remote IP Prefix Length", "*", RegistryValueKind.String);
            ruleKey.SetValue("DSCP Value", dscp.ToString(), RegistryValueKind.String);
            ruleKey.SetValue("Throttle Rate", throttleKbps > 0 ? throttleKbps.ToString() : "-1", RegistryValueKind.String);

            TriggerPolicyRefresh();
            return (true, $"QoS Policy applied for '{fileName}' (DSCP: {dscp}).");
        }
        catch (Exception ex)
        {
            return (false, $"Error setting QoS policy: {ex.Message}");
        }
    }

    public (bool Success, string Message) RemovePolicy(string appExeName)
    {
        if (string.IsNullOrWhiteSpace(appExeName))
        {
            return (false, "Invalid application executable name.");
        }

        if (!IsAdmin())
        {
            return (false, "Administrator privileges required to remove QoS policy.");
        }

        try
        {
            string fileName = Path.GetFileName(appExeName);
            string ruleName = RULE_PREFIX + fileName;

            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var qosKey = baseKey.OpenSubKey(QOS_REGISTRY_PATH, true);
            if (qosKey != null)
            {
                qosKey.DeleteSubKeyTree(ruleName, false);
            }

            TriggerPolicyRefresh();
            return (true, $"QoS Policy for '{fileName}' removed.");
        }
        catch (Exception ex)
        {
            return (false, $"Error removing QoS policy: {ex.Message}");
        }
    }

    public (bool Success, string Message) ClearAllPolicies()
    {
        if (!IsAdmin())
        {
            return (false, "Administrator privileges required.");
        }

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var qosKey = baseKey.OpenSubKey(QOS_REGISTRY_PATH, true);
            if (qosKey != null)
            {
                foreach (string subName in qosKey.GetSubKeyNames())
                {
                    if (subName.StartsWith(RULE_PREFIX, StringComparison.OrdinalIgnoreCase))
                    {
                        qosKey.DeleteSubKeyTree(subName, false);
                    }
                }
            }

            TriggerPolicyRefresh();
            return (true, "All NetFlow QoS policies cleared.");
        }
        catch (Exception ex)
        {
            return (false, $"Error clearing QoS policies: {ex.Message}");
        }
    }

    public (bool Success, string Message) SetProcessCpuPriority(int pid, string priorityLevel)
    {
        if (pid <= 4)
        {
            return (false, "Cannot alter kernel process priority.");
        }

        uint priorityClass = priorityLevel.ToLowerInvariant() switch
        {
            "high" => Kernel32.HIGH_PRIORITY_CLASS,
            "abovenormal" or "above_normal" => Kernel32.ABOVE_NORMAL_PRIORITY_CLASS,
            "belownormal" or "below_normal" => Kernel32.BELOW_NORMAL_PRIORITY_CLASS,
            "idle" => Kernel32.IDLE_PRIORITY_CLASS,
            _ => Kernel32.NORMAL_PRIORITY_CLASS
        };

        IntPtr hProc = Kernel32.OpenProcess(Kernel32.PROCESS_SET_INFORMATION, false, pid);
        if (hProc == IntPtr.Zero)
        {
            return (false, "Failed to open process with SET_INFORMATION privileges.");
        }

        try
        {
            bool ok = Kernel32.SetPriorityClass(hProc, priorityClass);
            if (ok)
            {
                // Optional I/O priority adjustment
                int ioPriority = priorityLevel.ToLowerInvariant() == "high" ? Kernel32.IoPriorityHigh : Kernel32.IoPriorityNormal;
                try
                {
                    Kernel32.NtSetInformationProcess(hProc, Kernel32.ProcessIoPriorityClass, ref ioPriority, sizeof(int));
                }
                catch { }

                return (true, $"Process {pid} priority set to {priorityLevel}.");
            }
            return (false, "SetPriorityClass Win32 call failed.");
        }
        finally
        {
            Kernel32.CloseHandle(hProc);
        }
    }

    private static void TriggerPolicyRefresh()
    {
        Task.Run(() =>
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "gpupdate.exe",
                    Arguments = "/target:computer /wait:0",
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                using var p = Process.Start(psi);
                p?.WaitForExit(3000);
            }
            catch { }
        });
    }
}
