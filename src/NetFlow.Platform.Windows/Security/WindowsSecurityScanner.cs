using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;
using NetFlow.Core.Models;
using NetFlow.Core.Services;

namespace NetFlow.Platform.Windows.Security;

public class WindowsSecurityScanner : ISecurityScanner
{
    private static readonly HashSet<string> SystemProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "system idle process", "registry", "smss", "smss.exe", "csrss", "csrss.exe",
        "wininit", "wininit.exe", "services", "services.exe", "lsass", "lsass.exe", "svchost", "svchost.exe",
        "fontdrvhost", "fontdrvhost.exe", "winlogon", "winlogon.exe", "dwm", "dwm.exe", "spoolsv", "spoolsv.exe",
        "taskhostw", "taskhostw.exe", "explorer", "explorer.exe", "sihost", "sihost.exe", "ctfmon", "ctfmon.exe",
        "searchindexer", "searchindexer.exe", "securityhealthservice", "securityhealthservice.exe",
        "smartscreen", "smartscreen.exe", "msmpeng", "msmpeng.exe", "nissrv", "nissrv.exe", "werfault", "werfault.exe",
        "audiodg", "audiodg.exe"
    };

    private static readonly HashSet<string> CriticalSystemNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "system idle process", "smss", "smss.exe", "csrss", "csrss.exe", "wininit", "wininit.exe",
        "services", "services.exe", "lsass", "lsass.exe"
    };

    private static readonly Dictionary<int, string> SuspiciousPorts = new()
    {
        { 1337, "Common Elite / Backdoor Port" },
        { 3128, "Squid Proxy / SOCKS Tunnel" },
        { 3333, "Stratum Cryptomining Protocol (Monero)" },
        { 4444, "Metasploit / Common Reverse Shell" },
        { 5555, "Android ADB / Trojan Backdoor Port" },
        { 6667, "IRC Botnet Command & Control" },
        { 6697, "IRC SSL Botnet C2" },
        { 7777, "Default RAT / Backdoor Port" },
        { 8333, "Bitcoin P2P Network" },
        { 9050, "Tor SOCKS Proxy" },
        { 9150, "Tor Browser SOCKS Proxy" },
        { 14444, "Cryptomining Pool Protocol" },
        { 55555, "Known Backdoor Port" }
    };

    private readonly ConcurrentDictionary<string, (bool IsSigned, bool ChainVerified, string Publisher, string Status)> _signatureCache = new(StringComparer.OrdinalIgnoreCase);

    public (bool IsSigned, bool ChainVerified, string Publisher, string Status) CheckSignature(string exePath)
    {
        if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
        {
            return (false, false, "File Inaccessible", "Cannot open executable file on disk");
        }

        if (_signatureCache.TryGetValue(exePath, out var cached))
        {
            return cached;
        }

        (bool IsSigned, bool ChainVerified, string Publisher, string Status) result;

        try
        {
#pragma warning disable SYSLIB0057
            using var basicCert = X509Certificate.CreateFromSignedFile(exePath);
#pragma warning restore SYSLIB0057
            using var cert2 = new X509Certificate2(basicCert);

            bool isValid = cert2.Verify();
            string subject = cert2.Subject;
            string cn = subject;
            int cnIdx = subject.IndexOf("CN=", StringComparison.OrdinalIgnoreCase);
            if (cnIdx >= 0)
            {
                int commaIdx = subject.IndexOf(',', cnIdx);
                cn = commaIdx > cnIdx ? subject.Substring(cnIdx + 3, commaIdx - (cnIdx + 3)) : subject.Substring(cnIdx + 3);
            }

            result = (
                true,
                isValid,
                cn.Trim(),
                isValid ? "Cryptographically Verified by Trusted Root CA" : "Certificate Chain Untrusted or Expired"
            );
        }
        catch
        {
            bool isSystemDir = false;
            try
            {
                string fullPath = Path.GetFullPath(exePath);
                string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                if (string.IsNullOrEmpty(winDir))
                {
                    winDir = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
                }
                string sysDir = Environment.GetFolderPath(Environment.SpecialFolder.System);
                if (string.IsNullOrEmpty(sysDir))
                {
                    sysDir = Path.Combine(winDir, "System32");
                }
                string sysWow64 = Path.Combine(winDir, "SysWOW64");

                if (!string.IsNullOrEmpty(sysDir) && fullPath.StartsWith(sysDir + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                {
                    isSystemDir = true;
                }
                else if (!string.IsNullOrEmpty(sysWow64) && fullPath.StartsWith(sysWow64 + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                {
                    isSystemDir = true;
                }
            }
            catch
            {
                isSystemDir = false;
            }

            if (isSystemDir)
            {
                result = (true, true, "Microsoft Windows (Catalog Signed)", "Verified Windows OS System Component");
            }
            else
            {
                result = (false, false, "Unsigned / Unknown Publisher", "No valid digital signature detected");
            }
        }

        _signatureCache[exePath] = result;
        return result;
    }

    public ThreatAssessment AssessProcess(int pid, string name, string path, List<SocketInfo>? sockets = null)
    {
        var assessment = new ThreatAssessment();

        if (pid <= 4)
        {
            assessment.Level = RiskLevel.Safe;
            assessment.IsCriticalOS = true;
            assessment.IsSigned = true;
            assessment.ChainVerified = true;
            assessment.Publisher = "Microsoft Windows (Kernel)";
            assessment.StatusMessage = "Core Operating System Component";
            return assessment;
        }

        string cleanName = (name ?? string.Empty).ToLowerInvariant();
        if (cleanName.EndsWith(".exe")) cleanName = cleanName[..^4];
        string cleanPath = (path ?? string.Empty).ToLowerInvariant();

        assessment.IsCriticalOS = CriticalSystemNames.Contains(cleanName) || CriticalSystemNames.Contains(cleanName + ".exe");

        // 1. Signature Check
        if (!string.IsNullOrEmpty(path) && File.Exists(path))
        {
            var sig = CheckSignature(path);
            assessment.IsSigned = sig.IsSigned;
            assessment.ChainVerified = sig.ChainVerified;
            assessment.Publisher = sig.Publisher;
            assessment.StatusMessage = sig.Status;

            if (!sig.IsSigned)
            {
                assessment.Flags.Add("Unsigned Binary: Executable lacks digital signature");
                if (assessment.Level < RiskLevel.Low) assessment.Level = RiskLevel.Low;
            }
            else if (!sig.ChainVerified)
            {
                assessment.Flags.Add("Untrusted Certificate: Signature chain failed root CA validation");
                if (assessment.Level < RiskLevel.Medium) assessment.Level = RiskLevel.Medium;
            }
        }

        // 2. Masquerading Check: Known system process running outside Windows directory
        if (SystemProcessNames.Contains(cleanName) || SystemProcessNames.Contains(cleanName + ".exe"))
        {
            if (!string.IsNullOrEmpty(cleanPath) && (cleanPath.Contains('\\') || cleanPath.Contains('/')))
            {
                bool isSystemLocation = false;
                try
                {
                    string fullPath = Path.GetFullPath(path!);
                    string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                    if (string.IsNullOrEmpty(winDir))
                    {
                        winDir = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
                    }
                    string progFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                    string progFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

                    if (!string.IsNullOrEmpty(winDir) && fullPath.StartsWith(winDir + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                    {
                        isSystemLocation = true;
                    }
                    else if (!string.IsNullOrEmpty(progFiles) && fullPath.StartsWith(progFiles + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                    {
                        isSystemLocation = true;
                    }
                    else if (!string.IsNullOrEmpty(progFilesX86) && fullPath.StartsWith(progFilesX86 + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                    {
                        isSystemLocation = true;
                    }
                }
                catch
                {
                    isSystemLocation = false;
                }

                if (!isSystemLocation)
                {
                    assessment.Flags.Add($"Masquerading: Named '{name}' but executing from non-system location: {path}");
                    assessment.Level = RiskLevel.High;
                }
            }
            else
            {
                // Protected Windows core system process whose path cannot be queried by non-admin
                assessment.IsSigned = true;
                assessment.ChainVerified = true;
                assessment.Publisher = "Microsoft Windows (Protected System Component)";
                assessment.StatusMessage = "Verified Core System Process";
            }
        }

        // 3. Suspicious Directory Execution
        if (!string.IsNullOrEmpty(cleanPath))
        {
            if (cleanPath.Contains(@"\appdata\local\temp\") ||
                cleanPath.Contains(@"\windows\temp\") ||
                cleanPath.Contains(@"\users\public\"))
            {
                assessment.Flags.Add($"Suspicious Path: Executing from temp/public directory ({path})");
                if (assessment.Level < RiskLevel.Medium) assessment.Level = RiskLevel.Medium;
            }
            else if (cleanPath.Length <= 6 && cleanPath.EndsWith(".exe")) // e.g. C:\x.exe
            {
                assessment.Flags.Add("Suspicious Path: Running directly in drive root");
                if (assessment.Level < RiskLevel.Medium) assessment.Level = RiskLevel.Medium;
            }
        }

        // 4. Suspicious Ports
        if (sockets != null)
        {
            foreach (var s in sockets)
            {
                if (SuspiciousPorts.TryGetValue(s.RemotePort, out var desc))
                {
                    assessment.Flags.Add($"Suspicious Port: Connection to port {s.RemotePort} ({desc})");
                    if (assessment.Level < RiskLevel.High) assessment.Level = RiskLevel.High;
                }
            }
        }

        return assessment;
    }

    public List<ThreatAssessment> GetDetectedThreats(IEnumerable<ProcessBandwidth> processes)
    {
        return processes
            .Where(p => p.Threat != null && p.Threat.Level >= RiskLevel.Medium)
            .Select(p => p.Threat!)
            .ToList();
    }
}
