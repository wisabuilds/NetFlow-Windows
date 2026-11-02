using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Input;
using NetFlow.App.Services;
using NetFlow.Core.Models;
using NetFlow.Platform.Windows.QoS;
using MessageBox = System.Windows.MessageBox;

namespace NetFlow.App.ViewModels;

public class ThreatItemRow : ViewModelBase
{
    public string ProcessName { get; set; } = string.Empty;
    public int Pid { get; set; }
    public string RiskLevel { get; set; } = "Safe";
    public string Publisher { get; set; } = "Unknown";
    public string DetectedFlags { get; set; } = "None";
    public string BandwidthText { get; set; } = "0 B/s";
}

public class QosRuleRow : ViewModelBase
{
    public string RuleName { get; set; } = string.Empty;
    public string TargetApp { get; set; } = string.Empty;
    public string DscpTier { get; set; } = string.Empty;
    public string BandwidthCap { get; set; } = "Uncapped";
}

public class DscpOption
{
    public int Dscp { get; set; }
    public string Name { get; set; } = string.Empty;
    public override string ToString() => Name;
}

public class SentinelViewModel : ViewModelBase
{
    private readonly TelemetryService _telemetry = TelemetryService.Instance;

    // QoS
    private string _qosAppInput = string.Empty;
    private DscpOption? _selectedDscp;
    private string _qosElevationText = "Checking...";
    private bool _isAdmin;

    // VPN
    private string _vpnStateText = "Disconnected";
    private string _vpnButtonText = "Connect VPN";
    private VpnRelayNode? _selectedRelay;

    // Tor
    private string _torProbeText = "Probing...";
    private string _torProxyStateText = "Direct (Disabled)";
    private string _torButtonText = "Route Windows Traffic Through Tor";

    public string QosAppInput { get => _qosAppInput; set => SetProperty(ref _qosAppInput, value); }
    public DscpOption? SelectedDscp { get => _selectedDscp; set => SetProperty(ref _selectedDscp, value); }
    public string QosElevationText { get => _qosElevationText; set => SetProperty(ref _qosElevationText, value); }
    public bool IsAdmin { get => _isAdmin; set => SetProperty(ref _isAdmin, value); }

    public string VpnStateText { get => _vpnStateText; set => SetProperty(ref _vpnStateText, value); }
    public string VpnButtonText { get => _vpnButtonText; set => SetProperty(ref _vpnButtonText, value); }
    public VpnRelayNode? SelectedRelay { get => _selectedRelay; set => SetProperty(ref _selectedRelay, value); }

    public string TorProbeText { get => _torProbeText; set => SetProperty(ref _torProbeText, value); }
    public string TorProxyStateText { get => _torProxyStateText; set => SetProperty(ref _torProxyStateText, value); }
    public string TorButtonText { get => _torButtonText; set => SetProperty(ref _torButtonText, value); }

    public ObservableCollection<ThreatItemRow> Threats { get; } = new();
    public bool HasThreats => Threats.Count > 0;
    public ObservableCollection<QosRuleRow> QosRules { get; } = new();
    public ObservableCollection<DscpOption> DscpOptions { get; } = new();
    public ObservableCollection<VpnRelayNode> VpnRelays { get; } = new();

    public ICommand DeepThreatScanCommand { get; }
    public ICommand ApplyQosCommand { get; }
    public ICommand RemoveQosCommand { get; }
    public ICommand ToggleVpnCommand { get; }
    public ICommand ToggleTorCommand { get; }
    public ICommand KillThreatCommand { get; }
    public ICommand RefreshRelaysCommand { get; }

    public SentinelViewModel()
    {
        DeepThreatScanCommand = new RelayCommand(DeepThreatScan);
        ApplyQosCommand = new RelayCommand(ApplyQos);
        RemoveQosCommand = new RelayCommand(param => RemoveQos(param as QosRuleRow));
        ToggleVpnCommand = new AsyncRelayCommand(ToggleVpnAsync);
        ToggleTorCommand = new RelayCommand(ToggleTor);
        KillThreatCommand = new RelayCommand(param => KillThreat(param as ThreatItemRow));
        RefreshRelaysCommand = new AsyncRelayCommand(async () => await RefreshRelaysAsync(true));

        // Init DSCP options
        DscpOptions.Add(new DscpOption { Dscp = 46, Name = "DSCP 46 EF (Competitive Gaming / VoIP)" });
        DscpOptions.Add(new DscpOption { Dscp = 34, Name = "DSCP 34 AF41 (Video Streaming / Conf)" });
        DscpOptions.Add(new DscpOption { Dscp = 8, Name = "DSCP 8 CS1 (Background / Torrent Throttle)" });
        SelectedDscp = DscpOptions[0];

        // Init VPN relays from cache / seed
        var relays = _telemetry.VpnManager.GetRelayNodes();
        foreach (var r in relays) VpnRelays.Add(r);
        SelectedRelay = VpnRelays.FirstOrDefault();

        // Background auto-refresh of live dynamic VPNGate relays
        _ = Task.Run(async () => await RefreshRelaysAsync(false));

        // Check Admin
        IsAdmin = WindowsQosManager.IsAdmin();
        QosElevationText = IsAdmin ? "Elevated (Admin)" : "Standard (Elevation Required)";

        RefreshQosRules();
        RefreshVpnStatus();
        RefreshTorStatus();
        DeepThreatScan();

        _telemetry.SnapshotUpdated += _ =>
        {
            if (Threats.Count == 0)
            {
                DeepThreatScan();
            }
        };
    }

    public void DeepThreatScan()
    {
        try
        {
            var snapshot = _telemetry.Tracker.GetLatestSnapshot();
            var procs = snapshot?.TopProcesses ?? new List<ProcessBandwidth>();

            Threats.Clear();
            foreach (var p in procs)
            {
                if (p.Threat != null && p.Threat.Level >= RiskLevel.Low)
                {
                    Threats.Add(new ThreatItemRow
                    {
                        ProcessName = p.Name,
                        Pid = p.Pid,
                        RiskLevel = p.Threat.Level.ToString(),
                        Publisher = string.IsNullOrEmpty(p.Threat.Publisher) ? "Unsigned / Unknown" : p.Threat.Publisher,
                        DetectedFlags = p.Threat.Flags.Count > 0 ? string.Join(", ", p.Threat.Flags) : p.Threat.StatusMessage,
                        BandwidthText = $"{p.TransferRateKbps:F1} KB/s"
                    });
                }
            }

            OnPropertyChanged(nameof(HasThreats));
        }
        catch { }
    }

    public void KillThreat(ThreatItemRow? threat)
    {
        if (threat == null || threat.Pid <= 0) return;
        var res = _telemetry.ActiveDefense.KillProcess(threat.Pid);
        if (res.Success)
        {
            MessageBox.Show($"Killed threat process {threat.ProcessName} (PID {threat.Pid}).", "Active Defense", MessageBoxButton.OK, MessageBoxImage.Information);
            DeepThreatScan();
        }
        else
        {
            MessageBox.Show(res.Error ?? "Failed to terminate process.", "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    public void ApplyQos()
    {
        if (string.IsNullOrWhiteSpace(_qosAppInput)) return;
        int dscp = _selectedDscp?.Dscp ?? 46;
        var (ok, msg) = _telemetry.QosManager.SetPolicy(_qosAppInput.Trim(), dscp, -1);
        if (ok)
        {
            MessageBox.Show(msg, "QoS Policy Applied", MessageBoxButton.OK, MessageBoxImage.Information);
            QosAppInput = string.Empty;
            RefreshQosRules();
        }
        else
        {
            MessageBox.Show(msg, "QoS Policy Failed", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    public void RemoveQos(QosRuleRow? rule)
    {
        if (rule == null) return;
        var (ok, msg) = _telemetry.QosManager.RemovePolicy(rule.TargetApp);
        if (ok)
        {
            RefreshQosRules();
        }
        else
        {
            MessageBox.Show(msg, "Failed", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    public void RefreshQosRules()
    {
        try
        {
            var rules = _telemetry.QosManager.GetActivePolicies();
            QosRules.Clear();
            foreach (var r in rules)
            {
                string tier = r.Dscp switch
                {
                    46 => "EF 46 (Gaming Booster)",
                    34 => "AF41 34 (Streaming)",
                    8 => "CS1 8 (Background)",
                    _ => $"DSCP {r.Dscp}"
                };

                QosRules.Add(new QosRuleRow
                {
                    RuleName = r.RuleName,
                    TargetApp = r.ApplicationName,
                    DscpTier = tier,
                    BandwidthCap = r.ThrottleBytesPerSec > 0
                        ? TelemetryService.FormatSpeed(r.ThrottleBytesPerSec)
                        : "Uncapped"
                });
            }
        }
        catch { }
    }

    public async Task ToggleVpnAsync()
    {
        var status = _telemetry.VpnManager.GetStatus();
        if (status.State == "Connected")
        {
            _telemetry.VpnManager.Disconnect();
            RefreshVpnStatus();
        }
        else
        {
            VpnStateText = "Connecting...";
            VpnButtonText = "Connecting...";
            string host = _selectedRelay?.HostOrIp ?? "public-vpn-58.opengw.net";
            var (ok, msg) = await _telemetry.VpnManager.ConnectAsync(host);
            RefreshVpnStatus();
            if (!ok)
            {
                MessageBox.Show(msg, "VPN Connection", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
    }

    public void RefreshVpnStatus()
    {
        try
        {
            var status = _telemetry.VpnManager.GetStatus();
            VpnStateText = status.State;
            VpnButtonText = status.State == "Connected" ? "Disconnect VPN" : "Connect VPN";
        }
        catch { }
    }

    public void ToggleTor()
    {
        try
        {
            var status = _telemetry.TorManager.GetStatus();
            bool enable = !status.IsSystemProxyEnabled;

            if (enable && !status.IsTorListening)
            {
                TorProbeText = "Tor service not detected on port 9050/9150";
                MessageBox.Show("Tor service not detected on port 9050/9150. Please launch Tor before routing Windows traffic.", "Tor Service Required", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            int port = status.ActivePort > 0 ? status.ActivePort : 9050;
            var (ok, msg) = enable ? _telemetry.TorManager.EnableSystemProxy(port) : _telemetry.TorManager.DisableSystemProxy();
            RefreshTorStatus();
            if (!ok)
            {
                MessageBox.Show(msg, "Tor Proxy", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
        catch { }
    }

    public void RefreshTorStatus()
    {
        try
        {
            var status = _telemetry.TorManager.GetStatus();
            TorProbeText = status.IsTorListening ? $"Active (Port {status.ActivePort})" : "Service Not Detected";
            TorProxyStateText = status.IsSystemProxyEnabled ? "Routed (Enabled)" : "Direct (Disabled)";
            TorButtonText = status.IsSystemProxyEnabled ? "Restore Direct Windows Traffic" : "Route Windows Traffic Through Tor";
        }
        catch { }
    }

    public async Task RefreshRelaysAsync(bool force = false)
    {
        try
        {
            var nodes = await _telemetry.VpnManager.RefreshRelaysAsync(force);
            if (nodes.Count > 0)
            {
                Action updateAction = () =>
                {
                    string? curSelected = SelectedRelay?.HostOrIp;
                    VpnRelays.Clear();
                    foreach (var n in nodes)
                    {
                        VpnRelays.Add(n);
                    }
                    SelectedRelay = VpnRelays.FirstOrDefault(n => n.HostOrIp.Equals(curSelected, StringComparison.OrdinalIgnoreCase))
                        ?? VpnRelays.FirstOrDefault();
                };

                var dispatcher = System.Windows.Application.Current?.Dispatcher;
                if (dispatcher != null && !dispatcher.HasShutdownStarted)
                {
                    await dispatcher.InvokeAsync(updateAction);
                }
                else
                {
                    updateAction();
                }
            }
        }
        catch { }
    }
}
