using System.Collections.ObjectModel;
using System.Windows.Input;
using NetFlow.App.Services;
using NetFlow.Core.Diagnostics;
using NetFlow.Platform.Windows.Wifi;

namespace NetFlow.App.ViewModels;

public class SubnetDeviceRow : ViewModelBase
{
    public string IpAddress { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    public string Vendor { get; set; } = string.Empty;
    public string Interface { get; set; } = string.Empty;
    public string Hostname { get; set; } = string.Empty;
}

public class WifiNetworkRow : ViewModelBase
{
    public string Ssid { get; set; } = string.Empty;
    public string Bssid { get; set; } = string.Empty;
    public int Channel { get; set; }
    public string Band { get; set; } = string.Empty;
    public string SignalText { get; set; } = string.Empty;
    public string SignalLevel { get; set; } = "Good";
    public string Security { get; set; } = string.Empty;
}

public class ToolsViewModel : ViewModelBase
{
    private readonly TelemetryService _telemetry = TelemetryService.Instance;

    private string _pingTarget = "1.1.1.1";
    private string _pingResultText = string.Empty;
    private bool _isPingRunning;
    private bool _hasPingResult;

    private string _speedtestText = "-- Mbps";
    private bool _isSpeedtestRunning;

    public string PingTarget { get => _pingTarget; set => SetProperty(ref _pingTarget, value); }
    public string PingResultText { get => _pingResultText; set => SetProperty(ref _pingResultText, value); }
    public bool IsPingRunning { get => _isPingRunning; set => SetProperty(ref _isPingRunning, value); }
    public bool HasPingResult { get => _hasPingResult; set => SetProperty(ref _hasPingResult, value); }

    public string SpeedtestText { get => _speedtestText; set => SetProperty(ref _speedtestText, value); }
    public bool IsSpeedtestRunning { get => _isSpeedtestRunning; set => SetProperty(ref _isSpeedtestRunning, value); }

    public ObservableCollection<SubnetDeviceRow> SubnetDevices { get; } = new();
    public ObservableCollection<WifiNetworkRow> WifiNetworks { get; } = new();

    public ICommand RunPingCommand { get; }
    public ICommand RunSpeedtestCommand { get; }
    public ICommand ScanSubnetCommand { get; }
    public ICommand ScanWifiCommand { get; }

    public ToolsViewModel()
    {
        RunPingCommand = new AsyncRelayCommand(RunPingAsync);
        RunSpeedtestCommand = new AsyncRelayCommand(RunSpeedtestAsync);
        ScanSubnetCommand = new RelayCommand(ScanSubnet);
        ScanWifiCommand = new RelayCommand(ScanWifi);
    }

    public async Task RunPingAsync()
    {
        if (string.IsNullOrWhiteSpace(_pingTarget)) return;

        IsPingRunning = true;
        HasPingResult = true;
        PingResultText = $"Pinging {_pingTarget}...";

        try
        {
            var res = await NetworkDiagnostics.MeasurePingAsync(_pingTarget);
            bool success = res.TryGetValue("success", out var sv) && sv is true;
            if (success && res.TryGetValue("latency_ms", out var lv))
            {
                PingResultText = $"Reply from {_pingTarget}: time={lv}ms status=Success";
            }
            else
            {
                string err = res.TryGetValue("error", out var ev) ? ev?.ToString() ?? "Host unreachable" : "Host unreachable";
                PingResultText = $"Ping to {_pingTarget} failed: {err}";
            }
        }
        catch (Exception ex)
        {
            PingResultText = $"Error: {ex.Message}";
        }
        finally
        {
            IsPingRunning = false;
        }
    }

    public async Task RunSpeedtestAsync()
    {
        IsSpeedtestRunning = true;
        SpeedtestText = "Testing...";

        try
        {
            var res = await NetworkDiagnostics.RunSpeedTestAsync(testSizeMb: 5);
            bool success = res.TryGetValue("success", out var sv) && sv is true;
            if (success && res.TryGetValue("speed_mbps", out var smv))
            {
                SpeedtestText = $"{smv} Mbps";
            }
            else
            {
                SpeedtestText = "Failed";
            }
        }
        catch
        {
            SpeedtestText = "Failed";
        }
        finally
        {
            IsSpeedtestRunning = false;
        }
    }

    public void ScanSubnet()
    {
        try
        {
            var devices = NetworkDiagnostics.GetLocalSubnetDevices();
            SubnetDevices.Clear();
            foreach (var d in devices)
            {
                string ip = d.TryGetValue("ip", out var ipv) ? ipv?.ToString() ?? "" : "";
                string mac = d.TryGetValue("mac", out var mv) ? mv?.ToString() ?? "" : "";
                string vendor = d.TryGetValue("vendor", out var vv) ? vv?.ToString() ?? "Unknown" : "Unknown";
                string host = d.TryGetValue("hostname", out var hv) ? hv?.ToString() ?? "--" : "--";

                SubnetDevices.Add(new SubnetDeviceRow
                {
                    IpAddress = ip,
                    MacAddress = mac,
                    Vendor = vendor,
                    Interface = "Local",
                    Hostname = host
                });
            }
        }
        catch { }
    }

    public void ScanWifi()
    {
        try
        {
            var result = _telemetry.WifiScanner.Scan();
            WifiNetworks.Clear();
            foreach (var n in result.Networks)
            {
                string signalGauge = n.SignalPct switch
                {
                    >= 80 => "●●●● Excellent",
                    >= 60 => "●●●○ Good",
                    >= 40 => "●●○○ Fair",
                    _ => "●○○○ Weak"
                };

                string level = n.SignalPct switch
                {
                    >= 80 => "Excellent",
                    >= 60 => "Good",
                    >= 40 => "Fair",
                    _ => "Weak"
                };

                WifiNetworks.Add(new WifiNetworkRow
                {
                    Ssid = string.IsNullOrEmpty(n.Ssid) ? "[Hidden Network]" : n.Ssid,
                    Bssid = n.Bssid,
                    Channel = n.Channel,
                    Band = n.Band,
                    SignalText = $"{n.SignalPct}% ({n.SignalDbm} dBm) {signalGauge}",
                    SignalLevel = level,
                    Security = n.Security
                });
            }
        }
        catch { }
    }
}
