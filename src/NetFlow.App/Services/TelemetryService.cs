using System.IO;
using System.Windows;
using NetFlow.Core.Diagnostics;
using NetFlow.Core.Models;
using NetFlow.Core.Services;
using NetFlow.Core.Storage;
using NetFlow.Platform.Windows.Defense;
using NetFlow.Platform.Windows.Firewall;
using NetFlow.Platform.Windows.QoS;
using NetFlow.Platform.Windows.Security;
using NetFlow.Platform.Windows.Services;
using NetFlow.Platform.Windows.Tor;
using NetFlow.Platform.Windows.Vpn;
using NetFlow.Platform.Windows.Wifi;

namespace NetFlow.App.Services;

public class TelemetryService : IDisposable
{
    private static TelemetryService? _instance;
    public static TelemetryService Instance => _instance ??= new TelemetryService();

    public NetflowStorage Storage { get; }
    public WindowsFirewallEngine Firewall { get; }
    public WindowsSocketProvider SocketProvider { get; }
    public WindowsSecurityScanner SecurityScanner { get; }
    public BandwidthTracker Tracker { get; }
    public ActiveDefenseManager ActiveDefense { get; }
    public GeoIpDatabase GeoIpDb { get; }
    public NetFlow.Core.Telemetry.GeoIpService GeoIp { get; }
    public NativeWifiScanner WifiScanner { get; }
    public WindowsQosManager QosManager { get; }
    public WindowsVpnManager VpnManager { get; }
    public WindowsTorManager TorManager { get; }

    private readonly PeriodicTimer _timer;
    private readonly CancellationTokenSource _cts = new();
    private Task? _pollLoopTask;
    private int _pingCounter;
    private int _lifecycleCounter;

    public event Action<RealtimeSnapshot>? SnapshotUpdated;

    public TelemetryService()
    {
        string appData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NetFlow");
        Directory.CreateDirectory(appData);

        string dbPath = Path.Combine(appData, "netflow.db");
        string geoDbPath = Path.Combine(appData, "geoip.db");

        Storage = new NetflowStorage(dbPath);
        Firewall = new WindowsFirewallEngine(Storage);
        SocketProvider = new WindowsSocketProvider();
        SecurityScanner = new WindowsSecurityScanner();
        ActiveDefense = new ActiveDefenseManager(Firewall);
        GeoIpDb = new GeoIpDatabase(geoDbPath);
        GeoIp = new NetFlow.Core.Telemetry.GeoIpService(GeoIpDb);
        WifiScanner = new NativeWifiScanner();
        QosManager = new WindowsQosManager();
        VpnManager = new WindowsVpnManager();
        TorManager = new WindowsTorManager();

        Tracker = new BandwidthTracker(Storage, Firewall, SocketProvider, SecurityScanner);

        _timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
    }

    public void Start()
    {
        if (_pollLoopTask != null) return;
        _pollLoopTask = Task.Run(PollLoopAsync);

        // Run initial lifecycle retention & maintenance in background
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(5000, _cts.Token);
                Storage.PerformLifecycleMaintenance();
            }
            catch { }
        }, _cts.Token);
    }

    private async Task PollLoopAsync()
    {
        try
        {
            // Initial poll
            var initialSnapshot = Tracker.PollOnce();
            DispatchSnapshot(initialSnapshot);

            while (!_cts.Token.IsCancellationRequested && await _timer.WaitForNextTickAsync(_cts.Token))
            {
                // Measure ping latency every 5 ticks (5 seconds)
                if (_pingCounter++ % 5 == 0)
                {
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            var pingResult = await NetworkDiagnostics.MeasurePingAsync("1.1.1.1");
                            if (pingResult.TryGetValue("success", out var s) && s is true &&
                                pingResult.TryGetValue("latency_ms", out var l) && l != null)
                            {
                                Tracker.SetPingLatency(Convert.ToDouble(l));
                            }
                        }
                        catch { }
                    });
                }

                // Hourly database lifecycle retention & rollup maintenance
                if (++_lifecycleCounter >= 3600)
                {
                    _lifecycleCounter = 0;
                    _ = Task.Run(() =>
                    {
                        try { Storage.PerformLifecycleMaintenance(); } catch { }
                    });
                }

                var snapshot = Tracker.PollOnce();
                DispatchSnapshot(snapshot);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error in TelemetryService poll loop: {ex.Message}");
        }
    }

    private void DispatchSnapshot(RealtimeSnapshot snapshot)
    {
        var app = System.Windows.Application.Current;
        if (app != null && !app.Dispatcher.HasShutdownStarted)
        {
            app.Dispatcher.InvokeAsync(() =>
            {
                SnapshotUpdated?.Invoke(snapshot);
            });
        }
    }

    public static string FormatBytes(double bytes)
    {
        if (bytes < 1024) return $"{bytes:F0} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024:F1} KB";
        if (bytes < 1024L * 1024 * 1024) return $"{bytes / (1024 * 1024):F1} MB";
        return $"{bytes / (1024L * 1024 * 1024):F2} GB";
    }

    public static string FormatSpeed(double bytesPerSec)
    {
        return TrayTooltipHelper.FormatSpeed(bytesPerSec);
    }

    public void Dispose()
    {
        _cts.Cancel();
        _timer.Dispose();
        _cts.Dispose();
    }
}
