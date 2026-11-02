using System.Collections.Concurrent;
using Microsoft.Extensions.Hosting;
using NetFlow.Core.Diagnostics;
using NetFlow.Core.Models;
using NetFlow.Core.Services;
using NetFlow.Core.Storage;
using NetFlow.Platform.Windows.Services;

namespace NetFlow.Server;

public class NetflowBackgroundWorker : BackgroundService
{
    private readonly BandwidthTracker _tracker;
    private readonly NetflowStorage? _storage;
    private readonly ConcurrentDictionary<int, DateTimeOffset> _alertedThreatPids = new();
    private DateTimeOffset _lastQuotaAlert = DateTimeOffset.MinValue;
    private int _quotaCheckCounter = 0;
    private int _lifecycleCounter = 3590;

    public static bool NotificationsEnabled { get; set; } = true;

    public ConcurrentDictionary<int, DateTimeOffset> AlertedThreatPids => _alertedThreatPids;
    public DateTimeOffset LastQuotaAlert
    {
        get => _lastQuotaAlert;
        set => _lastQuotaAlert = value;
    }

    public NetflowBackgroundWorker(BandwidthTracker tracker, NetflowStorage? storage = null)
    {
        _tracker = tracker;
        _storage = storage;
    }

    public void CheckThreatAlerts(DateTimeOffset? currentTime = null)
    {
        if (!NotificationsEnabled) return;

        var snapshot = _tracker.GetLatestSnapshot();
        if (snapshot?.TopProcesses == null) return;

        var now = currentTime ?? DateTimeOffset.UtcNow;
        foreach (var p in snapshot.TopProcesses)
        {
            if (p.Threat != null && p.Threat.Level >= RiskLevel.High)
            {
                if (!_alertedThreatPids.TryGetValue(p.Pid, out var lastAlert) || (now - lastAlert).TotalSeconds >= 60)
                {
                    _alertedThreatPids[p.Pid] = now;
                    WindowsNotifier.SendNotification("Security Threat Detected", $"{p.Name} (PID {p.Pid}) flagged as {p.Threat.Level} risk.");
                }
            }
        }

        // Cleanup stale PIDs (older than 5 minutes)
        if (_alertedThreatPids.Count > 100)
        {
            foreach (var kvp in _alertedThreatPids)
            {
                if ((now - kvp.Value).TotalMinutes > 5)
                    _alertedThreatPids.TryRemove(kvp.Key, out _);
            }
        }
    }

    public bool CheckQuotaAlerts(DateTimeOffset? currentTime = null)
    {
        if (!NotificationsEnabled || _storage == null) return false;

        try
        {
            var plan = _storage.GetDataPlanStatus();
            if (plan != null && (plan.IsWarning || plan.IsExceeded))
            {
                var now = currentTime ?? DateTimeOffset.UtcNow;
                if ((now - _lastQuotaAlert).TotalMinutes >= 15)
                {
                    _lastQuotaAlert = now;
                    WindowsNotifier.SendNotification("NetFlow Quota Alert", $"Data plan has reached {plan.PercentUsed:F1}% ({plan.UsedBytesHuman} / {plan.LimitBytesHuman}).");
                    return true;
                }
            }
        }
        catch { }

        return false;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // 1. Ping worker in background
        _ = Task.Run(async () =>
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var res = await NetworkDiagnostics.MeasurePingAsync("1.1.1.1", 1, 2000);
                    if (res.TryGetValue("latency_ms", out var lat) && lat is double d)
                    {
                        _tracker.SetPingLatency(d);
                    }
                }
                catch { }
                await Task.Delay(5000, stoppingToken);
            }
        }, stoppingToken);

        // 2. High precision 1.0s telemetry poll loop
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        while (!stoppingToken.IsCancellationRequested && await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                _tracker.PollOnce();

                if (NotificationsEnabled)
                {
                    CheckThreatAlerts();

                    if (++_quotaCheckCounter >= 10)
                    {
                        _quotaCheckCounter = 0;
                        CheckQuotaAlerts();
                    }
                }

                if (++_lifecycleCounter >= 3600)
                {
                    _lifecycleCounter = 0;
                    _storage?.PerformLifecycleMaintenance();
                }
            }
            catch { }
        }
    }
}
