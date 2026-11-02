using System.Collections.ObjectModel;
using NetFlow.App.Services;
using NetFlow.Core.Models;

namespace NetFlow.App.ViewModels;

public class InterfaceItemViewModel : ViewModelBase
{
    private string _name = string.Empty;
    private string _rxSpeedText = "0 B/s";
    private string _txSpeedText = "0 B/s";
    private string _totalRxText = "0 B";
    private string _totalTxText = "0 B";

    public string Name { get => _name; set => SetProperty(ref _name, value); }
    public string RxSpeedText { get => _rxSpeedText; set => SetProperty(ref _rxSpeedText, value); }
    public string TxSpeedText { get => _txSpeedText; set => SetProperty(ref _txSpeedText, value); }
    public string TotalRxText { get => _totalRxText; set => SetProperty(ref _totalRxText, value); }
    public string TotalTxText { get => _totalTxText; set => SetProperty(ref _totalTxText, value); }
}

public class ResourcesViewModel : ViewModelBase
{
    private readonly TelemetryService _telemetry = TelemetryService.Instance;

    private string _rateRxText = "0 B/s";
    private string _rateTxText = "0 B/s";
    private string _peakRxText = "(Peak: 0 B/s)";
    private string _peakTxText = "(Peak: 0 B/s)";
    private string _graphMaxLabel = "Max: 100 KB/s";
    private string _statPing = "-- ms";
    private string _statSockets = "0";

    // Data plan quota
    private string _quotaTitle = "Monthly Allowance";
    private string _quotaSubtitle = "No quota configured";
    private string _quotaPercentText = "--";
    private double _quotaFillPercent = 0.0;
    private string _paceStatus = "Off";
    private string _burnStatus = "unconfigured";
    private string _safeDailyBudget = "--";
    private string _projectedTotal = "--";
    private string _estimatedExhaustionDate = "--";

    private bool _isEditingQuota;
    private string _quotaInputGb = "50";

    private bool _launchOnStartup;
    private bool _toastNotifications = true;

    public string RateRxText { get => _rateRxText; set => SetProperty(ref _rateRxText, value); }
    public string RateTxText { get => _rateTxText; set => SetProperty(ref _rateTxText, value); }
    public string PeakRxText { get => _peakRxText; set => SetProperty(ref _peakRxText, value); }
    public string PeakTxText { get => _peakTxText; set => SetProperty(ref _peakTxText, value); }
    public string GraphMaxLabel { get => _graphMaxLabel; set => SetProperty(ref _graphMaxLabel, value); }
    public string StatPing { get => _statPing; set => SetProperty(ref _statPing, value); }
    public string StatSockets { get => _statSockets; set => SetProperty(ref _statSockets, value); }

    public string QuotaTitle { get => _quotaTitle; set => SetProperty(ref _quotaTitle, value); }
    public string QuotaSubtitle { get => _quotaSubtitle; set => SetProperty(ref _quotaSubtitle, value); }
    public string QuotaPercentText { get => _quotaPercentText; set => SetProperty(ref _quotaPercentText, value); }
    public double QuotaFillPercent { get => _quotaFillPercent; set => SetProperty(ref _quotaFillPercent, value); }
    public string PaceStatus { get => _paceStatus; set => SetProperty(ref _paceStatus, value); }
    public string BurnStatus { get => _burnStatus; set => SetProperty(ref _burnStatus, value); }
    public string SafeDailyBudget { get => _safeDailyBudget; set => SetProperty(ref _safeDailyBudget, value); }
    public string ProjectedTotal { get => _projectedTotal; set => SetProperty(ref _projectedTotal, value); }
    public string EstimatedExhaustionDate { get => _estimatedExhaustionDate; set => SetProperty(ref _estimatedExhaustionDate, value); }

    public bool IsEditingQuota { get => _isEditingQuota; set => SetProperty(ref _isEditingQuota, value); }
    public string QuotaInputGb { get => _quotaInputGb; set => SetProperty(ref _quotaInputGb, value); }

    public bool LaunchOnStartup
    {
        get => _launchOnStartup;
        set
        {
            if (SetProperty(ref _launchOnStartup, value))
            {
                NetFlow.Platform.Windows.Services.WindowsStartupManager.SetStartupEnabled(value);
            }
        }
    }

    public bool ToastNotifications
    {
        get => _toastNotifications;
        set
        {
            if (SetProperty(ref _toastNotifications, value))
            {
                _telemetry.Storage.SetSettingBool("toast_notifications", value);
                NetFlow.Platform.Windows.Services.WindowsNotifier.IsEnabled = value;
            }
        }
    }

    public System.Windows.Input.ICommand ConfigureQuotaCommand { get; }
    public System.Windows.Input.ICommand SaveQuotaCommand { get; }
    public System.Windows.Input.ICommand CancelQuotaEditCommand { get; }
    public System.Windows.Input.ICommand SetPresetQuotaCommand { get; }
    public System.Windows.Input.ICommand RemoveQuotaCommand { get; }

    public ObservableCollection<InterfaceItemViewModel> Interfaces { get; } = new();

    public event Action<double, double>? OnNewSpeedSample;

    public ResourcesViewModel()
    {
        ConfigureQuotaCommand = new RelayCommand(OpenQuotaEditor);
        SaveQuotaCommand = new RelayCommand(SaveQuota);
        CancelQuotaEditCommand = new RelayCommand(() => IsEditingQuota = false);
        SetPresetQuotaCommand = new RelayCommand(param =>
        {
            if (param != null && long.TryParse(param.ToString(), out long gb))
            {
                QuotaInputGb = gb.ToString();
            }
        });
        RemoveQuotaCommand = new RelayCommand(() =>
        {
            _telemetry.Storage.UpdateDataPlan("monthly", null, 1, 80);
            IsEditingQuota = false;
            RefreshDataPlan();
        });

        _launchOnStartup = NetFlow.Platform.Windows.Services.WindowsStartupManager.IsStartupEnabled();
        _toastNotifications = _telemetry.Storage.GetSettingBool("toast_notifications", true);
        NetFlow.Platform.Windows.Services.WindowsNotifier.IsEnabled = _toastNotifications;
        NetFlow.Platform.Windows.Services.WindowsNotifier.StorageCheck = () => _telemetry.Storage.GetSettingBool("toast_notifications", true);

        _telemetry.SnapshotUpdated += HandleSnapshot;
        LoadInitialHistory();
        RefreshDataPlan();
    }

    private void OpenQuotaEditor()
    {
        var plan = _telemetry.Storage.GetDataPlanStatus();
        long currentGb = plan.LimitBytes.HasValue ? plan.LimitBytes.Value / (1024L * 1024 * 1024) : 50;
        QuotaInputGb = (currentGb > 0 ? currentGb : 50).ToString();
        IsEditingQuota = true;
    }

    private void SaveQuota()
    {
        try
        {
            if (long.TryParse(QuotaInputGb?.Trim(), out long gb) && gb > 0)
            {
                long limitBytes = gb * 1024L * 1024 * 1024;
                _telemetry.Storage.UpdateDataPlan("monthly", limitBytes, 1, 80);
            }
            else
            {
                _telemetry.Storage.UpdateDataPlan("monthly", null, 1, 80);
            }
            IsEditingQuota = false;
            RefreshDataPlan();
        }
        catch { }
    }

    private void LoadInitialHistory()
    {
        try
        {
            var points = _telemetry.Storage.GetRecentSpeeds(60);
            if (points.Count > 0)
            {
                var rx = points.Select(p => p.TryGetValue("rx_speed", out var r) ? Convert.ToDouble(r) : 0.0).ToList();
                var tx = points.Select(p => p.TryGetValue("tx_speed", out var t) ? Convert.ToDouble(t) : 0.0).ToList();
                if (rx.Count > 0 && tx.Count > 0)
                {
                    OnNewSpeedSample?.Invoke(rx.Last(), tx.Last());
                }
            }
        }
        catch { }
    }

    public void RefreshDataPlan()
    {
        try
        {
            var forecast = _telemetry.Storage.GetBudgetForecast();
            var plan = _telemetry.Storage.GetDataPlanStatus();
            if (forecast.Configured)
            {
                string periodName = string.IsNullOrEmpty(plan.Period)
                    ? "Monthly"
                    : $"{char.ToUpper(plan.Period[0])}{plan.Period[1..]}";
                QuotaTitle = $"{periodName} Allowance ({plan.LimitBytesHuman})";
                QuotaSubtitle = plan.PercentUsed > 100
                    ? $"Used {plan.UsedBytesHuman} of {plan.LimitBytesHuman} (> 100%)"
                    : $"Used {plan.UsedBytesHuman} of {plan.LimitBytesHuman} ({plan.PercentUsed:F1}%)";
                QuotaPercentText = plan.PercentUsed > 100 ? "Exceeded (100%+)" : $"{plan.PercentUsed:F1}%";
                QuotaFillPercent = Math.Clamp(plan.PercentUsed, 0, 100);

                BurnStatus = plan.PercentUsed >= 100 ? "exceeded"
                    : forecast.BurnStatus == "critical" ? "critical"
                    : (plan.IsWarning || forecast.BurnStatus == "warning") ? "warning"
                    : forecast.BurnStatus;
                PaceStatus = BurnStatus switch
                {
                    "healthy" => "Safe Pace",
                    "warning" => "Elevated Pace",
                    "critical" => "Will Exceed Quota",
                    "exceeded" => "Cap Reached",
                    _ => "Off"
                };

                SafeDailyBudget = forecast.RecommendedDailyBudgetBytes > 0
                    ? $"{TelemetryService.FormatBytes(forecast.RecommendedDailyBudgetBytes)} / day"
                    : "0 B / day";

                ProjectedTotal = forecast.ProjectedPercentage > 100
                    ? $"{TelemetryService.FormatBytes(forecast.ProjectedTotalBytes)} (> 100%)"
                    : $"{TelemetryService.FormatBytes(forecast.ProjectedTotalBytes)} ({forecast.ProjectedPercentage:F1}%)";
                EstimatedExhaustionDate = forecast.EstimatedExhaustionDate;
            }
            else
            {
                QuotaTitle = "Monthly Allowance";
                QuotaSubtitle = "No quota configured";
                QuotaPercentText = "--";
                QuotaFillPercent = 0;
                BurnStatus = "unconfigured";
                PaceStatus = "Off";
                SafeDailyBudget = "--";
                ProjectedTotal = "--";
                EstimatedExhaustionDate = "Unlimited";
            }
        }
        catch { }
    }

    public void HandleSnapshot(RealtimeSnapshot snapshot)
    {
        RateRxText = TelemetryService.FormatSpeed(snapshot.TotalRxSpeed);
        RateTxText = TelemetryService.FormatSpeed(snapshot.TotalTxSpeed);
        PeakRxText = $"(Peak: {TelemetryService.FormatSpeed(snapshot.PeakRxSpeed)})";
        PeakTxText = $"(Peak: {TelemetryService.FormatSpeed(snapshot.PeakTxSpeed)})";

        StatPing = snapshot.PingLatencyMs.HasValue ? $"{snapshot.PingLatencyMs.Value:F0} ms" : "-- ms";
        StatSockets = snapshot.ActiveSocketCount.ToString();

        OnNewSpeedSample?.Invoke(snapshot.TotalRxSpeed, snapshot.TotalTxSpeed);

        // Update interface cards
        foreach (var (name, iface) in snapshot.Interfaces)
        {
            var existing = Interfaces.FirstOrDefault(i => i.Name == name);
            if (existing == null)
            {
                existing = new InterfaceItemViewModel { Name = name };
                Interfaces.Add(existing);
            }

            existing.RxSpeedText = TelemetryService.FormatSpeed(iface.RxSpeed);
            existing.TxSpeedText = TelemetryService.FormatSpeed(iface.TxSpeed);
            existing.TotalRxText = TelemetryService.FormatBytes(iface.RxBytes);
            existing.TotalTxText = TelemetryService.FormatBytes(iface.TxBytes);
        }

        // Periodically refresh data plan progress
        RefreshDataPlan();
    }
}
