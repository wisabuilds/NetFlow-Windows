using System.Collections.ObjectModel;
using System.IO;
using System.Windows.Input;
using NetFlow.App.Services;

namespace NetFlow.App.ViewModels;

public class FirewallAppItemViewModel : ViewModelBase
{
    private string _processName = string.Empty;
    private string _policy = "allow";
    private bool _isBlocked;

    public string ProcessName { get => _processName; set => SetProperty(ref _processName, value); }
    public string Policy
    {
        get => _policy;
        set
        {
            if (SetProperty(ref _policy, value))
            {
                IsBlocked = value is "block" or "lan_only";
            }
        }
    }
    public bool IsBlocked
    {
        get => _isBlocked;
        set
        {
            if (SetProperty(ref _isBlocked, value))
            {
                OnPropertyChanged(nameof(ActionText));
            }
        }
    }
    public string ActionText => IsBlocked ? "Allow" : "Block";
}

public class SecurityAuditLogItem : ViewModelBase
{
    public string Time { get; set; } = string.Empty;
    public string Application { get; set; } = string.Empty;
    public int Pid { get; set; }
    public string Destination { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
}

public class FirewallViewModel : ViewModelBase
{
    private readonly TelemetryService _telemetry = TelemetryService.Instance;

    private bool _isMasterEnabled = true;
    private string _masterTitle = "Firewall Protection: Active";
    private string _masterSubtitle = "Intercepting unauthorized connections and enforcing policy";
    private string _masterButtonText = "Disable Firewall";
    private int _blockedCount;
    private int _droppedCount;
    private string _searchText = string.Empty;

    public bool IsMasterEnabled
    {
        get => _isMasterEnabled;
        set
        {
            if (SetProperty(ref _isMasterEnabled, value))
            {
                MasterTitle = value ? "Firewall Protection: Active" : "Firewall Protection: Disabled";
                MasterSubtitle = value ? "Intercepting unauthorized connections and enforcing policy" : "Network traffic is unconstrained";
                MasterButtonText = value ? "Disable Firewall" : "Enable Firewall";
            }
        }
    }

    public string MasterTitle { get => _masterTitle; set => SetProperty(ref _masterTitle, value); }
    public string MasterSubtitle { get => _masterSubtitle; set => SetProperty(ref _masterSubtitle, value); }
    public string MasterButtonText { get => _masterButtonText; set => SetProperty(ref _masterButtonText, value); }
    public int BlockedCount { get => _blockedCount; set => SetProperty(ref _blockedCount, value); }
    public int DroppedCount { get => _droppedCount; set => SetProperty(ref _droppedCount, value); }

    public string SearchText
    {
        get => _searchText;
        set
        {
            if (SetProperty(ref _searchText, value))
            {
                ApplyFilter();
            }
        }
    }

    public ObservableCollection<FirewallAppItemViewModel> FilteredApps { get; } = new();
    private readonly List<FirewallAppItemViewModel> _allApps = new();

    public ObservableCollection<SecurityAuditLogItem> SecurityEvents { get; } = new();

    public ICommand ToggleMasterCommand { get; }
    public ICommand ToggleAppBlockCommand { get; }
    public ICommand UnblockAllCommand { get; }

    public FirewallViewModel()
    {
        ToggleMasterCommand = new RelayCommand(ToggleMaster);
        ToggleAppBlockCommand = new RelayCommand(param => ToggleAppBlock(param as FirewallAppItemViewModel));
        UnblockAllCommand = new RelayCommand(UnblockAll);

        RefreshStatus();
        LoadAppsAndEvents();
        _telemetry.SnapshotUpdated += _ => RefreshStatus();
    }

    public void ToggleMaster()
    {
        bool next = !_isMasterEnabled;
        _telemetry.Firewall.ToggleFirewall(next);
        IsMasterEnabled = next;
        RefreshStatus();
    }

    public void ToggleAppBlock(FirewallAppItemViewModel? app)
    {
        if (app == null) return;
        string nextPolicy = app.IsBlocked ? "allow" : "block";
        _telemetry.Firewall.SetAppPolicy(app.ProcessName, nextPolicy);
        app.Policy = nextPolicy;
        RefreshStatus();
    }

    public void UnblockAll()
    {
        _telemetry.Firewall.ClearAllBlocks();
        foreach (var app in _allApps)
        {
            app.Policy = "allow";
        }
        ApplyFilter();
        RefreshStatus();
    }

    public void RefreshStatus()
    {
        try
        {
            var status = _telemetry.Firewall.GetStatus();
            IsMasterEnabled = _telemetry.Firewall.IsEnabled;

            if (status.TryGetValue("blocked_apps_count", out var bCount) && bCount != null)
                BlockedCount = Convert.ToInt32(bCount);
            else if (status.TryGetValue("rules_count", out var rCount) && rCount != null)
                BlockedCount = Convert.ToInt32(rCount);

            if (status.TryGetValue("total_blocked", out var dCount) && dCount != null)
                DroppedCount = Convert.ToInt32(dCount);
            else if (status.TryGetValue("total_dropped_sockets", out var legacyDCount) && legacyDCount != null)
                DroppedCount = Convert.ToInt32(legacyDCount);
        }
        catch { }
    }

    public void LoadAppsAndEvents()
    {
        try
        {
            // Populate known apps from storage and running processes
            var policies = _telemetry.Storage.GetFirewallPolicies();
            var runningProcs = _telemetry.SocketProvider.GetEnrichedSockets()
                .Select(s => s.ProcessName)
                .Where(n => !string.IsNullOrEmpty(n))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            var combinedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var k in policies.Keys)
            {
                if (!string.IsNullOrWhiteSpace(k))
                    combinedNames.Add(Path.GetFileNameWithoutExtension(k.Trim()));
            }
            foreach (var p in runningProcs)
            {
                if (!string.IsNullOrWhiteSpace(p))
                    combinedNames.Add(Path.GetFileNameWithoutExtension(p.Trim()));
            }

            _allApps.Clear();
            foreach (var cleanName in combinedNames.OrderBy(n => n))
            {
                string pol = policies.TryGetValue(cleanName, out var p) ? p : "allow";
                _allApps.Add(new FirewallAppItemViewModel
                {
                    ProcessName = cleanName,
                    Policy = pol,
                    IsBlocked = pol is "block" or "lan_only"
                });
            }

            ApplyFilter();

            // Load recent security events
            var events = _telemetry.Storage.GetFirewallEvents(25);
            SecurityEvents.Clear();
            foreach (var ev in events)
            {
                SecurityEvents.Add(new SecurityAuditLogItem
                {
                    Time = DateTimeOffset.FromUnixTimeSeconds((long)ev.Timestamp).ToLocalTime().ToString("HH:mm:ss"),
                    Application = ev.ProcessName,
                    Pid = ev.Pid ?? 0,
                    Destination = ev.RemoteEndpoint,
                    Action = ev.Action
                });
            }
        }
        catch { }
    }

    private void ApplyFilter()
    {
        FilteredApps.Clear();
        var q = _searchText?.Trim() ?? string.Empty;
        var matches = string.IsNullOrEmpty(q)
            ? _allApps
            : _allApps.Where(a => a.ProcessName.Contains(q, StringComparison.OrdinalIgnoreCase));

        foreach (var app in matches)
        {
            FilteredApps.Add(app);
        }
    }
}
