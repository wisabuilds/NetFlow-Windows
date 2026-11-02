using System.Net.NetworkInformation;
using System.Windows.Input;
using NetFlow.App.Services;

namespace NetFlow.App.ViewModels;

public class MainViewModel : ViewModelBase
{
    private readonly TelemetryService _telemetry = TelemetryService.Instance;

    private string _selectedTab = "resources";
    private bool _isIncognito;
    private string _incognitoLabel = "Incognito";
    private bool _isOnline = true;

    public string SelectedTab
    {
        get => _selectedTab;
        set
        {
            if (SetProperty(ref _selectedTab, value))
            {
                OnTabChanged(value);
                OnPropertyChanged(nameof(CurrentViewModel));
            }
        }
    }

    public object CurrentViewModel => SelectedTab?.ToLowerInvariant() switch
    {
        "firewall" => FirewallVM,
        "history" => HistoryVM,
        "processes" => ProcessesVM,
        "connections" => ConnectionsVM,
        "tools" => ToolsVM,
        "sentinel" => SentinelVM,
        _ => ResourcesVM
    };

    private void OnTabChanged(string tab)
    {
        string lower = tab?.ToLowerInvariant() ?? "";
        HistoryVM.IsActive = (lower == "history");
        ConnectionsVM.IsActive = (lower == "connections");

        switch (lower)
        {
            case "history":
                HistoryVM.LoadHistoryData();
                break;
            case "firewall":
                FirewallVM.LoadAppsAndEvents();
                FirewallVM.RefreshStatus();
                break;
            case "connections":
                ConnectionsVM.RefreshConnections();
                break;
            case "sentinel":
                SentinelVM.DeepThreatScan();
                SentinelVM.RefreshQosRules();
                SentinelVM.RefreshVpnStatus();
                SentinelVM.RefreshTorStatus();
                break;
            case "resources":
                ResourcesVM.RefreshDataPlan();
                break;
        }
    }

    public bool IsIncognito
    {
        get => _isIncognito;
        set
        {
            if (SetProperty(ref _isIncognito, value))
            {
                IncognitoLabel = value ? "Incognito Active" : "Incognito";
            }
        }
    }

    public string IncognitoLabel
    {
        get => _incognitoLabel;
        set => SetProperty(ref _incognitoLabel, value);
    }

    private string _networkStatus = "Online";
    private string _networkStatusTooltip = "Network Connected (Online)";

    public string NetworkStatus
    {
        get => _networkStatus;
        set => SetProperty(ref _networkStatus, value);
    }

    public string NetworkStatusTooltip
    {
        get => _networkStatusTooltip;
        set => SetProperty(ref _networkStatusTooltip, value);
    }

    public bool IsOnline
    {
        get => _isOnline;
        set => SetProperty(ref _isOnline, value);
    }

    public ResourcesViewModel ResourcesVM { get; }
    public FirewallViewModel FirewallVM { get; }
    public HistoryViewModel HistoryVM { get; }
    public ProcessesViewModel ProcessesVM { get; }
    public ConnectionsViewModel ConnectionsVM { get; }
    public ToolsViewModel ToolsVM { get; }
    public SentinelViewModel SentinelVM { get; }

    public ICommand ToggleIncognitoCommand { get; }
    public ICommand SelectTabCommand { get; }

    public MainViewModel()
    {
        ResourcesVM = new ResourcesViewModel();
        FirewallVM = new FirewallViewModel();
        HistoryVM = new HistoryViewModel();
        ProcessesVM = new ProcessesViewModel();
        ConnectionsVM = new ConnectionsViewModel();
        ToolsVM = new ToolsViewModel();
        SentinelVM = new SentinelViewModel();

        ToggleIncognitoCommand = new RelayCommand(ToggleIncognito);
        SelectTabCommand = new RelayCommand(param =>
        {
            if (param is string tab)
            {
                SelectedTab = tab;
            }
        });

        IsIncognito = _telemetry.Tracker.IsIncognito;
        OnTabChanged(_selectedTab);

        UpdateNetworkStatus();
        NetworkChange.NetworkAvailabilityChanged += (_, _) => UpdateNetworkStatus();
        NetworkChange.NetworkAddressChanged += (_, _) => UpdateNetworkStatus();
        _telemetry.SnapshotUpdated += _ => UpdateNetworkStatus();
    }

    public void UpdateNetworkStatus()
    {
        void ApplyUpdate()
        {
            try
            {
                bool isAvailable = NetworkInterface.GetIsNetworkAvailable();
                if (!isAvailable)
                {
                    NetworkStatus = "Offline";
                    NetworkStatusTooltip = "Network Disconnected (Offline)";
                    IsOnline = false;
                    return;
                }

                var interfaces = NetworkInterface.GetAllNetworkInterfaces();
                var activeIfaces = interfaces.Where(ni =>
                    ni.OperationalStatus == OperationalStatus.Up &&
                    ni.NetworkInterfaceType != NetworkInterfaceType.Loopback).ToList();

                if (activeIfaces.Count == 0)
                {
                    NetworkStatus = "Offline";
                    NetworkStatusTooltip = "No active network interface (Offline)";
                    IsOnline = false;
                    return;
                }

                // Check for valid gateway or external routability
                bool hasGateway = activeIfaces.Any(ni =>
                {
                    try
                    {
                        var props = ni.GetIPProperties();
                        return props.GatewayAddresses.Any(g => g?.Address != null && 
                            !System.Net.IPAddress.Any.Equals(g.Address) && 
                            !System.Net.IPAddress.None.Equals(g.Address) &&
                            g.Address.ToString() != "0.0.0.0");
                    }
                    catch { return false; }
                });

                if (hasGateway)
                {
                    NetworkStatus = "Online";
                    NetworkStatusTooltip = "Network Connected (Online)";
                    IsOnline = true;
                }
                else
                {
                    NetworkStatus = "Degraded";
                    NetworkStatusTooltip = "Limited Connectivity / Local Only (Degraded)";
                    IsOnline = false;
                }
            }
            catch
            {
                NetworkStatus = "Offline";
                NetworkStatusTooltip = "Network Error (Offline)";
                IsOnline = false;
            }
        }

        if (System.Windows.Application.Current?.Dispatcher != null &&
            !System.Windows.Application.Current.Dispatcher.CheckAccess())
        {
            System.Windows.Application.Current.Dispatcher.InvokeAsync(ApplyUpdate);
        }
        else
        {
            ApplyUpdate();
        }
    }

    public void ToggleIncognito()
    {
        bool next = !_telemetry.Tracker.IsIncognito;
        _telemetry.Tracker.ToggleIncognito(next);
        IsIncognito = next;
    }
}
