using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Input;
using NetFlow.App.Services;
using NetFlow.Core.Models;
using MessageBox = System.Windows.MessageBox;

namespace NetFlow.App.ViewModels;

public class ConnectionItemViewModel : ViewModelBase
{
    private string _processName = string.Empty;
    private int _pid;
    private string _remoteDestination = string.Empty;
    private string _remoteIp = string.Empty;
    private int _remotePort;
    private string _localEndpoint = string.Empty;
    private string _state = string.Empty;
    private string _protocol = "TCP";
    private string _geoFlag = "🌐";
    private string _country = "--";
    private string _policy = "Allow";

    public string ProcessName { get => _processName; set => SetProperty(ref _processName, value); }
    public int Pid { get => _pid; set => SetProperty(ref _pid, value); }
    public string RemoteDestination { get => _remoteDestination; set => SetProperty(ref _remoteDestination, value); }
    public string RemoteIp { get => _remoteIp; set => SetProperty(ref _remoteIp, value); }
    public int RemotePort { get => _remotePort; set => SetProperty(ref _remotePort, value); }
    public string LocalEndpoint { get => _localEndpoint; set => SetProperty(ref _localEndpoint, value); }
    public string State { get => _state; set => SetProperty(ref _state, value); }
    public string Protocol { get => _protocol; set => SetProperty(ref _protocol, value); }
    public string GeoFlag { get => _geoFlag; set => SetProperty(ref _geoFlag, value); }
    public string Country { get => _country; set => SetProperty(ref _country, value); }
    public string Policy { get => _policy; set => SetProperty(ref _policy, value); }

    public string RemoteSummary => $"{GeoFlag} {RemoteDestination} ({Country})";
    public string LocalSummary => $"{Protocol} {LocalEndpoint} [{State}]";
}

public class ConnectionsViewModel : ViewModelBase
{
    private readonly TelemetryService _telemetry = TelemetryService.Instance;
    private string _searchText = string.Empty;
    private readonly List<ConnectionItemViewModel> _allConnections = new();

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

    public ObservableCollection<ConnectionItemViewModel> FilteredConnections { get; } = new();

    public ICommand RefreshCommand { get; }
    public ICommand SeverCommand { get; }
    public ICommand BlockIpCommand { get; }

    public bool IsActive { get; set; } = false;
    private int _snapshotCounter;

    public ConnectionsViewModel()
    {
        RefreshCommand = new RelayCommand(RefreshConnections);
        SeverCommand = new RelayCommand(param => SeverConnection(param as ConnectionItemViewModel));
        BlockIpCommand = new RelayCommand(param => BlockIp(param as ConnectionItemViewModel));

        RefreshConnections();

        _telemetry.SnapshotUpdated += _ =>
        {
            if (!IsActive) return;
            if (Interlocked.Increment(ref _snapshotCounter) % 2 == 0)
            {
                if (System.Windows.Application.Current?.Dispatcher != null)
                {
                    System.Windows.Application.Current.Dispatcher.InvokeAsync(RefreshConnections);
                }
                else
                {
                    RefreshConnections();
                }
            }
        };
    }

    public void RefreshConnections()
    {
        try
        {
            var sockets = _telemetry.Tracker.GetActiveSocketsEnriched();
            _telemetry.GeoIp.EnrichList(sockets);

            var items = new List<ConnectionItemViewModel>();
            foreach (var s in sockets)
            {
                string proc = string.IsNullOrEmpty(s.ProcessName) ? "System" : s.ProcessName;
                string remoteIp = s.RemoteIp ?? "0.0.0.0";
                int remotePort = s.RemotePort;
                string localIp = s.LocalIp ?? "0.0.0.0";
                int localPort = s.LocalPort;

                string flag = string.IsNullOrEmpty(s.CountryFlag) ? "🌐" : s.CountryFlag;
                string country = s.CountryCode ?? "--";

                bool isBlocked = _telemetry.Firewall.IsAppBlocked(proc);

                items.Add(new ConnectionItemViewModel
                {
                    ProcessName = proc,
                    Pid = s.Pid ?? 0,
                    RemoteIp = remoteIp,
                    RemotePort = remotePort,
                    RemoteDestination = $"{remoteIp}:{remotePort}",
                    LocalEndpoint = $"{localIp}:{localPort}",
                    State = s.State ?? "ESTABLISHED",
                    Protocol = s.Protocol ?? "TCP",
                    GeoFlag = flag,
                    Country = country,
                    Policy = isBlocked ? "Blocked" : "Allow"
                });
            }

            _allConnections.Clear();
            _allConnections.AddRange(items);
            ApplyFilter();
        }
        catch { }
    }

    public void SeverConnection(ConnectionItemViewModel? conn)
    {
        if (conn == null) return;
        var res = _telemetry.ActiveDefense.SeverConnection(conn.RemoteIp, conn.RemotePort, pid: conn.Pid > 0 ? conn.Pid : null);
        if (res.Success)
        {
            MessageBox.Show($"Severed connection to {conn.RemoteDestination}.", "Connection Severed", MessageBoxButton.OK, MessageBoxImage.Information);
            RefreshConnections();
        }
        else
        {
            string err = res.ElevationRequired ? "Administrator privileges required to sever socket." : res.Error ?? "Failed to sever connection.";
            MessageBox.Show(err, "Action Failed", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    public void BlockIp(ConnectionItemViewModel? conn)
    {
        if (conn == null || string.IsNullOrWhiteSpace(conn.RemoteIp)) return;
        var res = _telemetry.ActiveDefense.BlockIp(conn.RemoteIp, "User severed from GUI");
        if (res.Success)
        {
            MessageBox.Show($"Blocked destination IP {conn.RemoteIp} via Windows Firewall.", "IP Blocked", MessageBoxButton.OK, MessageBoxImage.Information);
            RefreshConnections();
        }
        else
        {
            string err = res.ElevationRequired ? "Administrator privileges required to configure Windows Firewall." : res.Error ?? "Failed to block IP.";
            MessageBox.Show(err, "Action Failed", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void ApplyFilter()
    {
        FilteredConnections.Clear();
        var q = _searchText?.Trim() ?? string.Empty;
        var matches = string.IsNullOrEmpty(q)
            ? _allConnections
            : _allConnections.Where(c => c.ProcessName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                                         c.RemoteDestination.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                                         c.Country.Contains(q, StringComparison.OrdinalIgnoreCase));

        foreach (var c in matches)
        {
            FilteredConnections.Add(c);
        }
    }
}
