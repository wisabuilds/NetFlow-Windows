using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Input;
using NetFlow.App.Services;
using NetFlow.Core.Models;
using MessageBox = System.Windows.MessageBox;

namespace NetFlow.App.ViewModels;

public class ProcessItemViewModel : ViewModelBase
{
    private string _name = string.Empty;
    private int _pid;
    private string _transferRateText = "0 B/s";
    private string _securityPublisher = "Verified";
    private string _riskLevel = "Safe";
    private int _socketCount;
    private string _endpointsSummary = "--";

    public string Name { get => _name; set => SetProperty(ref _name, value); }
    public int Pid { get => _pid; set => SetProperty(ref _pid, value); }
    public string TransferRateText { get => _transferRateText; set => SetProperty(ref _transferRateText, value); }
    public string SecurityPublisher { get => _securityPublisher; set => SetProperty(ref _securityPublisher, value); }
    public string RiskLevel { get => _riskLevel; set => SetProperty(ref _riskLevel, value); }
    public int SocketCount { get => _socketCount; set => SetProperty(ref _socketCount, value); }
    public string EndpointsSummary { get => _endpointsSummary; set => SetProperty(ref _endpointsSummary, value); }
}

public class ProcessesViewModel : ViewModelBase
{
    private readonly TelemetryService _telemetry = TelemetryService.Instance;
    private string _searchText = string.Empty;
    private readonly List<ProcessItemViewModel> _allProcesses = new();

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

    public ObservableCollection<ProcessItemViewModel> FilteredProcesses { get; } = new();

    public ICommand TerminateProcessCommand { get; }

    public ProcessesViewModel()
    {
        TerminateProcessCommand = new RelayCommand(param => TerminateProcess(param as ProcessItemViewModel));
        _telemetry.SnapshotUpdated += HandleSnapshot;
    }

    public void TerminateProcess(ProcessItemViewModel? proc)
    {
        if (proc == null || proc.Pid <= 0) return;

        var result = _telemetry.ActiveDefense.KillProcess(proc.Pid);
        if (result.Success)
        {
            MessageBox.Show($"Terminated process {proc.Name} (PID {proc.Pid}).", "Process Terminated", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        else
        {
            string err = result.ElevationRequired ? "Administrator privileges required to terminate this process." : result.Error ?? "Failed to kill process.";
            MessageBox.Show(err, "Termination Error", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void HandleSnapshot(RealtimeSnapshot snapshot)
    {
        var existingByPid = _allProcesses.ToDictionary(p => p.Pid);
        var currentItems = new List<ProcessItemViewModel>();

        foreach (var p in snapshot.TopProcesses)
        {
            string epSummary = "--";
            if (p.RemoteEndpoints != null && p.RemoteEndpoints.Count > 0)
            {
                epSummary = string.Join(", ", p.RemoteEndpoints.Take(2));
                if (p.RemoteEndpoints.Count > 2) epSummary += $" (+{p.RemoteEndpoints.Count - 2})";
            }

            string pub = p.Threat?.Publisher ?? "Verified";
            string risk = p.Threat?.Level.ToString() ?? "Safe";

            if (existingByPid.TryGetValue(p.Pid, out var existing))
            {
                existing.Name = p.Name;
                existing.TransferRateText = $"{p.TransferRateKbps:F1} KB/s";
                existing.SecurityPublisher = string.IsNullOrEmpty(pub) ? "Unsigned / Unknown" : pub;
                existing.RiskLevel = risk;
                existing.SocketCount = p.ActiveConnections;
                existing.EndpointsSummary = epSummary;
                currentItems.Add(existing);
            }
            else
            {
                currentItems.Add(new ProcessItemViewModel
                {
                    Name = p.Name,
                    Pid = p.Pid,
                    TransferRateText = $"{p.TransferRateKbps:F1} KB/s",
                    SecurityPublisher = string.IsNullOrEmpty(pub) ? "Unsigned / Unknown" : pub,
                    RiskLevel = risk,
                    SocketCount = p.ActiveConnections,
                    EndpointsSummary = epSummary
                });
            }
        }

        _allProcesses.Clear();
        _allProcesses.AddRange(currentItems);
        ApplyFilter();
    }

    private void ApplyFilter()
    {
        var q = _searchText?.Trim() ?? string.Empty;
        var matches = (string.IsNullOrEmpty(q)
            ? _allProcesses
            : _allProcesses.Where(p => p.Name.Contains(q, StringComparison.OrdinalIgnoreCase) || p.Pid.ToString().Contains(q))).ToList();

        for (int i = FilteredProcesses.Count - 1; i >= 0; i--)
        {
            if (!matches.Contains(FilteredProcesses[i]))
            {
                FilteredProcesses.RemoveAt(i);
            }
        }

        for (int i = 0; i < matches.Count; i++)
        {
            var item = matches[i];
            int curIdx = FilteredProcesses.IndexOf(item);
            if (curIdx < 0)
            {
                FilteredProcesses.Insert(Math.Min(i, FilteredProcesses.Count), item);
            }
            else if (curIdx != i)
            {
                FilteredProcesses.Move(curIdx, i);
            }
        }
    }
}
