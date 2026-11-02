using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Windows.Input;
using Microsoft.Win32;
using NetFlow.App.Services;
using MessageBox = System.Windows.MessageBox;
using SaveFileDialog = Microsoft.Win32.SaveFileDialog;

namespace NetFlow.App.ViewModels;

public class DailyHistoryRow : ViewModelBase
{
    public string Date { get; set; } = string.Empty;
    public string RxHuman { get; set; } = string.Empty;
    public string TxHuman { get; set; } = string.Empty;
    public string TotalHuman { get; set; } = string.Empty;
}

public class TopAppHistoryRow : ViewModelBase
{
    public string Name { get; set; } = string.Empty;
    public string RxHuman { get; set; } = string.Empty;
    public string TxHuman { get; set; } = string.Empty;
    public string TotalHuman { get; set; } = string.Empty;
}

public class HistoryViewModel : ViewModelBase
{
    private readonly TelemetryService _telemetry = TelemetryService.Instance;

    private string _todayText = "0.00 MB";
    private string _yesterdayText = "0.00 MB";
    private string _weekText = "0.00 MB";
    private string _monthText = "0.00 MB";

    public string TodayText { get => _todayText; set => SetProperty(ref _todayText, value); }
    public string YesterdayText { get => _yesterdayText; set => SetProperty(ref _yesterdayText, value); }
    public string WeekText { get => _weekText; set => SetProperty(ref _weekText, value); }
    public string MonthText { get => _monthText; set => SetProperty(ref _monthText, value); }

    public ObservableCollection<DailyHistoryRow> DailyRecords { get; } = new();
    public ObservableCollection<TopAppHistoryRow> TopApps { get; } = new();

    public ICommand ExportDailyCsvCommand { get; }
    public ICommand ExportAppsCsvCommand { get; }
    public ICommand ExportJsonCommand { get; }

    public bool IsActive { get; set; }
    private int _snapshotCounter;

    public HistoryViewModel()
    {
        ExportDailyCsvCommand = new RelayCommand(ExportDailyCsv);
        ExportAppsCsvCommand = new RelayCommand(ExportAppsCsv);
        ExportJsonCommand = new RelayCommand(ExportJson);

        LoadHistoryData();
        _telemetry.SnapshotUpdated += _ =>
        {
            if (!IsActive) return;
            if (Interlocked.Increment(ref _snapshotCounter) % 2 == 0)
            {
                if (System.Windows.Application.Current?.Dispatcher != null)
                {
                    System.Windows.Application.Current.Dispatcher.InvokeAsync(LoadHistoryData);
                }
                else
                {
                    LoadHistoryData();
                }
            }
        };
    }

    public void LoadHistoryData()
    {
        try
        {
            var summary = _telemetry.Storage.GetUsageSummary();
            long todayBytes = summary.TryGetValue("today_total_bytes", out var tb) && tb != null ? Convert.ToInt64(tb) : 0;
            TodayText = TelemetryService.FormatBytes(todayBytes);

            // Daily History
            var daily = _telemetry.Storage.GetDailyUsage(30);
            DailyRecords.Clear();

            long weekSum = 0;
            long monthSum = 0;
            long yesterdaySum = 0;

            string todayDate = DateTime.UtcNow.ToString("yyyy-MM-dd");
            string yesterdayDate = DateTime.UtcNow.AddDays(-1).ToString("yyyy-MM-dd");

            var rows = new List<DailyHistoryRow>();
            long todaySum = 0;
            bool foundToday = false;
            foreach (var d in daily)
            {
                string date = d.TryGetValue("date", out var dt) ? dt?.ToString() ?? "" : "";
                long rx = d.TryGetValue("rx_bytes", out var rxb) && rxb != null ? Convert.ToInt64(rxb) : 0;
                long tx = d.TryGetValue("tx_bytes", out var txb) && txb != null ? Convert.ToInt64(txb) : 0;
                long total = d.TryGetValue("total_bytes", out var tot) && tot != null ? Convert.ToInt64(tot) : rx + tx;

                if (date == todayDate)
                {
                    todaySum = total;
                    foundToday = true;
                }
                if (date == yesterdayDate) yesterdaySum = total;
                monthSum += total;

                rows.Add(new DailyHistoryRow
                {
                    Date = date,
                    RxHuman = TelemetryService.FormatBytes(rx),
                    TxHuman = TelemetryService.FormatBytes(tx),
                    TotalHuman = TelemetryService.FormatBytes(total)
                });
            }

            rows.Reverse();
            foreach (var r in rows) DailyRecords.Add(r);

            // Sum last 7 days
            for (int i = Math.Max(0, daily.Count - 7); i < daily.Count; i++)
            {
                if (daily[i].TryGetValue("total_bytes", out var tot) && tot != null)
                    weekSum += Convert.ToInt64(tot);
            }

            if (foundToday)
            {
                TodayText = TelemetryService.FormatBytes(todaySum);
            }
            YesterdayText = TelemetryService.FormatBytes(yesterdaySum);
            WeekText = TelemetryService.FormatBytes(weekSum);
            MonthText = TelemetryService.FormatBytes(monthSum);

            // Top Apps
            var apps = _telemetry.Storage.GetTopProcesses(86400, 15);
            TopApps.Clear();
            foreach (var a in apps)
            {
                string name = a.TryGetValue("process_name", out var pn) ? pn?.ToString() ?? "" : "";
                long rx = a.TryGetValue("rx_bytes", out var rxb) && rxb != null ? Convert.ToInt64(rxb) : 0;
                long tx = a.TryGetValue("tx_bytes", out var txb) && txb != null ? Convert.ToInt64(txb) : 0;
                long total = a.TryGetValue("total_bytes", out var tot) && tot != null ? Convert.ToInt64(tot) : rx + tx;

                TopApps.Add(new TopAppHistoryRow
                {
                    Name = name,
                    RxHuman = TelemetryService.FormatBytes(rx),
                    TxHuman = TelemetryService.FormatBytes(tx),
                    TotalHuman = TelemetryService.FormatBytes(total)
                });
            }
        }
        catch { }
    }

    private void ExportDailyCsv()
    {
        try
        {
            var sfd = new SaveFileDialog
            {
                Filter = "CSV File (*.csv)|*.csv",
                FileName = "netflow_daily_history.csv"
            };
            if (sfd.ShowDialog() == true)
            {
                string csv = _telemetry.Storage.ExportDailyCsv();
                File.WriteAllText(sfd.FileName, csv);
                MessageBox.Show("Daily history exported successfully.", "Export Complete", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to export CSV: {ex.Message}", "Export Error", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
        }
    }

    private void ExportAppsCsv()
    {
        try
        {
            var sfd = new SaveFileDialog
            {
                Filter = "CSV File (*.csv)|*.csv",
                FileName = "netflow_applications.csv"
            };
            if (sfd.ShowDialog() == true)
            {
                string csv = _telemetry.Storage.ExportProcessesCsv();
                File.WriteAllText(sfd.FileName, csv);
                MessageBox.Show("Applications history exported successfully.", "Export Complete", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to export CSV: {ex.Message}", "Export Error", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
        }
    }

    private void ExportJson()
    {
        try
        {
            var sfd = new SaveFileDialog
            {
                Filter = "JSON File (*.json)|*.json",
                FileName = "netflow_report.json"
            };
            if (sfd.ShowDialog() == true)
            {
                var exportData = new
                {
                    daily = _telemetry.Storage.GetDailyUsage(90),
                    top_processes = _telemetry.Storage.GetTopProcesses(30 * 86400),
                    plan = _telemetry.Storage.GetDataPlanStatus(),
                    exported_at = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                };
                string json = JsonSerializer.Serialize(exportData, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(sfd.FileName, json);
                MessageBox.Show("JSON report exported successfully.", "Export Complete", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to export JSON: {ex.Message}", "Export Error", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
        }
    }
}
