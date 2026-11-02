using System.Windows;
using UserControl = System.Windows.Controls.UserControl;
using NetFlow.App.Services;
using NetFlow.App.ViewModels;

namespace NetFlow.App.Views;

public partial class ResourcesView : UserControl
{
    private ResourcesViewModel? _vm;

    public ResourcesView()
    {
        InitializeComponent();
        Loaded += ResourcesView_Loaded;
        Unloaded += ResourcesView_Unloaded;
    }

    private void ResourcesView_Loaded(object sender, RoutedEventArgs e)
    {
        if (DataContext is ResourcesViewModel vm)
        {
            _vm = vm;

            try
            {
                var history = TelemetryService.Instance.Storage.GetRecentSpeeds(60);
                if (history.Count > 0)
                {
                    var rx = history.Select(h => h.TryGetValue("rx_speed", out var r) ? Convert.ToDouble(r) : 0.0).ToList();
                    var tx = history.Select(h => h.TryGetValue("tx_speed", out var t) ? Convert.ToDouble(t) : 0.0).ToList();
                    TrafficGraphHost.SetHistory(rx, tx);
                    vm.GraphMaxLabel = $"Max: {TelemetryService.FormatSpeed(TrafficGraphHost.GetCurrentMaxScale())}";
                }
            }
            catch { }

            _vm.OnNewSpeedSample -= OnSpeedSample;
            _vm.OnNewSpeedSample += OnSpeedSample;
        }
    }

    private void ResourcesView_Unloaded(object sender, RoutedEventArgs e)
    {
        if (_vm != null)
        {
            _vm.OnNewSpeedSample -= OnSpeedSample;
        }
    }

    private void OnSpeedSample(double rx, double tx)
    {
        Dispatcher.InvokeAsync(() =>
        {
            TrafficGraphHost.UpdateSpeeds(rx, tx);
            if (_vm != null)
            {
                _vm.GraphMaxLabel = $"Max: {TelemetryService.FormatSpeed(TrafficGraphHost.GetCurrentMaxScale())}";
            }
        });
    }
}
