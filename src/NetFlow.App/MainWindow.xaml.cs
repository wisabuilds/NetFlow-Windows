using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using NetFlow.App.Services;
using NetFlow.App.ViewModels;
using NetFlow.Platform.Windows.Services;

namespace NetFlow.App;

public partial class MainWindow : Window
{
    private readonly MainViewModel _mainViewModel;
    private System.Windows.Forms.NotifyIcon? _notifyIcon;
    private bool _isExiting;

    public MainWindow()
    {
        InitializeComponent();

        _mainViewModel = new MainViewModel();
        DataContext = _mainViewModel;

        InitializeNotifyIcon();

        Loaded += MainWindow_Loaded;
        Closing += MainWindow_Closing;
        Closed += MainWindow_Closed;
    }

    private void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        // Update Tray tooltip in-memory on each telemetry tick
        TelemetryService.Instance.SnapshotUpdated += snapshot =>
        {
            if (_notifyIcon != null && _notifyIcon.Visible)
            {
                string tooltip = TrayTooltipHelper.FormatTooltip(snapshot.TotalRxSpeed, snapshot.TotalTxSpeed);
                try
                {
                    _notifyIcon.Text = tooltip;
                }
                catch { }
            }
        };
    }

    private void InitializeNotifyIcon()
    {
        try
        {
            _notifyIcon = new System.Windows.Forms.NotifyIcon();

            System.Drawing.Icon? appIcon = null;
            try
            {
                string? exe = Environment.ProcessPath;
                if (!string.IsNullOrEmpty(exe) && File.Exists(exe))
                {
                    appIcon = System.Drawing.Icon.ExtractAssociatedIcon(exe);
                }
            }
            catch { }

            _notifyIcon.Icon = appIcon ?? System.Drawing.SystemIcons.Application;
            _notifyIcon.Text = "NetFlow Windows";
            _notifyIcon.Visible = true;

            WindowsNotifier.NotificationHandler = (title, message) =>
            {
                Dispatcher.InvokeAsync(() =>
                {
                    try
                    {
                        _notifyIcon?.ShowBalloonTip(3000, title, message, System.Windows.Forms.ToolTipIcon.Info);
                    }
                    catch { }
                });
            };

            var menu = new System.Windows.Forms.ContextMenuStrip();

            var openItem = new System.Windows.Forms.ToolStripMenuItem("Open NetFlow", null, (_, _) => RestoreWindow());
            openItem.Font = new System.Drawing.Font(openItem.Font, System.Drawing.FontStyle.Bold);
            menu.Items.Add(openItem);

            menu.Items.Add(new System.Windows.Forms.ToolStripMenuItem("Toggle Incognito", null, (_, _) =>
            {
                _mainViewModel.ToggleIncognito();
            }));

            menu.Items.Add(new System.Windows.Forms.ToolStripSeparator());

            menu.Items.Add(new System.Windows.Forms.ToolStripMenuItem("Exit", null, (_, _) => ExitApplication()));

            _notifyIcon.ContextMenuStrip = menu;
            _notifyIcon.DoubleClick += (_, _) => RestoreWindow();
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Failed to initialize NotifyIcon: {ex.Message}");
        }
    }

    public void RestoreWindow()
    {
        Dispatcher.Invoke(() =>
        {
            Show();
            Visibility = Visibility.Visible;
            WindowState = WindowState.Normal;
            ShowInTaskbar = true;
            Activate();
        });
    }

    public void HideToTray()
    {
        Dispatcher.Invoke(() =>
        {
            Visibility = Visibility.Hidden;
            ShowInTaskbar = false;
        });
    }

    public void ExitApplication()
    {
        _isExiting = true;

        if (_notifyIcon != null)
        {
            _notifyIcon.Visible = false;
            _notifyIcon.Dispose();
            _notifyIcon = null;
        }

        Dispatcher.Invoke(() =>
        {
            System.Windows.Application.Current.Shutdown();
        });
    }

    private void Minimize_Click(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState.Minimized;
    }

    private void Maximize_Click(object sender, RoutedEventArgs e)
    {
        WindowState = (WindowState == WindowState.Maximized) ? WindowState.Normal : WindowState.Maximized;
    }

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        HideToTray();
    }

    protected override void OnStateChanged(EventArgs e)
    {
        base.OnStateChanged(e);
        if (MaximizeIcon != null)
        {
            MaximizeIcon.Data = System.Windows.Media.Geometry.Parse(
                WindowState == WindowState.Maximized
                    ? "M 2,0 H 10 V 8 H 8 M 0,2 H 8 V 10 H 0 Z"
                    : "M 0,0 H 10 V 10 H 0 Z");
        }
    }

    private void MainWindow_Closing(object? sender, CancelEventArgs e)
    {
        if (!_isExiting)
        {
            e.Cancel = true;
            HideToTray();
        }
    }

    private void MainWindow_Closed(object? sender, EventArgs e)
    {
        if (_isExiting)
        {
            _notifyIcon?.Dispose();
        }
    }
}
