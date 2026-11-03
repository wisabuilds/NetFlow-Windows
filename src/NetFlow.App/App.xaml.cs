using System.IO;
using System.Windows;
using NetFlow.App.Services;

namespace NetFlow.App;

public partial class App : System.Windows.Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        string netflowDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NetFlow");
        string logPath = Path.Combine(netflowDir, "crash.log");

        try
        {
            if (!Directory.Exists(netflowDir))
            {
                Directory.CreateDirectory(netflowDir);
            }
        }
        catch { }

        AppDomain.CurrentDomain.UnhandledException += (s, ev) =>
        {
            try
            {
                string entry = $"[{DateTime.UtcNow:O}] [AppDomain Unhandled] {ev.ExceptionObject}\n\n";
                File.AppendAllText(logPath, entry);
            }
            catch { }
        };

        DispatcherUnhandledException += (s, ev) =>
        {
            try
            {
                string entry = $"[{DateTime.UtcNow:O}] [Dispatcher Unhandled] {ev.Exception}\n\n";
                File.AppendAllText(logPath, entry);
            }
            catch { }
            ev.Handled = true;
        };

        // Start in-memory telemetry engine
        TelemetryService.Instance.Start();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        TelemetryService.Instance.Dispose();
        base.OnExit(e);
    }
}
