using System.IO;
using System.Windows;
using NetFlow.App.Services;

namespace NetFlow.App;

public partial class App : System.Windows.Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        string logPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NetFlow",
            "crash.log");

        AppDomain.CurrentDomain.UnhandledException += (s, ev) =>
        {
            try
            {
                File.WriteAllText(logPath, ev.ExceptionObject.ToString());
            }
            catch { }
        };

        DispatcherUnhandledException += (s, ev) =>
        {
            try
            {
                File.WriteAllText(logPath, ev.Exception.ToString());
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
