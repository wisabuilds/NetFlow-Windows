using Microsoft.Win32;

namespace NetFlow.Platform.Windows.Services;

public static class WindowsStartupManager
{
    public const string RunRegistryKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    public const string AppValueName = "NetFlow";

    public static string GetAppPath()
    {
        return Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "NetFlow.App.exe");
    }

    public static bool IsStartupEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunRegistryKey, writable: false);
            if (key == null) return false;
            var val = key.GetValue(AppValueName);
            return val != null;
        }
        catch
        {
            return false;
        }
    }

    public static (bool Success, bool Enabled, string Path, string? Error) SetStartupEnabled(bool enable)
    {
        string path = GetAppPath();
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunRegistryKey, writable: true);
            if (key == null)
            {
                return (false, false, path, "Failed to open Run registry key with write access.");
            }

            if (enable)
            {
                string formattedPath = path.StartsWith("\"") && path.EndsWith("\"") ? path : $"\"{path}\"";
                key.SetValue(AppValueName, formattedPath);
            }
            else
            {
                key.DeleteValue(AppValueName, throwOnMissingValue: false);
            }

            return (true, enable, path, null);
        }
        catch (Exception ex)
        {
            return (false, IsStartupEnabled(), path, ex.Message);
        }
    }
}
