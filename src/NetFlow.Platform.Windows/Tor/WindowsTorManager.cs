using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using NetFlow.Core.Models;
using NetFlow.Core.Services;
using NetFlow.Platform.Windows.Native;

namespace NetFlow.Platform.Windows.Tor;

public class WindowsTorManager : ITorManager
{
    private const string INTERNET_SETTINGS_KEY = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    public TorStatusInfo GetStatus()
    {
        bool isListening = IsTorListening(out int activePort);
        bool isProxyEnabled = IsSystemProxyEnabled();

        return new TorStatusInfo
        {
            IsTorListening = isListening,
            ActivePort = activePort,
            IsSystemProxyEnabled = isProxyEnabled
        };
    }

    public (bool Success, string Message) EnableSystemProxy(int port = 9050)
    {
        try
        {
            string proxyServer = $"socks=127.0.0.1:{port}";

            using var key = Registry.CurrentUser.OpenSubKey(INTERNET_SETTINGS_KEY, true);
            if (key == null)
            {
                return (false, "Failed to access Windows Internet Settings registry key.");
            }

            key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
            key.SetValue("ProxyServer", proxyServer, RegistryValueKind.String);

            // Flush WinINet settings cache so browsers pick it up immediately
            Kernel32.InternetSetOption(IntPtr.Zero, Kernel32.INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
            Kernel32.InternetSetOption(IntPtr.Zero, Kernel32.INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);

            return (true, $"System proxy routed through Tor SOCKS5 (127.0.0.1:{port}).");
        }
        catch (Exception ex)
        {
            return (false, $"Error configuring system proxy: {ex.Message}");
        }
    }

    public (bool Success, string Message) DisableSystemProxy()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(INTERNET_SETTINGS_KEY, true);
            if (key == null)
            {
                return (false, "Failed to access Windows Internet Settings registry key.");
            }

            key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);

            // Flush WinINet
            Kernel32.InternetSetOption(IntPtr.Zero, Kernel32.INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
            Kernel32.InternetSetOption(IntPtr.Zero, Kernel32.INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);

            return (true, "System proxy disabled. Direct network connection restored.");
        }
        catch (Exception ex)
        {
            return (false, $"Error disabling system proxy: {ex.Message}");
        }
    }

    private static bool IsSystemProxyEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(INTERNET_SETTINGS_KEY, false);
            if (key == null) return false;

            object? val = key.GetValue("ProxyEnable");
            if (val != null && int.TryParse(val.ToString(), out int enabled))
            {
                return enabled == 1;
            }
        }
        catch { }
        return false;
    }

    private static bool IsTorListening(out int activePort)
    {
        activePort = 9050;
        if (ProbeSocksPort(9050))
        {
            activePort = 9050;
            return true;
        }
        if (ProbeSocksPort(9150))
        {
            activePort = 9150;
            return true;
        }
        return false;
    }

    private static bool ProbeSocksPort(int port)
    {
        try
        {
            using var client = new TcpClient();
            var ar = client.BeginConnect("127.0.0.1", port, null, null);
            bool ok = ar.AsyncWaitHandle.WaitOne(200);
            if (!ok) return false;
            client.EndConnect(ar);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
