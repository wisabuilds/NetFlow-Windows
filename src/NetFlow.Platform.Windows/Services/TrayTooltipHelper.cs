namespace NetFlow.Platform.Windows.Services;

public static class TrayTooltipHelper
{
    public const int MaxTooltipLength = 63;

    public static string FormatSpeed(double bytesPerSec)
    {
        if (bytesPerSec < 1024) return $"{bytesPerSec:F0} B/s";
        if (bytesPerSec < 1024 * 1024) return $"{bytesPerSec / 1024:F1} KB/s";
        if (bytesPerSec < 1024 * 1024 * 1024) return $"{bytesPerSec / (1024 * 1024):F1} MB/s";
        return $"{bytesPerSec / (1024 * 1024 * 1024):F2} GB/s";
    }

    public static string FormatTooltip(double rxBytesPerSec, double txBytesPerSec)
    {
        string tip = $"NetFlow - ↓ {FormatSpeed(rxBytesPerSec)} | ↑ {FormatSpeed(txBytesPerSec)}";
        if (tip.Length > MaxTooltipLength)
        {
            tip = tip.Substring(0, MaxTooltipLength);
        }
        return tip;
    }
}
