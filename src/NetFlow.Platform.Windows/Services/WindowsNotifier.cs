using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace NetFlow.Platform.Windows.Services;

public static class WindowsNotifier
{
    private static readonly object _lock = new();
    private static double _lastNotificationTime;

    public static bool IsEnabled { get; set; } = true;
    public static Action<string, string>? NotificationHandler { get; set; }
    public static Func<bool>? StorageCheck { get; set; }

    public static void ResetRateLimitForTesting()
    {
        lock (_lock)
        {
            _lastNotificationTime = 0;
        }
    }

    public static bool CheckRateLimit(double? timestamp = null)
    {
        double now = timestamp ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        lock (_lock)
        {
            if (now - _lastNotificationTime < 1.0)
            {
                return false;
            }
            _lastNotificationTime = now;
            return true;
        }
    }

    public static void SendNotification(string title, string message)
    {
        // 1. Strictly honor settings before dispatching
        if (!IsEnabled) return;
        if (StorageCheck != null && !StorageCheck()) return;

        // 2. Direct registered handler if available
        if (NotificationHandler != null)
        {
            try
            {
                NotificationHandler.Invoke(title, message);
                return;
            }
            catch { }
        }

        // 3. Rate limiting: 1 second cooldown on system toasts to prevent alert storms
        if (!CheckRateLimit())
        {
            return;
        }

        // 4. Dispatch zero-overhead native WinRT toast without spawning powershell.exe
        try
        {
            if (TryShowWinRtToast(title, message))
            {
                return;
            }
        }
        catch { }

        // 5. Fallback: Shell NotifyIcon balloon if WinRT is unavailable
        try
        {
            ShowNativeShellBalloon(title, message);
        }
        catch { }
    }

    #region Zero-Overhead Native WinRT Interop

    public static bool TryShowWinRtToastForTesting(string title, string message) => TryShowWinRtToast(title, message);

    private static bool TryShowWinRtToast(string title, string message)
    {
        // Initialize COM on calling thread (1 = RO_INIT_MULTITHREADED)
        int hrInit = Combase.RoInitialize(1);
        bool needsUninit = (hrInit == 0 || hrInit == 1);

        try
        {
            // AUMID for unpackaged desktop app
            string appId = "NetFlow.Windows.App";

            // 1. Get ToastNotificationManagerStatics factory
            var managerIid = new Guid("50AC103F-D235-4598-BBEF-98FE4D1A3AD4");
            IntPtr hManagerStr = IntPtr.Zero;
            IntPtr managerFactory = IntPtr.Zero;
            IntPtr notifier = IntPtr.Zero;
            IntPtr hAppId = IntPtr.Zero;

            IntPtr hXmlDocStr = IntPtr.Zero;
            IntPtr xmlDocInstance = IntPtr.Zero;
            IntPtr hXmlContent = IntPtr.Zero;

            IntPtr hToastStr = IntPtr.Zero;
            IntPtr toastFactory = IntPtr.Zero;
            IntPtr toastNotification = IntPtr.Zero;

            try
            {
                int hr = Combase.WindowsCreateString("Windows.UI.Notifications.ToastNotificationManager", 49, out hManagerStr);
                if (hr != 0) return false;

                hr = Combase.RoGetActivationFactory(hManagerStr, in managerIid, out managerFactory);
                if (hr != 0 || managerFactory == IntPtr.Zero) return false;

                Combase.WindowsCreateString(appId, appId.Length, out hAppId);

                // Slot 7: CreateToastNotifierWithId(HSTRING applicationId, out IToastNotifier)
                unsafe
                {
                    IntPtr* vtable = *(IntPtr**)managerFactory;
                    delegate* unmanaged[Stdcall]<IntPtr, IntPtr, out IntPtr, int> createNotifier =
                        (delegate* unmanaged[Stdcall]<IntPtr, IntPtr, out IntPtr, int>)vtable[7];
                    hr = createNotifier(managerFactory, hAppId, out notifier);
                    if (hr != 0 || notifier == IntPtr.Zero)
                    {
                        // Fallback to slot 6: CreateToastNotifier(out IToastNotifier)
                        delegate* unmanaged[Stdcall]<IntPtr, out IntPtr, int> createNotifierDef =
                            (delegate* unmanaged[Stdcall]<IntPtr, out IntPtr, int>)vtable[6];
                        hr = createNotifierDef(managerFactory, out notifier);
                    }
                }
                if (hr != 0 || notifier == IntPtr.Zero) return false;

                // 2. Create XmlDocument
                hr = Combase.WindowsCreateString("Windows.Data.Xml.Dom.XmlDocument", 31, out hXmlDocStr);
                if (hr != 0) return false;

                hr = Combase.RoActivateInstance(hXmlDocStr, out xmlDocInstance);
                if (hr != 0 || xmlDocInstance == IntPtr.Zero) return false;

                // Escape title and message for XML
                string safeTitle = SecurityElement.Escape(title) ?? title;
                string safeMessage = SecurityElement.Escape(message) ?? message;
                string xml = $"<toast><visual><binding template=\"ToastGeneric\"><text>{safeTitle}</text><text>{safeMessage}</text></binding></visual></toast>";

                Combase.WindowsCreateString(xml, xml.Length, out hXmlContent);

                // Query IXmlDocumentIO (6CD3148A-291D-4E2F-9C7B-3E6173784603)
                var ioIid = new Guid("6CD3148A-291D-4E2F-9C7B-3E6173784603");
                hr = Marshal.QueryInterface(xmlDocInstance, in ioIid, out IntPtr xmlIo);
                if (hr != 0 || xmlIo == IntPtr.Zero) return false;

                try
                {
                    unsafe
                    {
                        IntPtr* ioVtable = *(IntPtr**)xmlIo;
                        // Slot 6: LoadXml(HSTRING xml)
                        delegate* unmanaged[Stdcall]<IntPtr, IntPtr, int> loadXml =
                            (delegate* unmanaged[Stdcall]<IntPtr, IntPtr, int>)ioVtable[6];
                        hr = loadXml(xmlIo, hXmlContent);
                    }
                    if (hr != 0) return false;
                }
                finally
                {
                    Marshal.Release(xmlIo);
                }

                // 3. Create ToastNotification via IToastNotificationFactory
                hr = Combase.WindowsCreateString("Windows.UI.Notifications.ToastNotification", 42, out hToastStr);
                if (hr != 0) return false;

                var toastFactoryIid = new Guid("04124B20-82C6-4229-B109-FD9ED4662B53");
                hr = Combase.RoGetActivationFactory(hToastStr, in toastFactoryIid, out toastFactory);
                if (hr != 0 || toastFactory == IntPtr.Zero) return false;

                unsafe
                {
                    IntPtr* tfVtable = *(IntPtr**)toastFactory;
                    // Slot 6: CreateToastNotification(IntPtr xmlDoc, out IntPtr notification)
                    delegate* unmanaged[Stdcall]<IntPtr, IntPtr, out IntPtr, int> createToast =
                        (delegate* unmanaged[Stdcall]<IntPtr, IntPtr, out IntPtr, int>)tfVtable[6];
                    hr = createToast(toastFactory, xmlDocInstance, out toastNotification);
                }
                if (hr != 0 || toastNotification == IntPtr.Zero) return false;

                // 4. Show Toast Notification
                unsafe
                {
                    IntPtr* notifVtable = *(IntPtr**)notifier;
                    // Slot 6: Show(IntPtr notification)
                    delegate* unmanaged[Stdcall]<IntPtr, IntPtr, int> show =
                        (delegate* unmanaged[Stdcall]<IntPtr, IntPtr, int>)notifVtable[6];
                    hr = show(notifier, toastNotification);
                }

                return hr == 0;
            }
            finally
            {
                if (toastNotification != IntPtr.Zero) Marshal.Release(toastNotification);
                if (toastFactory != IntPtr.Zero) Marshal.Release(toastFactory);
                if (hToastStr != IntPtr.Zero) Combase.WindowsDeleteString(hToastStr);

                if (hXmlContent != IntPtr.Zero) Combase.WindowsDeleteString(hXmlContent);
                if (xmlDocInstance != IntPtr.Zero) Marshal.Release(xmlDocInstance);
                if (hXmlDocStr != IntPtr.Zero) Combase.WindowsDeleteString(hXmlDocStr);

                if (hAppId != IntPtr.Zero) Combase.WindowsDeleteString(hAppId);
                if (notifier != IntPtr.Zero) Marshal.Release(notifier);
                if (managerFactory != IntPtr.Zero) Marshal.Release(managerFactory);
                if (hManagerStr != IntPtr.Zero) Combase.WindowsDeleteString(hManagerStr);
            }
        }
        catch
        {
            return false;
        }
        finally
        {
            if (needsUninit)
            {
                try { Combase.RoUninitialize(); } catch { }
            }
        }
    }

    private static class Combase
    {
        [DllImport("combase.dll")]
        public static extern int RoInitialize(int initType);

        [DllImport("combase.dll")]
        public static extern void RoUninitialize();

        [DllImport("combase.dll")]
        public static extern int RoGetActivationFactory(IntPtr activatableClassId, in Guid iid, out IntPtr factory);

        [DllImport("combase.dll")]
        public static extern int RoActivateInstance(IntPtr activatableClassId, out IntPtr instance);

        [DllImport("combase.dll")]
        public static extern int WindowsCreateString([MarshalAs(UnmanagedType.LPWStr)] string sourceString, int length, out IntPtr hstring);

        [DllImport("combase.dll")]
        public static extern int WindowsDeleteString(IntPtr hstring);
    }

    #endregion

    #region Native Shell NotifyIcon Balloon Fallback

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NOTIFYICONDATA
    {
        public int cbSize;
        public IntPtr hWnd;
        public uint uID;
        public uint uFlags;
        public uint uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szTip;
        public int dwState;
        public int dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szInfo;
        public uint uTimeoutOrVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string szInfoTitle;
        public int dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

    private const uint NIM_ADD = 0x00000000;
    private const uint NIM_MODIFY = 0x00000001;
    private const uint NIM_DELETE = 0x00000002;
    private const uint NIF_MESSAGE = 0x00000001;
    private const uint NIF_ICON = 0x00000002;
    private const uint NIF_TIP = 0x00000004;
    private const uint NIF_INFO = 0x00000010;
    private const int NIIF_INFO = 0x00000001;

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern bool Shell_NotifyIcon(uint dwMessage, ref NOTIFYICONDATA lpData);

    private static void ShowNativeShellBalloon(string title, string message)
    {
        try
        {
            var nid = new NOTIFYICONDATA
            {
                cbSize = Marshal.SizeOf<NOTIFYICONDATA>(),
                hWnd = IntPtr.Zero,
                uID = 1001,
                uFlags = NIF_INFO | NIF_TIP,
                szTip = "NetFlow Windows",
                szInfoTitle = title.Length > 63 ? title.Substring(0, 63) : title,
                szInfo = message.Length > 255 ? message.Substring(0, 255) : message,
                dwInfoFlags = NIIF_INFO,
                uTimeoutOrVersion = 3000
            };

            Shell_NotifyIcon(NIM_ADD, ref nid);
            Shell_NotifyIcon(NIM_MODIFY, ref nid);
        }
        catch { }
    }

    #endregion
}
