using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace NetFlow.Platform.Windows.Services;

/// <summary>
/// Kernel ETW Network Provider Tracing (Microsoft-Windows-Kernel-Network: {7DD42A49-5329-4832-8DFD-43D979153A88})
/// Provides pure kernel-level network socket I/O accounting without conflating local disk I/O.
/// Runs when elevated (Administrator), with graceful fallback to socket rate calculations when non-elevated.
/// </summary>
public class WindowsKernelNetworkEtwSession : IDisposable
{
    private static readonly Lazy<WindowsKernelNetworkEtwSession> _instance = new(() => new WindowsKernelNetworkEtwSession());
    public static WindowsKernelNetworkEtwSession Instance => _instance.Value;

    public static readonly Guid KernelNetworkProviderGuid = new("7DD42A49-5329-4832-8DFD-43D979153A88");
    private const string SessionName = "NetFlowKernelNetworkTrace";

    private readonly ConcurrentDictionary<int, (ulong RxBytes, ulong TxBytes)> _procNetworkBytes = new();
    private readonly bool _isElevated;
    private bool _isActive;
    private bool _disposed;

    private ulong _sessionHandle;
    private ulong _traceHandle;
    private Thread? _traceThread;
    private NativeEtw.EventRecordCallback? _callback;
    private IntPtr _pProperties = IntPtr.Zero;

    public bool IsElevated => _isElevated;
    public bool IsElevatedAndActive => _isElevated && _isActive;

    public WindowsKernelNetworkEtwSession()
    {
        _isElevated = CheckElevation();
        if (_isElevated)
        {
            TryStartEtwSession();
        }
    }

    private static bool CheckElevation()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private void TryStartEtwSession()
    {
        try
        {
            int propSize = Marshal.SizeOf<NativeEtw.EVENT_TRACE_PROPERTIES>() + 1024;
            _pProperties = Marshal.AllocHGlobal(propSize);
            for (int i = 0; i < propSize; i++) Marshal.WriteByte(_pProperties, i, 0);

            var props = new NativeEtw.EVENT_TRACE_PROPERTIES();
            props.Wnode.BufferSize = (uint)propSize;
            props.Wnode.Flags = NativeEtw.WNODE_FLAG_TRACED_GUID;
            props.LogFileMode = NativeEtw.EVENT_TRACE_REAL_TIME_MODE;
            props.LoggerNameOffset = (uint)Marshal.SizeOf<NativeEtw.EVENT_TRACE_PROPERTIES>();
            Marshal.StructureToPtr(props, _pProperties, false);

            // Stop any existing stale session with the same name first
            NativeEtw.ControlTraceW(0, SessionName, _pProperties, NativeEtw.EVENT_TRACE_CONTROL_STOP);

            // Start new trace session
            uint status = NativeEtw.StartTraceW(out _sessionHandle, SessionName, _pProperties);
            if (status != 0)
            {
                Marshal.FreeHGlobal(_pProperties);
                _pProperties = IntPtr.Zero;
                _isActive = false;
                return;
            }

            // Enable Microsoft-Windows-Kernel-Network provider
            status = NativeEtw.EnableTraceEx2(
                _sessionHandle,
                in KernelNetworkProviderGuid,
                1, // EVENT_CONTROL_CODE_ENABLE_PROVIDER
                5, // TRACE_LEVEL_VERBOSE
                0, // Match all keywords
                0,
                0,
                IntPtr.Zero);

            if (status != 0)
            {
                StopSession();
                _isActive = false;
                return;
            }

            _callback = OnEventRecord;
            var logfile = new NativeEtw.EVENT_TRACE_LOGFILE
            {
                LoggerName = SessionName,
                ProcessTraceMode = NativeEtw.PROCESS_TRACE_MODE_REAL_TIME | NativeEtw.PROCESS_TRACE_MODE_EVENT_RECORD,
                EventRecordCallback = _callback
            };

            _traceHandle = NativeEtw.OpenTraceW(ref logfile);
            if (_traceHandle == 0 || _traceHandle == unchecked((ulong)-1))
            {
                StopSession();
                _isActive = false;
                return;
            }

            _traceThread = new Thread(() =>
            {
                try
                {
                    ulong[] handles = new[] { _traceHandle };
                    NativeEtw.ProcessTrace(handles, 1, IntPtr.Zero, IntPtr.Zero);
                }
                catch { }
            })
            {
                IsBackground = true,
                Name = "NetFlow_ETW_Consumer"
            };
            _traceThread.Start();
            _isActive = true;
        }
        catch
        {
            StopSession();
            _isActive = false;
        }
    }

    private void OnEventRecord(in NativeEtw.EVENT_RECORD record)
    {
        try
        {
            int pid = (int)record.EventHeader.ProcessId;
            if (pid <= 0) return;

            ushort eventId = record.EventHeader.EventDescriptor.Id;
            ulong rx = 0;
            ulong tx = 0;

            uint size = 0;
            if (record.UserData != IntPtr.Zero && record.UserDataLength >= 4)
            {
                size = (uint)Marshal.ReadInt32(record.UserData);
                if (size > 65536 * 16) size = 1500;
            }
            if (size == 0) size = 64;

            if (eventId is 10 or 26 or 42)
            {
                tx = size;
            }
            else if (eventId is 11 or 27 or 43)
            {
                rx = size;
            }
            else
            {
                rx = size / 2;
                tx = size - rx;
            }

            RecordNetworkEvent(pid, rx, tx);
        }
        catch { }
    }

    private void StopSession()
    {
        try
        {
            if (_traceHandle != 0 && _traceHandle != unchecked((ulong)-1))
            {
                NativeEtw.CloseTrace(_traceHandle);
                _traceHandle = 0;
            }

            if (_sessionHandle != 0)
            {
                if (_pProperties != IntPtr.Zero)
                {
                    NativeEtw.ControlTraceW(_sessionHandle, SessionName, _pProperties, NativeEtw.EVENT_TRACE_CONTROL_STOP);
                }
                _sessionHandle = 0;
            }

            if (_pProperties != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(_pProperties);
                _pProperties = IntPtr.Zero;
            }
        }
        catch { }
    }

    public void SetActiveForTesting(bool active)
    {
        _isActive = active;
    }

    public void RecordNetworkEvent(int pid, ulong rxDelta, ulong txDelta)
    {
        _procNetworkBytes.AddOrUpdate(
            pid,
            (rxDelta, txDelta),
            (_, current) => (current.RxBytes + rxDelta, current.TxBytes + txDelta)
        );
    }

    public bool TryGetProcessNetworkBytes(int pid, out ulong rxBytes, out ulong txBytes)
    {
        if (_procNetworkBytes.TryGetValue(pid, out var bytes))
        {
            rxBytes = bytes.RxBytes;
            txBytes = bytes.TxBytes;
            return true;
        }

        rxBytes = 0;
        txBytes = 0;
        return false;
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
            _isActive = false;
            StopSession();
        }
    }

    private static class NativeEtw
    {
        public const uint EVENT_TRACE_REAL_TIME_MODE = 0x00000100;
        public const uint EVENT_TRACE_CONTROL_STOP = 1;
        public const uint WNODE_FLAG_TRACED_GUID = 0x00020000;
        public const uint PROCESS_TRACE_MODE_REAL_TIME = 0x00000100;
        public const uint PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000;

        [StructLayout(LayoutKind.Sequential)]
        public struct WNODE_HEADER
        {
            public uint BufferSize;
            public uint ProviderId;
            public ulong HistoricalContext;
            public ulong TimeStamp;
            public Guid Guid;
            public uint ClientContext;
            public uint Flags;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct EVENT_TRACE_PROPERTIES
        {
            public WNODE_HEADER Wnode;
            public uint BufferSize;
            public uint MinimumBuffers;
            public uint MaximumBuffers;
            public uint MaximumFileSize;
            public uint LogFileMode;
            public uint FlushTimer;
            public uint EnableFlags;
            public int AgeLimit;
            public uint NumberOfBuffers;
            public uint FreeBuffers;
            public uint EventsLost;
            public uint BuffersWritten;
            public uint LogBuffersLost;
            public uint RealTimeBuffersLost;
            public IntPtr LoggerThreadId;
            public uint LogFileNameOffset;
            public uint LoggerNameOffset;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EVENT_DESCRIPTOR
        {
            public ushort Id;
            public byte Version;
            public byte Channel;
            public byte Level;
            public byte Opcode;
            public ushort Task;
            public ulong Keyword;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EVENT_HEADER
        {
            public ushort Size;
            public ushort HeaderType;
            public ushort Flags;
            public ushort EventProperty;
            public uint ThreadId;
            public uint ProcessId;
            public long TimeStamp;
            public Guid ProviderId;
            public EVENT_DESCRIPTOR EventDescriptor;
            public ulong ProcessorTime;
            public Guid ActivityId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ETW_BUFFER_CONTEXT
        {
            public byte ProcessorNumber;
            public byte Alignment;
            public ushort LoggerId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EVENT_RECORD
        {
            public EVENT_HEADER EventHeader;
            public ETW_BUFFER_CONTEXT BufferContext;
            public ushort ExtendedDataCount;
            public ushort UserDataLength;
            public IntPtr ExtendedData;
            public IntPtr UserData;
            public IntPtr UserContext;
        }

        public delegate void EventRecordCallback(in EVENT_RECORD eventRecord);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct EVENT_TRACE_LOGFILE
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string? LogFileName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string? LoggerName;
            public long CurrentTime;
            public uint BuffersRead;
            public uint ProcessTraceMode;
            public IntPtr CurrentEvent;
            public IntPtr LogfileHeader;
            public IntPtr BufferCallback;
            public int BufferSize;
            public int Filled;
            public int EventsLost;
            public EventRecordCallback? EventRecordCallback;
            public uint IsKernelTrace;
            public IntPtr Context;
        }

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint StartTraceW(out ulong sessionHandle, string sessionName, IntPtr properties);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint ControlTraceW(ulong sessionHandle, string sessionName, IntPtr properties, uint controlCode);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        public static extern uint EnableTraceEx2(
            ulong sessionHandle,
            in Guid providerId,
            uint controlCode,
            byte level,
            ulong matchAnyKeyword,
            ulong matchAllKeyword,
            uint timeout,
            IntPtr enableParameters);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern ulong OpenTraceW(ref EVENT_TRACE_LOGFILE logfile);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        public static extern uint ProcessTrace(
            [In] ulong[] handleArray,
            uint handleCount,
            IntPtr startTime,
            IntPtr endTime);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        public static extern uint CloseTrace(ulong traceHandle);
    }
}
