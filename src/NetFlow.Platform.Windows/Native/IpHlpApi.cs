using System.Net;
using System.Runtime.InteropServices;
using NetFlow.Core.Models;

namespace NetFlow.Platform.Windows.Native;

public static class IpHlpApi
{
    public const int AF_INET = 2;
    public const int AF_INET6 = 23;

    public const int TCP_TABLE_OWNER_PID_ALL = 5;
    public const int UDP_TABLE_OWNER_PID = 1;

    public const uint MIB_TCP_STATE_CLOSED = 1;
    public const uint MIB_TCP_STATE_LISTEN = 2;
    public const uint MIB_TCP_STATE_SYN_SENT = 3;
    public const uint MIB_TCP_STATE_SYN_RCVD = 4;
    public const uint MIB_TCP_STATE_ESTAB = 5;
    public const uint MIB_TCP_STATE_FIN_WAIT1 = 6;
    public const uint MIB_TCP_STATE_FIN_WAIT2 = 7;
    public const uint MIB_TCP_STATE_CLOSE_WAIT = 8;
    public const uint MIB_TCP_STATE_CLOSING = 9;
    public const uint MIB_TCP_STATE_LAST_ACK = 10;
    public const uint MIB_TCP_STATE_TIME_WAIT = 11;
    public const uint MIB_TCP_STATE_DELETE_TCB = 12;

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public byte localPort1;
        public byte localPort2;
        public byte localPort3;
        public byte localPort4;
        public uint remoteAddr;
        public byte remotePort1;
        public byte remotePort2;
        public byte remotePort3;
        public byte remotePort4;
        public uint owningPid;

        public ushort LocalPort => (ushort)((localPort1 << 8) + localPort2);
        public ushort RemotePort => (ushort)((remotePort1 << 8) + remotePort2);
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDPROW_OWNER_PID
    {
        public uint localAddr;
        public byte localPort1;
        public byte localPort2;
        public byte localPort3;
        public byte localPort4;
        public uint owningPid;

        public ushort LocalPort => (ushort)((localPort1 << 8) + localPort2);
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        int tableClass,
        uint reserved = 0);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        int tableClass,
        uint reserved = 0);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern uint SetTcpEntry(ref MIB_TCPROW pTcpRow);

    public static string StateToString(uint state) => state switch
    {
        MIB_TCP_STATE_CLOSED => "CLOSED",
        MIB_TCP_STATE_LISTEN => "LISTEN",
        MIB_TCP_STATE_SYN_SENT => "SYN_SENT",
        MIB_TCP_STATE_SYN_RCVD => "SYN_RECV",
        MIB_TCP_STATE_ESTAB => "ESTABLISHED",
        MIB_TCP_STATE_FIN_WAIT1 => "FIN_WAIT1",
        MIB_TCP_STATE_FIN_WAIT2 => "FIN_WAIT2",
        MIB_TCP_STATE_CLOSE_WAIT => "CLOSE_WAIT",
        MIB_TCP_STATE_CLOSING => "CLOSING",
        MIB_TCP_STATE_LAST_ACK => "LAST_ACK",
        MIB_TCP_STATE_TIME_WAIT => "TIME_WAIT",
        MIB_TCP_STATE_DELETE_TCB => "DELETE_TCB",
        _ => "UNKNOWN"
    };

    public static List<SocketInfo> GetAllSockets()
    {
        var sockets = new List<SocketInfo>();
        sockets.AddRange(GetTcpSockets());
        sockets.AddRange(GetUdpSockets());
        return sockets;
    }

    public static List<SocketInfo> GetTcpSockets()
    {
        var list = new List<SocketInfo>();
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            uint ret = GetExtendedTcpTable(buffer, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret == 0)
            {
                int numEntries = Marshal.ReadInt32(buffer);
                IntPtr rowPtr = IntPtr.Add(buffer, 4);
                int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

                for (int i = 0; i < numEntries; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                    string localIp = new IPAddress(row.localAddr).ToString();
                    string remoteIp = new IPAddress(row.remoteAddr).ToString();

                    list.Add(new SocketInfo
                    {
                        Protocol = "TCP",
                        LocalIp = localIp,
                        LocalPort = row.LocalPort,
                        RemoteIp = remoteIp,
                        RemotePort = row.RemotePort,
                        State = StateToString(row.state),
                        Pid = (int)row.owningPid
                    });

                    rowPtr = IntPtr.Add(rowPtr, rowSize);
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return list;
    }

    public static List<SocketInfo> GetUdpSockets()
    {
        var list = new List<SocketInfo>();
        int size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, true, AF_INET, UDP_TABLE_OWNER_PID, 0);

        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            uint ret = GetExtendedUdpTable(buffer, ref size, true, AF_INET, UDP_TABLE_OWNER_PID, 0);
            if (ret == 0)
            {
                int numEntries = Marshal.ReadInt32(buffer);
                IntPtr rowPtr = IntPtr.Add(buffer, 4);
                int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();

                for (int i = 0; i < numEntries; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                    string localIp = new IPAddress(row.localAddr).ToString();

                    list.Add(new SocketInfo
                    {
                        Protocol = "UDP",
                        LocalIp = localIp,
                        LocalPort = row.LocalPort,
                        RemoteIp = "0.0.0.0",
                        RemotePort = 0,
                        State = "STATELESS",
                        Pid = (int)row.owningPid
                    });

                    rowPtr = IntPtr.Add(rowPtr, rowSize);
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return list;
    }

    public static (int SeveredCount, uint LastWin32Error) SeverSockets(
        string? remoteIp = null,
        int? remotePort = null,
        string? localIp = null,
        int? localPort = null,
        int? pid = null)
    {
        if ((pid.HasValue && pid.Value <= 0) ||
            (remotePort.HasValue && (remotePort.Value <= 0 || remotePort.Value > 65535)) ||
            (localPort.HasValue && (localPort.Value <= 0 || localPort.Value > 65535)))
        {
            return (0, 87);
        }

        var sockets = GetTcpSockets();
        int count = 0;
        uint lastError = 0;

        foreach (var s in sockets)
        {
            if (pid.HasValue && s.Pid != pid.Value)
                continue;

            if (!string.IsNullOrWhiteSpace(remoteIp) && !string.Equals(s.RemoteIp, remoteIp, StringComparison.OrdinalIgnoreCase))
                continue;

            if (remotePort.HasValue && s.RemotePort != remotePort.Value)
                continue;

            if (!string.IsNullOrWhiteSpace(localIp) && !string.Equals(s.LocalIp, localIp, StringComparison.OrdinalIgnoreCase))
                continue;

            if (localPort.HasValue && s.LocalPort != localPort.Value)
                continue;

            uint ret = SeverSingleSocket(s);
            if (ret == 0)
            {
                count++;
            }
            else
            {
                lastError = ret;
            }
        }

        return (count, lastError);
    }

    public static int SeverSocketsByPid(int pid)
    {
        var (count, _) = SeverSockets(pid: pid);
        return count;
    }

    public static bool SeverTcpConnection(string remoteIp, int remotePort)
    {
        var (count, _) = SeverSockets(remoteIp: remoteIp, remotePort: remotePort);
        return count > 0;
    }

    public static bool SeverTcpConnection(string remoteIp, int remotePort, string? localIp, int? localPort)
    {
        var (count, _) = SeverSockets(remoteIp: remoteIp, remotePort: remotePort, localIp: localIp, localPort: localPort);
        return count > 0;
    }

    private static uint SeverSingleSocket(SocketInfo s)
    {
        if (!IPAddress.TryParse(s.LocalIp, out var lIp) || !IPAddress.TryParse(s.RemoteIp, out var rIp))
        {
            return 87; // ERROR_INVALID_PARAMETER
        }

        if (lIp.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
            rIp.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return 87;
        }

        byte[] localBytes = lIp.GetAddressBytes();
        byte[] remoteBytes = rIp.GetAddressBytes();

        uint lAddr = BitConverter.ToUInt32(localBytes, 0);
        uint rAddr = BitConverter.ToUInt32(remoteBytes, 0);

        ushort lPort = (ushort)s.LocalPort;
        ushort rPort = (ushort)s.RemotePort;

        // Network byte order (big-endian) port representation for MIB_TCPROW
        uint dwLocalPort = (uint)(((lPort & 0xFF) << 8) | ((lPort >> 8) & 0xFF));
        uint dwRemotePort = (uint)(((rPort & 0xFF) << 8) | ((rPort >> 8) & 0xFF));

        var row = new MIB_TCPROW
        {
            dwState = MIB_TCP_STATE_DELETE_TCB,
            dwLocalAddr = lAddr,
            dwLocalPort = dwLocalPort,
            dwRemoteAddr = rAddr,
            dwRemotePort = dwRemotePort
        };

        return SetTcpEntry(ref row);
    }
}
