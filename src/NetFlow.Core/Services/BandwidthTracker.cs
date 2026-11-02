using System.Net.NetworkInformation;
using NetFlow.Core.Models;
using NetFlow.Core.Storage;

namespace NetFlow.Core.Services;

public class BandwidthTracker
{
    private readonly NetflowStorage _storage;
    public IFirewallEngine Firewall { get; }
    private readonly ISocketProvider _socketProvider;
    private readonly ISecurityScanner? _securityScanner;
    public bool IsIncognito { get; set; }

    private readonly object _lock = new();
    private readonly Dictionary<string, (long Rx, long Tx, long RxPackets, long TxPackets)> _prevIfaceStats = new();
    private readonly Dictionary<int, (ulong ReadBytes, ulong WriteBytes, double Timestamp)> _lastProcessIo = new();
    private double _prevTimestamp;
    private double _peakRxSpeed;
    private double _peakTxSpeed;
    private double? _pingLatencyMs;
    private RealtimeSnapshot? _latestSnapshot;

    public BandwidthTracker(
        NetflowStorage storage,
        IFirewallEngine firewall,
        ISocketProvider socketProvider,
        ISecurityScanner? securityScanner = null)
    {
        _storage = storage;
        Firewall = firewall;
        _socketProvider = socketProvider;
        _securityScanner = securityScanner;
    }

    public bool IsDualModeElevated => _socketProvider.IsEtwElevated;

    public void SetPingLatency(double ms)
    {
        lock (_lock)
        {
            _pingLatencyMs = ms;
        }
    }

    public bool ToggleIncognito(bool? enabled = null)
    {
        lock (_lock)
        {
            IsIncognito = enabled ?? !IsIncognito;
            return IsIncognito;
        }
    }

    public virtual RealtimeSnapshot? GetLatestSnapshot()
    {
        lock (_lock)
        {
            return _latestSnapshot;
        }
    }

    public List<SocketInfo> GetActiveSocketsEnriched()
    {
        return _socketProvider.GetEnrichedSockets();
    }

    public RealtimeSnapshot PollOnce()
    {
        double now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        double dt = _prevTimestamp > 0 ? Math.Max(0.1, now - _prevTimestamp) : 1.0;

        var currentIfaces = new Dictionary<string, (long Rx, long Tx, long RxPackets, long TxPackets)>();
        var ifaceSnapshots = new Dictionary<string, InterfaceSnapshot>();

        long totalRxBytesAll = 0;
        long totalTxBytesAll = 0;
        double totalRxSpeed = 0.0;
        double totalTxSpeed = 0.0;

        try
        {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var iface in interfaces)
            {
                if (iface.OperationalStatus != OperationalStatus.Up) continue;
                if (iface.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;

                var stats = iface.GetIPStatistics();
                long rx = stats.BytesReceived;
                long tx = stats.BytesSent;
                long rxPackets = stats.UnicastPacketsReceived;
                long txPackets = stats.UnicastPacketsSent;

                currentIfaces[iface.Name] = (rx, tx, rxPackets, txPackets);
                totalRxBytesAll += rx;
                totalTxBytesAll += tx;

                double ifaceRxSpeed = 0.0;
                double ifaceTxSpeed = 0.0;

                if (_prevIfaceStats.TryGetValue(iface.Name, out var prev))
                {
                    long rxDelta = Math.Max(0, rx - prev.Rx);
                    long txDelta = Math.Max(0, tx - prev.Tx);
                    ifaceRxSpeed = rxDelta / dt;
                    ifaceTxSpeed = txDelta / dt;
                }

                totalRxSpeed += ifaceRxSpeed;
                totalTxSpeed += ifaceTxSpeed;

                ifaceSnapshots[iface.Name] = new InterfaceSnapshot(
                    iface.Name,
                    Math.Round(ifaceRxSpeed, 2),
                    Math.Round(ifaceTxSpeed, 2),
                    rx,
                    tx,
                    rxPackets,
                    txPackets
                );

                if (!IsIncognito && _prevTimestamp > 0)
                {
                    _storage.RecordInterfaceSnapshot((long)now, iface.Name, rx, tx, ifaceRxSpeed, ifaceTxSpeed);
                }
            }
        }
        catch { }

        // Sockets & Process Attribution
        var activeSockets = _socketProvider.GetEnrichedSockets();
        var procMap = new Dictionary<string, ProcessBandwidth>(StringComparer.OrdinalIgnoreCase);
        var pidSocketsMap = new Dictionary<int, List<SocketInfo>>();
        var procPidsMap = new Dictionary<string, HashSet<int>>(StringComparer.OrdinalIgnoreCase);

        foreach (var s in activeSockets)
        {
            if (s.Pid.HasValue)
            {
                if (!pidSocketsMap.TryGetValue(s.Pid.Value, out var sList))
                {
                    sList = new List<SocketInfo>();
                    pidSocketsMap[s.Pid.Value] = sList;
                }
                sList.Add(s);
            }

            if (string.IsNullOrEmpty(s.ProcessName)) continue;

            if (s.Pid.HasValue && s.Pid.Value > 0)
            {
                if (!procPidsMap.TryGetValue(s.ProcessName, out var pids))
                {
                    pids = new HashSet<int>();
                    procPidsMap[s.ProcessName] = pids;
                }
                pids.Add(s.Pid.Value);
            }

            if (!procMap.TryGetValue(s.ProcessName, out var p))
            {
                p = new ProcessBandwidth
                {
                    Pid = s.Pid ?? 0,
                    Name = s.ProcessName,
                    Cmdline = s.Cmdline ?? "",
                    ExePath = s.Cmdline,
                    ActiveConnections = 0,
                    RemoteEndpoints = new List<string>()
                };
                procMap[s.ProcessName] = p;
            }

            p.ActiveConnections++;
            if (!string.IsNullOrEmpty(s.RemoteIp) && s.RemotePort > 0)
            {
                string ep = $"{s.RemoteIp}:{s.RemotePort}";
                if (p.RemoteEndpoints.Count < 5 && !p.RemoteEndpoints.Contains(ep))
                {
                    p.RemoteEndpoints.Add(ep);
                    var geo = GeoIpService.Instance.Resolve(s.RemoteIp);
                    if (geo != null && !p.RemoteGeoIp.Any(g => g.Ip == s.RemoteIp))
                    {
                        p.RemoteGeoIp.Add(geo);
                    }
                }
            }
        }

        int totalConns = procMap.Values.Sum(p => p.ActiveConnections);
        var topProcesses = procMap.Values.OrderByDescending(p => p.ActiveConnections).Take(100).ToList();
        int highRiskCounter = 0;
        var allTrackedPids = new HashSet<int>();

        // Discover running PIDs for process names once per poll in batch (e.g. Chrome / Edge child processes)
        Dictionary<string, List<int>>? runningProcPids = null;
        try
        {
            var allProcs = System.Diagnostics.Process.GetProcesses();
            runningProcPids = new Dictionary<string, List<int>>(StringComparer.OrdinalIgnoreCase);
            foreach (var pr in allProcs)
            {
                try
                {
                    if (pr.Id > 4)
                    {
                        if (!runningProcPids.TryGetValue(pr.ProcessName, out var pList))
                        {
                            pList = new List<int>();
                            runningProcPids[pr.ProcessName] = pList;
                        }
                        pList.Add(pr.Id);
                    }
                }
                finally
                {
                    pr.Dispose();
                }
            }
        }
        catch { }

        foreach (var p in topProcesses)
        {
            // 1. Process Network Measurement (Graceful Dual-Mode: Pure ETW when elevated, socket delta / I/O when non-elevated)
            bool measuredWithEtw = false;
            bool measuredWithIo = false;
            ulong totalRead = 0;
            ulong totalWrite = 0;
            long totalRxDelta = 0;
            long totalTxDelta = 0;
            double totalRxSpeedForProc = 0;
            double totalTxSpeedForProc = 0;

            var pids = new HashSet<int>();
            if (procPidsMap.TryGetValue(p.Name, out var mappedPids))
            {
                foreach (int pid in mappedPids) pids.Add(pid);
            }
            if (p.Pid > 4) pids.Add(p.Pid);

            if (runningProcPids != null)
            {
                string cleanName = Path.GetFileNameWithoutExtension(p.Name);
                if (runningProcPids.TryGetValue(cleanName, out var discoveredPids))
                {
                    foreach (int pid in discoveredPids) pids.Add(pid);
                }
                if (runningProcPids.TryGetValue(p.Name, out var exactPids))
                {
                    foreach (int pid in exactPids) pids.Add(pid);
                }
            }

            // A. Pure Kernel Network ETW Tracing (Microsoft-Windows-Kernel-Network) when Elevated
            if (_socketProvider.IsEtwElevated)
            {
                foreach (int pid in pids)
                {
                    if (pid <= 4) continue;
                    allTrackedPids.Add(pid);

                    if (_socketProvider.TryGetProcessNetworkBytes(pid, out ulong netRx, out ulong netTx))
                    {
                        measuredWithEtw = true;
                        totalRead += netRx;
                        totalWrite += netTx;

                        if (_lastProcessIo.TryGetValue(pid, out var prevEtw))
                        {
                            double elapsed = Math.Max(0.05, now - prevEtw.Timestamp);
                            if (netRx >= prevEtw.ReadBytes && netTx >= prevEtw.WriteBytes)
                            {
                                long rxDelta = (long)(netRx - prevEtw.ReadBytes);
                                long txDelta = (long)(netTx - prevEtw.WriteBytes);
                                totalRxDelta += rxDelta;
                                totalTxDelta += txDelta;
                                totalRxSpeedForProc += Math.Round(rxDelta / elapsed, 2);
                                totalTxSpeedForProc += Math.Round(txDelta / elapsed, 2);
                            }
                        }
                        _lastProcessIo[pid] = (netRx, netTx, now);
                    }
                }
            }

            if (measuredWithEtw)
            {
                p.TotalReadBytes = totalRead;
                p.TotalWriteBytes = totalWrite;
                p.RxSpeed = totalRxSpeedForProc;
                p.TxSpeed = totalTxSpeedForProc;
                p.RxBytesDelta = totalRxDelta;
                p.TxBytesDelta = totalTxDelta;
                p.TransferRateKbps = Math.Round((totalRxSpeedForProc + totalTxSpeedForProc) / 1024.0, 1);
            }
            else
            {
                // B. Non-elevated fallback: check provider I/O (for mock unit tests or non-elevated I/O)
                foreach (int pid in pids)
                {
                    if (pid <= 4) continue;
                    allTrackedPids.Add(pid);

                    if (_socketProvider.TryGetProcessIo(pid, out ulong readBytes, out ulong writeBytes))
                    {
                        measuredWithIo = true;
                        totalRead += readBytes;
                        totalWrite += writeBytes;

                        if (_lastProcessIo.TryGetValue(pid, out var prevIo))
                        {
                            double elapsed = Math.Max(0.05, now - prevIo.Timestamp);
                            if (readBytes >= prevIo.ReadBytes && writeBytes >= prevIo.WriteBytes)
                            {
                                long rxDelta = (long)(readBytes - prevIo.ReadBytes);
                                long txDelta = (long)(writeBytes - prevIo.WriteBytes);
                                totalRxDelta += rxDelta;
                                totalTxDelta += txDelta;
                                totalRxSpeedForProc += Math.Round(rxDelta / elapsed, 2);
                                totalTxSpeedForProc += Math.Round(txDelta / elapsed, 2);
                            }
                        }
                        _lastProcessIo[pid] = (readBytes, writeBytes, now);
                    }
                }

                if (measuredWithIo)
                {
                    p.TotalReadBytes = totalRead;
                    p.TotalWriteBytes = totalWrite;
                    p.RxSpeed = totalRxSpeedForProc;
                    p.TxSpeed = totalTxSpeedForProc;
                    p.RxBytesDelta = totalRxDelta;
                    p.TxBytesDelta = totalTxDelta;
                    p.TransferRateKbps = Math.Round((totalRxSpeedForProc + totalTxSpeedForProc) / 1024.0, 1);
                }

                // Fallback to per-process socket delta rate calculations when non-elevated and no I/O available
                if (!measuredWithIo && totalConns > 0 && (totalRxSpeed > 0 || totalTxSpeed > 0))
                {
                    double ratio = (double)p.ActiveConnections / totalConns;
                    p.RxSpeed = Math.Round(totalRxSpeed * ratio, 2);
                    p.TxSpeed = Math.Round(totalTxSpeed * ratio, 2);
                    p.RxBytesDelta = (long)(p.RxSpeed * dt);
                    p.TxBytesDelta = (long)(p.TxSpeed * dt);
                    p.TransferRateKbps = Math.Round((p.RxSpeed + p.TxSpeed) / 1024.0, 1);
                }
            }

            // 2. Threat & Authenticode Assessment
            if (_securityScanner != null)
            {
                pidSocketsMap.TryGetValue(p.Pid, out var pSockets);
                p.Threat = _securityScanner.AssessProcess(p.Pid, p.Name, p.ExePath ?? p.Cmdline, pSockets);
                if (p.Threat.Level >= RiskLevel.Medium)
                {
                    highRiskCounter++;
                }
            }

            // Record process snapshot in SQLite storage
            if (!IsIncognito && (p.RxBytesDelta > 0 || p.TxBytesDelta > 0))
            {
                _storage.RecordProcessSnapshot((long)now, p.Name, p.Pid, p.RxBytesDelta, p.TxBytesDelta, p.ActiveConnections);
            }
        }

        // Cleanup dead PIDs from _lastProcessIo
        var deadPids = _lastProcessIo.Keys.Where(k => !allTrackedPids.Contains(k)).ToList();
        foreach (var dead in deadPids)
        {
            _lastProcessIo.Remove(dead);
        }

        // Firewall enforcement
        Firewall.Enforce(activeSockets, topProcesses);

        // Peaks
        if (totalRxSpeed > _peakRxSpeed) _peakRxSpeed = totalRxSpeed;
        if (totalTxSpeed > _peakTxSpeed) _peakTxSpeed = totalTxSpeed;

        var snapshot = new RealtimeSnapshot
        {
            Timestamp = now,
            TotalRxSpeed = Math.Round(totalRxSpeed, 2),
            TotalTxSpeed = Math.Round(totalTxSpeed, 2),
            TotalRxBytes = totalRxBytesAll,
            TotalTxBytes = totalTxBytesAll,
            PeakRxSpeed = Math.Round(_peakRxSpeed, 2),
            PeakTxSpeed = Math.Round(_peakTxSpeed, 2),
            Interfaces = ifaceSnapshots,
            TopProcesses = topProcesses,
            ActiveSocketCount = activeSockets.Count,
            PingLatencyMs = _pingLatencyMs,
            HighRiskCount = highRiskCounter
        };

        lock (_lock)
        {
            _prevIfaceStats.Clear();
            foreach (var kvp in currentIfaces) _prevIfaceStats[kvp.Key] = kvp.Value;
            _prevTimestamp = now;
            _latestSnapshot = snapshot;
        }

        return snapshot;
    }
}
