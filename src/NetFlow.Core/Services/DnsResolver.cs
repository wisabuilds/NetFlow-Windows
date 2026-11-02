using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace NetFlow.Core.Services;

public class DnsResolver : IDisposable
{
    private static readonly Lazy<DnsResolver> _instance = new(() => new DnsResolver());
    public static DnsResolver Instance => _instance.Value;

    private readonly ConcurrentDictionary<string, (string Hostname, DateTime Expiry)> _cache = new();
    private readonly BlockingCollection<string> _queue = new(new ConcurrentQueue<string>(), 1000);
    private readonly ConcurrentDictionary<string, byte> _inFlight = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly TimeSpan _ttl = TimeSpan.FromHours(1);

    public DnsResolver()
    {
        Task.Factory.StartNew(WorkerLoop, TaskCreationOptions.LongRunning);
    }

    private void WorkerLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                if (_queue.TryTake(out string? ip, 500, _cts.Token) && ip != null)
                {
                    string hostname = ip;
                    try
                    {
                        var entry = Dns.GetHostEntry(ip);
                        if (!string.IsNullOrWhiteSpace(entry.HostName))
                        {
                            hostname = entry.HostName;
                        }
                    }
                    catch
                    {
                        hostname = ip;
                    }
                    finally
                    {
                        _cache[ip] = (hostname, DateTime.UtcNow.Add(_ttl));
                        _inFlight.TryRemove(ip, out _);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                // Ignore transient lookup exceptions
            }
        }
    }

    public string Resolve(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip) || ip == "0.0.0.0" || ip == "::") return ip;

        if (_cache.TryGetValue(ip, out var item))
        {
            if (DateTime.UtcNow < item.Expiry)
            {
                return item.Hostname;
            }
        }

        if (_inFlight.TryAdd(ip, 0))
        {
            _queue.TryAdd(ip);
        }

        return ip;
    }

    public static string ClassifyScope(string ipStr)
    {
        if (!IPAddress.TryParse(ipStr, out var ip)) return "WAN";

        if (IPAddress.IsLoopback(ip) || ipStr == "0.0.0.0" || ipStr == "::1")
        {
            return "LOOPBACK";
        }

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] bytes = ip.GetAddressBytes();
            // 10.0.0.0/8
            if (bytes[0] == 10) return "LAN";
            // 172.16.0.0/12
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return "LAN";
            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168) return "LAN";
            // 169.254.0.0/16 (Link Local)
            if (bytes[0] == 169 && bytes[1] == 254) return "LAN";
        }
        else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6UniqueLocal)
            {
                return "LAN";
            }
        }

        return "WAN";
    }

    public static bool IsLanOrLocal(string ipStr)
    {
        var scope = ClassifyScope(ipStr);
        return scope is "LOOPBACK" or "LAN";
    }

    public void Dispose()
    {
        _cts.Cancel();
        _queue.CompleteAdding();
    }
}
