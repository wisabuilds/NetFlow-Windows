using NetFlow.Core.Diagnostics;
using NetFlow.Core.Models;
using NetFlow.Core.Services;
using NetFlow.Core.Storage;
using NetFlow.Platform.Windows.Firewall;
using NetFlow.Platform.Windows.Services;

string dbPath = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
    "NetFlow", "netflow.db");

if (args.Length > 0)
{
    string cmd = args[0].ToLowerInvariant();

    if (cmd is "--ping" or "ping")
    {
        string target = args.Length > 1 ? args[1] : "1.1.1.1";
        Console.WriteLine($"[*] Pinging {target}...");
        var res = await NetworkDiagnostics.MeasurePingAsync(target, 3);
        if (res.TryGetValue("success", out var s) && (bool)s)
        {
            Console.WriteLine($"[+] Target: {res["target"]} | Latency: {res["avg_ms"]} ms (min: {res["min_ms"]} ms, max: {res["max_ms"]} ms)");
        }
        else
        {
            Console.WriteLine($"[!] Ping failed: {res.GetValueOrDefault("error")}");
        }
        return;
    }

    if (cmd is "--scan" or "scan")
    {
        Console.WriteLine("[*] Scanning local subnet for active devices (ARP table)...");
        var devices = NetworkDiagnostics.GetLocalSubnetDevices();
        if (devices.Count == 0)
        {
            Console.WriteLine("[!] No local devices found.");
        }
        else
        {
            Console.WriteLine($"\n{"IP Address",-18} | {"MAC Address",-18} | {"Vendor",-20}");
            Console.WriteLine(new string('-', 62));
            foreach (var d in devices)
            {
                Console.WriteLine($"{d["ip"],-18} | {d["mac"],-18} | {d["vendor"],-20}");
            }
            Console.WriteLine($"\nTotal: {devices.Count} device(s) found.");
        }
        return;
    }

    if (cmd is "--speedtest" or "speedtest")
    {
        Console.WriteLine("[*] Running internet speed test (fetching test payload from Cloudflare CDN)...");
        var res = await NetworkDiagnostics.RunSpeedTestAsync(5);
        if (res.TryGetValue("success", out var s) && (bool)s)
        {
            Console.WriteLine($"[-] Download Speed: {res["speed_mbps"]} Mbps ({res["speed_mbytes_sec"]} MB/s)");
            Console.WriteLine($"[-] Transferred in {res["duration_seconds"]}s");
        }
        else
        {
            Console.WriteLine($"[!] Speed test failed: {res.GetValueOrDefault("error")}");
        }
        return;
    }

    if (cmd is "--plan-set-gb" or "plan")
    {
        if (args.Length > 1 && double.TryParse(args[1], out double gb))
        {
            using var storage = new NetflowStorage(dbPath);
            long limitBytes = (long)(gb * 1024 * 1024 * 1024);
            storage.UpdateDataPlan("monthly", limitBytes);
            Console.WriteLine($"[+] Configured monthly data plan limit to {gb} GB.");
        }
        else
        {
            Console.WriteLine("[!] Please specify data plan in GB, e.g.: netflow plan 50");
        }
        return;
    }
}

// Live interactive console dashboard
Console.Clear();
Console.CursorVisible = false;
Console.WriteLine("==========================================================================");
Console.WriteLine(" NetFlow Windows: Real-Time Network Speed & Process Attribution Monitor ");
Console.WriteLine("==========================================================================");
Console.WriteLine("Press Ctrl+C to exit.\n");

using var consoleStorage = new NetflowStorage(dbPath);
var firewall = new WindowsFirewallEngine(consoleStorage);
var socketProvider = new WindowsSocketProvider();
var tracker = new BandwidthTracker(consoleStorage, firewall, socketProvider);

var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

while (!cts.IsCancellationRequested)
{
    var snapshot = tracker.PollOnce();

    Console.SetCursorPosition(0, 4);
    Console.WriteLine($"Time: {DateTime.Now:HH:mm:ss} | Active Sockets: {snapshot.ActiveSocketCount,-5} | Ping: {snapshot.PingLatencyMs?.ToString("F1") ?? "--",-5} ms");
    Console.WriteLine($"Download Speed: {FormatSpeed(snapshot.TotalRxSpeed),-15} (Peak: {FormatSpeed(snapshot.PeakRxSpeed)})");
    Console.WriteLine($"Upload Speed:   {FormatSpeed(snapshot.TotalTxSpeed),-15} (Peak: {FormatSpeed(snapshot.PeakTxSpeed)})");
    Console.WriteLine(new string('-', 74));

    Console.WriteLine($"{"PID",-7} | {"Process Name",-25} | {"Conns",-6} | {"Down Speed",-14} | {"Up Speed",-14}");
    Console.WriteLine(new string('-', 74));

    int lines = 0;
    foreach (var p in snapshot.TopProcesses.Take(8))
    {
        string name = p.Name.Length > 24 ? p.Name[..24] : p.Name;
        Console.WriteLine($"{p.Pid,-7} | {name,-25} | {p.ActiveConnections,-6} | {FormatSpeed(p.RxSpeed),-14} | {FormatSpeed(p.TxSpeed),-14}");
        lines++;
    }

    while (lines < 8)
    {
        Console.WriteLine(new string(' ', 74));
        lines++;
    }

    try
    {
        await Task.Delay(1000, cts.Token);
    }
    catch (OperationCanceledException)
    {
        break;
    }
}

Console.CursorVisible = true;
Console.WriteLine("\nNetFlow stopped.");

static string FormatSpeed(double bytesPerSec)
{
    if (bytesPerSec < 1024) return $"{bytesPerSec:F0} B/s";
    if (bytesPerSec < 1024 * 1024) return $"{bytesPerSec / 1024:F1} KB/s";
    if (bytesPerSec < 1024 * 1024 * 1024) return $"{bytesPerSec / (1024 * 1024):F1} MB/s";
    return $"{bytesPerSec / (1024 * 1024 * 1024):F2} GB/s";
}
