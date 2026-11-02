using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NetFlow.Core.Diagnostics;
using NetFlow.Core.Models;
using NetFlow.Core.Services;
using NetFlow.Core.Storage;
using NetFlow.Platform.Windows.Defense;
using NetFlow.Platform.Windows.Firewall;
using NetFlow.Platform.Windows.QoS;
using NetFlow.Platform.Windows.Security;
using NetFlow.Platform.Windows.Services;
using NetFlow.Platform.Windows.Tor;
using NetFlow.Platform.Windows.Vpn;
using NetFlow.Platform.Windows.Wifi;

namespace NetFlow.Server;

public static class NetFlowServerHost
{
    public static WebApplication CreateApp(string[]? args = null, string? contentRoot = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = args ?? Array.Empty<string>(),
            ContentRootPath = contentRoot ?? AppContext.BaseDirectory
        });

        builder.WebHost.ConfigureKestrel(options =>
        {
            options.Listen(System.Net.IPAddress.Parse("127.0.0.1"), 9095);
        });

        builder.Services.AddCors(options =>
        {
            options.AddDefaultPolicy(policy =>
            {
                policy.SetIsOriginAllowed(origin =>
                    origin.StartsWith("http://127.0.0.1") || origin.StartsWith("http://localhost"))
                    .AllowAnyHeader()
                    .AllowAnyMethod();
            });
        });

        string dbPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NetFlow", "netflow.db");

        var storage = new NetflowStorage(dbPath);
        var firewall = new WindowsFirewallEngine(storage);
        var socketProvider = new WindowsSocketProvider();
        var securityScanner = new WindowsSecurityScanner();
        var qosManager = new WindowsQosManager();
        var vpnManager = new WindowsVpnManager();
        var torManager = new WindowsTorManager();
        var activeDefense = new ActiveDefenseManager(firewall);
        var wifiScanner = new NativeWifiScanner();

        string geoDbPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NetFlow", "geoip.db");
        var geoDb = new GeoIpDatabase(geoDbPath);
        var geoIpService = new NetFlow.Core.Telemetry.GeoIpService(geoDb);

        var tracker = new BandwidthTracker(storage, firewall, socketProvider, securityScanner);

        builder.Services.AddSingleton(storage);
        builder.Services.AddSingleton(geoDb);
        builder.Services.AddSingleton(geoIpService);
        builder.Services.AddSingleton(tracker);
        builder.Services.AddSingleton<ISecurityScanner>(securityScanner);
        builder.Services.AddSingleton<IQosManager>(qosManager);
        builder.Services.AddSingleton<IVpnManager>(vpnManager);
        builder.Services.AddSingleton<ITorManager>(torManager);
        builder.Services.AddSingleton<IActiveDefenseManager>(activeDefense);
        builder.Services.AddSingleton(activeDefense);
        builder.Services.AddSingleton<IWifiScanner>(wifiScanner);
        builder.Services.AddSingleton(wifiScanner);
        builder.Services.AddHostedService<NetflowBackgroundWorker>();

        var app = builder.Build();

        app.UseCors();
        app.UseDefaultFiles();
        app.UseStaticFiles();

        // 1. Realtime
        app.MapGet("/api/stats/realtime", (BandwidthTracker t) =>
        {
            var snapshot = t.GetLatestSnapshot();
            if (snapshot == null) return Results.Ok(new { status = "initializing" });

            return Results.Ok(new
            {
                timestamp = snapshot.Timestamp,
                total_rx_speed_bps = snapshot.TotalRxSpeed,
                total_tx_speed_bps = snapshot.TotalTxSpeed,
                total_rx_speed_human = FormatSpeed(snapshot.TotalRxSpeed),
                total_tx_speed_human = FormatSpeed(snapshot.TotalTxSpeed),
                total_rx_bytes = snapshot.TotalRxBytes,
                total_tx_bytes = snapshot.TotalTxBytes,
                peak_rx_speed = snapshot.PeakRxSpeed,
                peak_tx_speed = snapshot.PeakTxSpeed,
                ping_latency_ms = snapshot.PingLatencyMs,
                active_sockets = snapshot.ActiveSocketCount,
                high_risk_count = snapshot.HighRiskCount,
                interfaces = snapshot.Interfaces,
                top_processes = snapshot.TopProcesses
            });
        });

        // 2. History
        app.MapGet("/api/stats/history", ([FromQuery] int? seconds, [FromQuery] string? @interface, NetflowStorage s) =>
        {
            int sec = seconds ?? 60;
            var points = s.GetRecentSpeeds(sec, @interface);
            return Results.Ok(new { points, count = points.Count });
        });

        // 3. Daily Usage
        app.MapGet("/api/stats/daily", ([FromQuery] int? days, NetflowStorage s) =>
        {
            int d = days ?? 30;
            var history = s.GetDailyUsage(d);
            return Results.Ok(new { daily_usage = history });
        });

        // 4. Usage Summary
        app.MapGet("/api/stats/summary", (NetflowStorage s) =>
        {
            return Results.Ok(s.GetUsageSummary());
        });

        // 5. Top Apps
        app.MapGet("/api/stats/top-apps", ([FromQuery] int? period, [FromQuery] int? limit, NetflowStorage s) =>
        {
            int p = period ?? 86400;
            int lim = limit ?? 15;
            var topApps = s.GetTopProcesses(p, lim);
            return Results.Ok(new { top_apps = topApps });
        });

        // 6. Netstat
        app.MapGet("/api/netstat", (BandwidthTracker t, NetFlow.Core.Telemetry.GeoIpService geoService) =>
        {
            var sockets = t.GetActiveSocketsEnriched();
            geoService.EnrichList(sockets);
            return Results.Ok(new { sockets, total = sockets.Count });
        });

        // GeoIP & ASN Lookup
        app.MapGet("/api/geoip/lookup", async ([FromQuery] string? ip, NetFlow.Core.Telemetry.GeoIpService geoService) =>
        {
            if (string.IsNullOrWhiteSpace(ip))
            {
                return Results.BadRequest(new { error = "Parameter 'ip' is required" });
            }
            var info = await geoService.ResolveAsync(ip);
            return Results.Ok(new
            {
                ip = ip,
                country_code = info.CountryCode,
                country_name = info.CountryName,
                flag = info.FlagEmoji,
                flag_emoji = info.FlagEmoji,
                asn = info.Asn,
                as_org = info.AsOrg,
                is_local = info.IsLocal
            });
        });

        // 7. Plan
        app.MapGet("/api/plan", (NetflowStorage s) =>
        {
            return Results.Ok(s.GetDataPlanStatus());
        });

        app.MapPost("/api/plan", async (HttpRequest request, NetflowStorage s) =>
        {
            using var reader = new StreamReader(request.Body);
            string json = await reader.ReadToEndAsync();
            var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(json) ? "{}" : json);
            var root = doc.RootElement;

            string period = root.TryGetProperty("period", out var pEl) ? pEl.GetString() ?? "monthly" : "monthly";
            long? limitBytes = null;
            if (root.TryGetProperty("limit_bytes", out var lEl) && lEl.ValueKind == JsonValueKind.Number)
            {
                limitBytes = lEl.GetInt64();
            }
            int resetDay = root.TryGetProperty("reset_day", out var rEl) ? rEl.GetInt32() : 1;
            int warningPct = root.TryGetProperty("warning_pct", out var wEl) ? wEl.GetInt32() : 80;

            s.UpdateDataPlan(period, limitBytes, resetDay, warningPct);
            return Results.Ok(new { status = "updated", plan = s.GetDataPlanStatus() });
        });

        app.MapGet("/api/plan/forecast", (NetflowStorage s) =>
        {
            var forecast = s.GetBudgetForecast();
            return Results.Ok(new
            {
                configured = forecast.Configured,
                limit_bytes = forecast.LimitBytes,
                used_bytes = forecast.UsedBytes,
                remaining_bytes = forecast.RemainingBytes,
                days_elapsed = forecast.DaysElapsed,
                days_remaining = forecast.DaysRemaining,
                avg_daily_bytes = forecast.AvgDailyBytes,
                recommended_daily_budget_bytes = forecast.RecommendedDailyBudgetBytes,
                projected_total_bytes = forecast.ProjectedTotalBytes,
                projected_percentage = forecast.ProjectedPercentage,
                burn_status = forecast.BurnStatus,
                estimated_exhaustion_date = forecast.EstimatedExhaustionDate,
                period = forecast.Period,
                plan = s.GetDataPlanStatus(),
                daily_budget_bytes = forecast.RecommendedDailyBudgetBytes,
                daily_budget_human = FormatSpeed(forecast.RecommendedDailyBudgetBytes)
            });
        });

        // 8. Monitor Status & Incognito
        app.MapGet("/api/monitor/status", (BandwidthTracker t) =>
        {
            return Results.Ok(new { incognito = t.IsIncognito });
        });

        app.MapPost("/api/monitor/incognito", async (HttpRequest request, BandwidthTracker t) =>
        {
            using var reader = new StreamReader(request.Body);
            string json = await reader.ReadToEndAsync();
            bool? state = null;
            if (!string.IsNullOrWhiteSpace(json))
            {
                var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("enabled", out var eEl))
                    state = eEl.GetBoolean();
            }
            bool newState = t.ToggleIncognito(state);
            return Results.Ok(new { incognito = newState, status = newState ? "active" : "disabled" });
        });

        // 9. Firewall
        app.MapGet("/api/firewall/status", (BandwidthTracker t) =>
        {
            return Results.Ok(t.Firewall.GetStatus());
        });

        app.MapPost("/api/firewall/toggle", async (HttpRequest request, BandwidthTracker t) =>
        {
            using var reader = new StreamReader(request.Body);
            string json = await reader.ReadToEndAsync();
            bool? enabled = null;
            if (!string.IsNullOrWhiteSpace(json))
            {
                var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("enabled", out var eEl))
                    enabled = eEl.GetBoolean();
            }
            bool newState = t.Firewall.ToggleFirewall(enabled);
            return Results.Ok(new { enabled = newState, status = newState ? "active" : "disabled" });
        });

        app.MapPost("/api/firewall/policy", async (HttpRequest request, BandwidthTracker t) =>
        {
            using var reader = new StreamReader(request.Body);
            string json = await reader.ReadToEndAsync();
            var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(json) ? "{}" : json);
            if (!doc.RootElement.TryGetProperty("process_name", out var pEl))
            {
                return Results.BadRequest(new { error = "Missing process_name" });
            }
            string procName = pEl.GetString() ?? "";
            string policy = doc.RootElement.TryGetProperty("policy", out var polEl) ? polEl.GetString() ?? "block" : "block";

            string pol = t.Firewall.SetAppPolicy(procName, policy);
            return Results.Ok(new
            {
                process_name = procName,
                policy = pol,
                blocked = pol is "block" or "lan_only",
                firewall = t.Firewall.GetStatus()
            });
        });

        app.MapPost("/api/firewall/block", async (HttpRequest request, BandwidthTracker t) =>
        {
            using var reader = new StreamReader(request.Body);
            string json = await reader.ReadToEndAsync();
            var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(json) ? "{}" : json);
            if (!doc.RootElement.TryGetProperty("process_name", out var pEl))
            {
                return Results.BadRequest(new { error = "Missing process_name" });
            }
            string procName = pEl.GetString() ?? "";
            string pol = t.Firewall.SetAppPolicy(procName, "block");
            return Results.Ok(new { process_name = procName, blocked = true, policy = pol, firewall = t.Firewall.GetStatus() });
        });

        app.MapPost("/api/firewall/unblock", async (HttpRequest request, BandwidthTracker t) =>
        {
            using var reader = new StreamReader(request.Body);
            string json = await reader.ReadToEndAsync();
            var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(json) ? "{}" : json);
            if (!doc.RootElement.TryGetProperty("process_name", out var pEl))
            {
                return Results.BadRequest(new { error = "Missing process_name" });
            }
            string procName = pEl.GetString() ?? "";
            string pol = t.Firewall.SetAppPolicy(procName, "allow");
            return Results.Ok(new { process_name = procName, blocked = false, policy = pol, firewall = t.Firewall.GetStatus() });
        });

        app.MapPost("/api/firewall/clear", (BandwidthTracker t) =>
        {
            int count = t.Firewall.ClearAllBlocks();
            return Results.Ok(new { unblocked_count = count, firewall = t.Firewall.GetStatus() });
        });

        // 9b. Active Defense & Threat Remediation
        app.MapGet("/api/defense/status", (ActiveDefenseManager defense) =>
        {
            return Results.Ok(defense.GetStatus());
        });

        app.MapPost("/api/defense/kill-process", async (HttpRequest request, ActiveDefenseManager defense) =>
        {
            using var reader = new StreamReader(request.Body);
            string json = await reader.ReadToEndAsync();
            int pid = 0;
            uint exitCode = 1;

            if (!string.IsNullOrWhiteSpace(json))
            {
                try
                {
                    var doc = JsonDocument.Parse(json);
                    if (doc.RootElement.TryGetProperty("pid", out var pEl) && pEl.ValueKind == JsonValueKind.Number && pEl.TryGetInt32(out int pVal))
                    {
                        pid = pVal;
                    }
                    if (doc.RootElement.TryGetProperty("exit_code", out var eEl) && eEl.ValueKind == JsonValueKind.Number && eEl.TryGetUInt32(out uint eVal))
                    {
                        exitCode = eVal;
                    }
                }
                catch (Exception ex) when (ex is JsonException || ex is InvalidOperationException)
                {
                    return Results.BadRequest(new { success = false, error = "Malformed JSON payload.", elevation_required = false });
                }
            }

            if (pid <= 0)
            {
                return Results.BadRequest(new { success = false, error = "Missing or invalid 'pid'. PID must be a positive integer.", elevation_required = false });
            }

            var result = defense.KillProcess(pid, exitCode);
            return Results.Ok(new
            {
                success = result.Success,
                pid = result.Pid,
                process_name = result.ProcessName,
                error = result.Error,
                elevation_required = result.ElevationRequired
            });
        });

        app.MapPost("/api/defense/sever-connection", async (HttpRequest request, ActiveDefenseManager defense) =>
        {
            using var reader = new StreamReader(request.Body);
            string json = await reader.ReadToEndAsync();
            string? remoteIp = null;
            int? remotePort = null;
            string? localIp = null;
            int? localPort = null;
            int? pid = null;

            if (!string.IsNullOrWhiteSpace(json))
            {
                try
                {
                    var doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;
                    if (root.TryGetProperty("remote_ip", out var ripEl) && ripEl.ValueKind == JsonValueKind.String)
                        remoteIp = ripEl.GetString();
                    if (root.TryGetProperty("remote_port", out var rportEl) && rportEl.ValueKind == JsonValueKind.Number && rportEl.TryGetInt32(out int rp))
                        remotePort = rp;
                    if (root.TryGetProperty("local_ip", out var lipEl) && lipEl.ValueKind == JsonValueKind.String)
                        localIp = lipEl.GetString();
                    if (root.TryGetProperty("local_port", out var lportEl) && lportEl.ValueKind == JsonValueKind.Number && lportEl.TryGetInt32(out int lp))
                        localPort = lp;
                    if (root.TryGetProperty("pid", out var pidEl) && pidEl.ValueKind == JsonValueKind.Number && pidEl.TryGetInt32(out int pVal))
                        pid = pVal;
                }
                catch (Exception ex) when (ex is JsonException || ex is InvalidOperationException)
                {
                    return Results.BadRequest(new { success = false, error = "Malformed JSON payload.", elevation_required = false });
                }
            }

            var result = defense.SeverConnection(remoteIp, remotePort, localIp, localPort, pid);
            return Results.Ok(new
            {
                success = result.Success,
                severed_count = result.SeveredCount,
                remote_ip = result.RemoteIp,
                remote_port = result.RemotePort,
                error = result.Error,
                elevation_required = result.ElevationRequired
            });
        });

        app.MapPost("/api/defense/block-ip", async (HttpRequest request, ActiveDefenseManager defense) =>
        {
            using var reader = new StreamReader(request.Body);
            string json = await reader.ReadToEndAsync();
            string? ip = null;
            string? reason = null;

            if (!string.IsNullOrWhiteSpace(json))
            {
                try
                {
                    var doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;
                    if (root.TryGetProperty("ip", out var ipEl) && ipEl.ValueKind == JsonValueKind.String)
                        ip = ipEl.GetString();
                    if (root.TryGetProperty("reason", out var rEl) && rEl.ValueKind == JsonValueKind.String)
                        reason = rEl.GetString();
                }
                catch (JsonException)
                {
                    return Results.BadRequest(new { success = false, error = "Malformed JSON payload.", elevation_required = false });
                }
            }

            if (string.IsNullOrWhiteSpace(ip))
            {
                return Results.BadRequest(new { success = false, error = "Missing 'ip' parameter.", elevation_required = false });
            }

            var result = defense.BlockIp(ip, reason);
            return Results.Ok(new
            {
                success = result.Success,
                rule_name = result.RuleName,
                ip = result.Ip,
                severed_count = result.SeveredConnectionCount,
                error = result.Error,
                elevation_required = result.ElevationRequired
            });
        });

        app.MapPost("/api/defense/unblock-ip", async (HttpRequest request, ActiveDefenseManager defense) =>
        {
            using var reader = new StreamReader(request.Body);
            string json = await reader.ReadToEndAsync();
            string? ip = null;

            if (!string.IsNullOrWhiteSpace(json))
            {
                try
                {
                    var doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;
                    if (root.TryGetProperty("ip", out var ipEl) && ipEl.ValueKind == JsonValueKind.String)
                        ip = ipEl.GetString();
                }
                catch (JsonException)
                {
                    return Results.BadRequest(new { success = false, error = "Malformed JSON payload.", elevation_required = false });
                }
            }

            if (string.IsNullOrWhiteSpace(ip))
            {
                return Results.BadRequest(new { success = false, error = "Missing 'ip' parameter.", elevation_required = false });
            }

            var result = defense.UnblockIp(ip);
            return Results.Ok(new
            {
                success = result.Success,
                ip = result.Ip,
                error = result.Error,
                elevation_required = result.ElevationRequired
            });
        });

        // 10. Security & Threat Scanning (Adopted from NetWatch-Sentinel)
        app.MapGet("/api/security/scan", (BandwidthTracker t, ISecurityScanner scanner) =>
        {
            var snapshot = t.GetLatestSnapshot();
            var procs = snapshot?.TopProcesses ?? new List<ProcessBandwidth>();
            var threats = scanner.GetDetectedThreats(procs);
            return Results.Ok(new
            {
                total_assessed = procs.Count,
                threat_count = threats.Count,
                threats,
                processes = procs.Select(p => new
                {
                    p.Pid,
                    p.Name,
                    p.ExePath,
                    p.TransferRateKbps,
                    threat = p.Threat
                })
            });
        });

        // 11. QoS DSCP Prioritization & CPU Tuning (Adopted from NetWatch-Sentinel)
        app.MapGet("/api/qos/policies", (IQosManager qos) =>
        {
            var policies = qos.GetActivePolicies();
            return Results.Ok(new { policies, is_admin = WindowsQosManager.IsAdmin() });
        });

        app.MapPost("/api/qos/apply", async (HttpRequest request, IQosManager qos) =>
        {
            using var reader = new StreamReader(request.Body);
            string json = await reader.ReadToEndAsync();
            var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(json) ? "{}" : json);
            if (!doc.RootElement.TryGetProperty("process_name", out var pEl))
            {
                return Results.BadRequest(new { error = "Missing process_name" });
            }
            string proc = pEl.GetString() ?? "";
            int dscp = doc.RootElement.TryGetProperty("dscp", out var dEl) ? dEl.GetInt32() : 46;
            long throttle = doc.RootElement.TryGetProperty("throttle_bytes", out var tEl) ? tEl.GetInt64() : -1;

            var (ok, msg) = qos.SetPolicy(proc, dscp, throttle);
            return Results.Ok(new { success = ok, message = msg, policies = qos.GetActivePolicies() });
        });

        app.MapPost("/api/qos/remove", async (HttpRequest request, IQosManager qos) =>
        {
            using var reader = new StreamReader(request.Body);
            string json = await reader.ReadToEndAsync();
            var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(json) ? "{}" : json);
            if (!doc.RootElement.TryGetProperty("process_name", out var pEl))
            {
                return Results.BadRequest(new { error = "Missing process_name" });
            }
            string proc = pEl.GetString() ?? "";
            var (ok, msg) = qos.RemovePolicy(proc);
            return Results.Ok(new { success = ok, message = msg, policies = qos.GetActivePolicies() });
        });

        app.MapPost("/api/qos/clear", (IQosManager qos) =>
        {
            var (ok, msg) = qos.ClearAllPolicies();
            return Results.Ok(new { success = ok, message = msg, policies = qos.GetActivePolicies() });
        });

        app.MapPost("/api/qos/priority", async (HttpRequest request, IQosManager qos) =>
        {
            using var reader = new StreamReader(request.Body);
            string json = await reader.ReadToEndAsync();
            var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(json) ? "{}" : json);
            if (!doc.RootElement.TryGetProperty("pid", out var pidEl))
            {
                return Results.BadRequest(new { error = "Missing pid" });
            }
            int pid = pidEl.GetInt32();
            string prio = doc.RootElement.TryGetProperty("priority", out var prioEl) ? prioEl.GetString() ?? "high" : "high";

            var (ok, msg) = qos.SetProcessCpuPriority(pid, prio);
            return Results.Ok(new { success = ok, message = msg });
        });

        // 12. Driverless VPN Engine (Adopted from NetWatch-Sentinel)
        app.MapGet("/api/vpn/status", (IVpnManager vpn) =>
        {
            return Results.Ok(vpn.GetStatus());
        });

        app.MapGet("/api/vpn/relays", (IVpnManager vpn) =>
        {
            return Results.Ok(new { relays = vpn.GetRelayNodes() });
        });

        app.MapPost("/api/vpn/connect", async (HttpRequest request, IVpnManager vpn) =>
        {
            using var reader = new StreamReader(request.Body);
            string json = await reader.ReadToEndAsync();
            var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(json) ? "{}" : json);
            string host = doc.RootElement.TryGetProperty("host", out var hEl) ? hEl.GetString() ?? "" : "";
            string proto = doc.RootElement.TryGetProperty("protocol", out var prEl) ? prEl.GetString() ?? "SSTP" : "SSTP";

            if (string.IsNullOrWhiteSpace(host))
            {
                var defaultNode = vpn.GetRelayNodes().FirstOrDefault();
                host = defaultNode?.HostOrIp ?? "public-vpn-58.opengw.net";
            }

            var (ok, msg) = await vpn.ConnectAsync(host, proto);
            return Results.Ok(new { success = ok, message = msg, status = vpn.GetStatus() });
        });

        app.MapPost("/api/vpn/disconnect", (IVpnManager vpn) =>
        {
            var (ok, msg) = vpn.Disconnect();
            return Results.Ok(new { success = ok, message = msg, status = vpn.GetStatus() });
        });

        // 13. Tor Privacy Gateway & System Proxy (Adopted from NetWatch-Sentinel)
        app.MapGet("/api/tor/status", (ITorManager tor) =>
        {
            return Results.Ok(tor.GetStatus());
        });

        app.MapPost("/api/tor/toggle", async (HttpRequest request, ITorManager tor) =>
        {
            using var reader = new StreamReader(request.Body);
            string json = await reader.ReadToEndAsync();
            var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(json) ? "{}" : json);
            bool enable = doc.RootElement.TryGetProperty("enabled", out var eEl) ? eEl.GetBoolean() : !tor.GetStatus().IsSystemProxyEnabled;
            int port = doc.RootElement.TryGetProperty("port", out var pEl) ? pEl.GetInt32() : 9050;
            if (enable)
            {
                var currentStatus = tor.GetStatus();
                if (!currentStatus.IsTorListening)
                {
                    return Results.Ok(new { success = false, message = "Tor service not detected on port 9050/9150. Please launch Tor before routing traffic.", status = currentStatus });
                }
            }

            var (ok, msg) = enable ? tor.EnableSystemProxy(port) : tor.DisableSystemProxy();
            return Results.Ok(new { success = ok, message = msg, status = tor.GetStatus() });
        });

        // 14. Network Diagnostics
        app.MapGet("/api/diagnostics/ping", async ([FromQuery] string? host) =>
        {
            var result = await NetworkDiagnostics.MeasurePingAsync(host ?? "1.1.1.1");
            return Results.Ok(result);
        });

        app.MapGet("/api/diagnostics/devices", () =>
        {
            var devices = NetworkDiagnostics.GetLocalSubnetDevices();
            return Results.Ok(new { devices, total = devices.Count });
        });

        app.MapPost("/api/diagnostics/speedtest", async (HttpRequest request) =>
        {
            using var reader = new StreamReader(request.Body);
            string json = await reader.ReadToEndAsync();
            int sizeMb = 5;
            if (!string.IsNullOrWhiteSpace(json))
            {
                var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("size_mb", out var sEl))
                    sizeMb = sEl.GetInt32();
            }
            var res = await NetworkDiagnostics.RunSpeedTestAsync(sizeMb);
            return Results.Ok(res);
        });

        app.MapGet("/api/diagnostics/wifi", (IWifiScanner scanner) =>
        {
            var result = scanner.Scan();
            return Results.Ok(new
            {
                success = result.Success,
                adapter_available = result.AdapterAvailable,
                interface_name = result.InterfaceName,
                count = result.Count,
                message = result.Message,
                networks = result.Networks.Select(n => new
                {
                    ssid = n.Ssid,
                    bssid = n.Bssid,
                    signal_pct = n.SignalPct,
                    signal_dbm = n.SignalDbm,
                    band = n.Band,
                    channel = n.Channel,
                    frequency_mhz = n.FrequencyMhz,
                    security = n.Security
                })
            });
        });

        // 15. Data Exports
        app.MapGet("/api/export/csv", ([FromQuery] string? type, NetflowStorage s) =>
        {
            string csv = type == "processes" ? s.ExportProcessesCsv() : s.ExportDailyCsv();
            return Results.File(System.Text.Encoding.UTF8.GetBytes(csv), "text/csv", $"netflow_{type ?? "daily"}.csv");
        });

        app.MapGet("/api/export/json", (NetflowStorage s) =>
        {
            var exportData = new
            {
                daily = s.GetDailyUsage(90),
                top_processes = s.GetTopProcesses(30 * 86400),
                plan = s.GetDataPlanStatus(),
                exported_at = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            };
            return Results.Ok(exportData);
        });

        // 16. System & Desktop Integration
        app.MapGet("/api/system/startup", () =>
        {
            return Results.Ok(new
            {
                enabled = WindowsStartupManager.IsStartupEnabled(),
                path = WindowsStartupManager.GetAppPath()
            });
        });

        app.MapPost("/api/system/startup", async (HttpRequest request) =>
        {
            using var reader = new StreamReader(request.Body);
            string json = await reader.ReadToEndAsync();
            bool enable = false;
            if (!string.IsNullOrWhiteSpace(json))
            {
                try
                {
                    var doc = JsonDocument.Parse(json);
                    if (doc.RootElement.TryGetProperty("enable", out var eEl) && (eEl.ValueKind == JsonValueKind.True || eEl.ValueKind == JsonValueKind.False))
                    {
                        enable = eEl.GetBoolean();
                    }
                    else if (doc.RootElement.TryGetProperty("enabled", out var edEl) && (edEl.ValueKind == JsonValueKind.True || edEl.ValueKind == JsonValueKind.False))
                    {
                        enable = edEl.GetBoolean();
                    }
                }
                catch (JsonException)
                {
                    return Results.BadRequest(new { success = false, error = "Malformed JSON payload.", enabled = WindowsStartupManager.IsStartupEnabled() });
                }
            }

            var res = WindowsStartupManager.SetStartupEnabled(enable);
            return Results.Ok(new
            {
                success = res.Success,
                enabled = res.Enabled,
                path = res.Path,
                error = res.Error
            });
        });

        app.MapGet("/api/system/notifications", () =>
        {
            return Results.Ok(new
            {
                enabled = NetflowBackgroundWorker.NotificationsEnabled
            });
        });

        app.MapPost("/api/system/notifications", async (HttpRequest request) =>
        {
            using var reader = new StreamReader(request.Body);
            string json = await reader.ReadToEndAsync();
            if (!string.IsNullOrWhiteSpace(json))
            {
                try
                {
                    var doc = JsonDocument.Parse(json);
                    if (doc.RootElement.TryGetProperty("enabled", out var eEl) && (eEl.ValueKind == JsonValueKind.True || eEl.ValueKind == JsonValueKind.False))
                    {
                        NetflowBackgroundWorker.NotificationsEnabled = eEl.GetBoolean();
                    }
                    else if (doc.RootElement.TryGetProperty("enable", out var enEl) && (enEl.ValueKind == JsonValueKind.True || enEl.ValueKind == JsonValueKind.False))
                    {
                        NetflowBackgroundWorker.NotificationsEnabled = enEl.GetBoolean();
                    }
                }
                catch { }
            }
            return Results.Ok(new
            {
                success = true,
                enabled = NetflowBackgroundWorker.NotificationsEnabled
            });
        });

        return app;
    }

    private static string FormatSpeed(double bytesPerSec)
    {
        if (bytesPerSec < 1024) return $"{bytesPerSec:F0} B/s";
        if (bytesPerSec < 1024 * 1024) return $"{bytesPerSec / 1024:F1} KB/s";
        if (bytesPerSec < 1024 * 1024 * 1024) return $"{bytesPerSec / (1024 * 1024):F1} MB/s";
        return $"{bytesPerSec / (1024 * 1024 * 1024):F2} GB/s";
    }
}
