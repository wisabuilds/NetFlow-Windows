using System.Net;
using System.Net.Sockets;
using NetFlow.Core.Models;

namespace NetFlow.Core.Storage;

public record GeoIpRangeEntry(
    uint StartIp,
    uint EndIp,
    string CountryCode,
    string CountryName,
    string Flag,
    int? Asn,
    string? AsOrg
);

public record GeoIpRangeEntryV6(
    string StartIp, // 32-character lowercase hex
    string EndIp,   // 32-character lowercase hex
    string CountryCode,
    string CountryName,
    string Flag,
    int? Asn,
    string? AsOrg
);

public class GeoIpDatabase : IDisposable
{
    private readonly string _dbPath;
    private IntPtr _db = IntPtr.Zero;
    private readonly object _lock = new();
    private bool _disposed;

    public GeoIpDatabase(string? dbPath = null)
    {
        _dbPath = dbPath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NetFlow", "geoip.db");

        var dir = Path.GetDirectoryName(_dbPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }

        Open();
        InitDb();
    }

    private void Open()
    {
        int flags = WinSqliteInterop.SQLITE_OPEN_READWRITE | WinSqliteInterop.SQLITE_OPEN_CREATE;
        int rc = WinSqliteInterop.Open(WinSqliteInterop.Utf8Bytes(_dbPath), out _db, flags, IntPtr.Zero);
        if (rc != WinSqliteInterop.SQLITE_OK)
        {
            string err = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ErrMsg(_db));
            throw new InvalidOperationException($"Failed to open SQLite database at '{_dbPath}': {err} (code {rc})");
        }

        ExecuteNonQuery("PRAGMA journal_mode=WAL;");
        ExecuteNonQuery("PRAGMA synchronous=NORMAL;");
    }

    public void ExecuteNonQuery(string sql)
    {
        lock (_lock)
        {
            if (_disposed || _db == IntPtr.Zero) return;
            int rc = WinSqliteInterop.Exec(_db, WinSqliteInterop.Utf8Bytes(sql), IntPtr.Zero, IntPtr.Zero, out IntPtr errPtr);
            if (rc != WinSqliteInterop.SQLITE_OK)
            {
                string msg = WinSqliteInterop.PtrToStringUtf8(errPtr);
                throw new InvalidOperationException($"SQLite execution error: {msg} for SQL: {sql}");
            }
        }
    }

    private void InitDb()
    {
        ExecuteNonQuery("""
            CREATE TABLE IF NOT EXISTS geoip_asn (
                start_ip INTEGER NOT NULL,
                end_ip INTEGER NOT NULL,
                country_code TEXT NOT NULL,
                country_name TEXT NOT NULL,
                flag TEXT NOT NULL,
                asn INTEGER,
                as_org TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_geoip_start_end
            ON geoip_asn (start_ip, end_ip);

            CREATE TABLE IF NOT EXISTS geoip_asn_v6 (
                start_ip TEXT NOT NULL,
                end_ip TEXT NOT NULL,
                country_code TEXT NOT NULL,
                country_name TEXT NOT NULL,
                flag TEXT NOT NULL,
                asn INTEGER,
                as_org TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_geoip_v6_start_end
            ON geoip_asn_v6 (start_ip, end_ip);
        """);

        if (GetCount() == 0)
        {
            InsertRangesBatch(GetCuratedRanges());
        }

        if (GetCountV6() == 0)
        {
            InsertRangesBatchV6(GetCuratedRangesV6());
        }
    }

    public int GetCount()
    {
        lock (_lock)
        {
            if (_disposed || _db == IntPtr.Zero) return 0;
            string sql = "SELECT COUNT(*) FROM geoip_asn;";
            int rc = WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sql), -1, out IntPtr stmt, IntPtr.Zero);
            if (rc != WinSqliteInterop.SQLITE_OK) return 0;
            try
            {
                if (WinSqliteInterop.Step(stmt) == WinSqliteInterop.SQLITE_ROW)
                {
                    return WinSqliteInterop.ColumnInt(stmt, 0);
                }
            }
            finally
            {
                WinSqliteInterop.Finalize(stmt);
            }
            return 0;
        }
    }

    public int GetCountV6()
    {
        lock (_lock)
        {
            if (_disposed || _db == IntPtr.Zero) return 0;
            string sql = "SELECT COUNT(*) FROM geoip_asn_v6;";
            int rc = WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sql), -1, out IntPtr stmt, IntPtr.Zero);
            if (rc != WinSqliteInterop.SQLITE_OK) return 0;
            try
            {
                if (WinSqliteInterop.Step(stmt) == WinSqliteInterop.SQLITE_ROW)
                {
                    return WinSqliteInterop.ColumnInt(stmt, 0);
                }
            }
            finally
            {
                WinSqliteInterop.Finalize(stmt);
            }
            return 0;
        }
    }

    public void InsertRange(GeoIpRangeEntry entry)
    {
        lock (_lock)
        {
            if (_disposed || _db == IntPtr.Zero) return;
            string sql = "INSERT INTO geoip_asn (start_ip, end_ip, country_code, country_name, flag, asn, as_org) VALUES (?, ?, ?, ?, ?, ?, ?);";
            int rc = WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sql), -1, out IntPtr stmt, IntPtr.Zero);
            if (rc != WinSqliteInterop.SQLITE_OK) return;

            try
            {
                WinSqliteInterop.BindInt64(stmt, 1, entry.StartIp);
                WinSqliteInterop.BindInt64(stmt, 2, entry.EndIp);
                WinSqliteInterop.BindText(stmt, 3, WinSqliteInterop.Utf8Bytes(entry.CountryCode), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                WinSqliteInterop.BindText(stmt, 4, WinSqliteInterop.Utf8Bytes(entry.CountryName), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                WinSqliteInterop.BindText(stmt, 5, WinSqliteInterop.Utf8Bytes(entry.Flag), -1, WinSqliteInterop.SQLITE_TRANSIENT);

                if (entry.Asn.HasValue)
                    WinSqliteInterop.BindInt(stmt, 6, entry.Asn.Value);
                else
                    WinSqliteInterop.BindNull(stmt, 6);

                if (!string.IsNullOrEmpty(entry.AsOrg))
                    WinSqliteInterop.BindText(stmt, 7, WinSqliteInterop.Utf8Bytes(entry.AsOrg), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                else
                    WinSqliteInterop.BindNull(stmt, 7);

                WinSqliteInterop.Step(stmt);
            }
            finally
            {
                WinSqliteInterop.Finalize(stmt);
            }
        }
    }

    public void InsertRangesBatch(IEnumerable<GeoIpRangeEntry> entries)
    {
        lock (_lock)
        {
            if (_disposed || _db == IntPtr.Zero) return;
            ExecuteNonQuery("BEGIN TRANSACTION;");
            try
            {
                foreach (var entry in entries)
                {
                    InsertRange(entry);
                }
                ExecuteNonQuery("COMMIT;");
            }
            catch
            {
                ExecuteNonQuery("ROLLBACK;");
                throw;
            }
        }
    }

    public void InsertRangeV6(GeoIpRangeEntryV6 entry)
    {
        lock (_lock)
        {
            if (_disposed || _db == IntPtr.Zero) return;
            string sql = "INSERT INTO geoip_asn_v6 (start_ip, end_ip, country_code, country_name, flag, asn, as_org) VALUES (?, ?, ?, ?, ?, ?, ?);";
            int rc = WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sql), -1, out IntPtr stmt, IntPtr.Zero);
            if (rc != WinSqliteInterop.SQLITE_OK) return;

            try
            {
                WinSqliteInterop.BindText(stmt, 1, WinSqliteInterop.Utf8Bytes(entry.StartIp), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                WinSqliteInterop.BindText(stmt, 2, WinSqliteInterop.Utf8Bytes(entry.EndIp), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                WinSqliteInterop.BindText(stmt, 3, WinSqliteInterop.Utf8Bytes(entry.CountryCode), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                WinSqliteInterop.BindText(stmt, 4, WinSqliteInterop.Utf8Bytes(entry.CountryName), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                WinSqliteInterop.BindText(stmt, 5, WinSqliteInterop.Utf8Bytes(entry.Flag), -1, WinSqliteInterop.SQLITE_TRANSIENT);

                if (entry.Asn.HasValue)
                    WinSqliteInterop.BindInt(stmt, 6, entry.Asn.Value);
                else
                    WinSqliteInterop.BindNull(stmt, 6);

                if (!string.IsNullOrEmpty(entry.AsOrg))
                    WinSqliteInterop.BindText(stmt, 7, WinSqliteInterop.Utf8Bytes(entry.AsOrg), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                else
                    WinSqliteInterop.BindNull(stmt, 7);

                WinSqliteInterop.Step(stmt);
            }
            finally
            {
                WinSqliteInterop.Finalize(stmt);
            }
        }
    }

    public void InsertRangesBatchV6(IEnumerable<GeoIpRangeEntryV6> entries)
    {
        lock (_lock)
        {
            if (_disposed || _db == IntPtr.Zero) return;
            ExecuteNonQuery("BEGIN TRANSACTION;");
            try
            {
                foreach (var entry in entries)
                {
                    InsertRangeV6(entry);
                }
                ExecuteNonQuery("COMMIT;");
            }
            catch
            {
                ExecuteNonQuery("ROLLBACK;");
                throw;
            }
        }
    }

    public GeoIpInfo? QueryRange(uint ip)
    {
        lock (_lock)
        {
            if (_disposed || _db == IntPtr.Zero) return null;
            // Find matching range with smallest interval (most specific CIDR prefix)
            string sql = "SELECT country_code, country_name, flag, asn, as_org FROM geoip_asn WHERE start_ip <= ? AND end_ip >= ? ORDER BY (end_ip - start_ip) ASC LIMIT 1;";
            int rc = WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sql), -1, out IntPtr stmt, IntPtr.Zero);
            if (rc != WinSqliteInterop.SQLITE_OK) return null;

            try
            {
                WinSqliteInterop.BindInt64(stmt, 1, ip);
                WinSqliteInterop.BindInt64(stmt, 2, ip);

                if (WinSqliteInterop.Step(stmt) == WinSqliteInterop.SQLITE_ROW)
                {
                    string cc = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 0));
                    string name = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 1));
                    string flag = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 2));

                    int? asn = null;
                    if (WinSqliteInterop.ColumnType(stmt, 3) != 5) // 5 = SQLITE_NULL
                    {
                        asn = WinSqliteInterop.ColumnInt(stmt, 3);
                    }

                    string? asOrg = null;
                    if (WinSqliteInterop.ColumnType(stmt, 4) != 5)
                    {
                        asOrg = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 4));
                    }

                    return new GeoIpInfo(cc, name, flag, asn, asOrg);
                }
            }
            finally
            {
                WinSqliteInterop.Finalize(stmt);
            }
            return null;
        }
    }

    public GeoIpInfo? QueryRangeV6(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetworkV6) return null;
        string hex = IpV6ToHex(ip);

        lock (_lock)
        {
            if (_disposed || _db == IntPtr.Zero) return null;
            string sql = "SELECT country_code, country_name, flag, asn, as_org FROM geoip_asn_v6 WHERE start_ip <= ? AND end_ip >= ? ORDER BY start_ip DESC, end_ip ASC LIMIT 1;";
            int rc = WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sql), -1, out IntPtr stmt, IntPtr.Zero);
            if (rc != WinSqliteInterop.SQLITE_OK) return null;

            try
            {
                WinSqliteInterop.BindText(stmt, 1, WinSqliteInterop.Utf8Bytes(hex), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                WinSqliteInterop.BindText(stmt, 2, WinSqliteInterop.Utf8Bytes(hex), -1, WinSqliteInterop.SQLITE_TRANSIENT);

                if (WinSqliteInterop.Step(stmt) == WinSqliteInterop.SQLITE_ROW)
                {
                    string cc = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 0));
                    string name = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 1));
                    string flag = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 2));

                    int? asn = null;
                    if (WinSqliteInterop.ColumnType(stmt, 3) != 5)
                    {
                        asn = WinSqliteInterop.ColumnInt(stmt, 3);
                    }

                    string? asOrg = null;
                    if (WinSqliteInterop.ColumnType(stmt, 4) != 5)
                    {
                        asOrg = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 4));
                    }

                    return new GeoIpInfo(cc, name, flag, asn, asOrg);
                }
            }
            finally
            {
                WinSqliteInterop.Finalize(stmt);
            }
            return null;
        }
    }

    public List<GeoIpRangeEntry> GetAllRanges()
    {
        var list = new List<GeoIpRangeEntry>();
        lock (_lock)
        {
            if (_disposed || _db == IntPtr.Zero) return list;
            string sql = "SELECT start_ip, end_ip, country_code, country_name, flag, asn, as_org FROM geoip_asn ORDER BY start_ip ASC;";
            int rc = WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sql), -1, out IntPtr stmt, IntPtr.Zero);
            if (rc != WinSqliteInterop.SQLITE_OK) return list;

            try
            {
                while (WinSqliteInterop.Step(stmt) == WinSqliteInterop.SQLITE_ROW)
                {
                    uint start = (uint)WinSqliteInterop.ColumnInt64(stmt, 0);
                    uint end = (uint)WinSqliteInterop.ColumnInt64(stmt, 1);
                    string cc = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 2));
                    string name = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 3));
                    string flag = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 4));

                    int? asn = null;
                    if (WinSqliteInterop.ColumnType(stmt, 5) != 5)
                    {
                        asn = WinSqliteInterop.ColumnInt(stmt, 5);
                    }

                    string? asOrg = null;
                    if (WinSqliteInterop.ColumnType(stmt, 6) != 5)
                    {
                        asOrg = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 6));
                    }

                    list.Add(new GeoIpRangeEntry(start, end, cc, name, flag, asn, asOrg));
                }
            }
            finally
            {
                WinSqliteInterop.Finalize(stmt);
            }
        }
        return list;
    }

    public List<GeoIpRangeEntryV6> GetAllRangesV6()
    {
        var list = new List<GeoIpRangeEntryV6>();
        lock (_lock)
        {
            if (_disposed || _db == IntPtr.Zero) return list;
            string sql = "SELECT start_ip, end_ip, country_code, country_name, flag, asn, as_org FROM geoip_asn_v6 ORDER BY start_ip ASC;";
            int rc = WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sql), -1, out IntPtr stmt, IntPtr.Zero);
            if (rc != WinSqliteInterop.SQLITE_OK) return list;

            try
            {
                while (WinSqliteInterop.Step(stmt) == WinSqliteInterop.SQLITE_ROW)
                {
                    string start = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 0));
                    string end = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 1));
                    string cc = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 2));
                    string name = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 3));
                    string flag = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 4));

                    int? asn = null;
                    if (WinSqliteInterop.ColumnType(stmt, 5) != 5)
                    {
                        asn = WinSqliteInterop.ColumnInt(stmt, 5);
                    }

                    string? asOrg = null;
                    if (WinSqliteInterop.ColumnType(stmt, 6) != 5)
                    {
                        asOrg = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 6));
                    }

                    list.Add(new GeoIpRangeEntryV6(start, end, cc, name, flag, asn, asOrg));
                }
            }
            finally
            {
                WinSqliteInterop.Finalize(stmt);
            }
        }
        return list;
    }

    public static uint IpToUInt32(string ipStr)
    {
        if (!IPAddress.TryParse(ipStr, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork)
            return 0;

        byte[] bytes = ip.GetAddressBytes();
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | (uint)bytes[3];
    }

    public static string UInt32ToIp(uint ip)
    {
        return $"{(ip >> 24) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 8) & 0xFF}.{ip & 0xFF}";
    }

    public static (uint StartIp, uint EndIp) ParseCidr(string cidr)
    {
        var parts = cidr.Split('/');
        uint ip = IpToUInt32(parts[0].Trim());
        int prefix = parts.Length > 1 && int.TryParse(parts[1].Trim(), out int p) ? p : 32;

        if (prefix <= 0) return (0u, uint.MaxValue);
        if (prefix >= 32) return (ip, ip);

        uint mask = 0xFFFFFFFFu << (32 - prefix);
        uint start = ip & mask;
        uint end = start | ~mask;
        return (start, end);
    }

    public static string IpV6ToHex(IPAddress ip)
    {
        byte[] bytes = ip.GetAddressBytes();
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public static (string StartHex, string EndHex) ParseCidrV6(string cidr)
    {
        var parts = cidr.Split('/');
        var ip = IPAddress.Parse(parts[0].Trim());
        int prefix = parts.Length > 1 && int.TryParse(parts[1].Trim(), out int p) ? p : 128;

        byte[] addr = ip.GetAddressBytes();
        byte[] start = new byte[16];
        byte[] end = new byte[16];

        for (int i = 0; i < 16; i++)
        {
            int bitStart = i * 8;
            int bitEnd = bitStart + 8;

            if (prefix >= bitEnd)
            {
                start[i] = addr[i];
                end[i] = addr[i];
            }
            else if (prefix > bitStart)
            {
                int bitsInByte = prefix - bitStart;
                byte mask = (byte)(0xFF << (8 - bitsInByte));
                start[i] = (byte)(addr[i] & mask);
                end[i] = (byte)(addr[i] | ~mask);
            }
            else
            {
                start[i] = 0x00;
                end[i] = 0xFF;
            }
        }

        return (Convert.ToHexString(start).ToLowerInvariant(), Convert.ToHexString(end).ToLowerInvariant());
    }

    public static string CountryCodeToFlag(string? countryCode)
    {
        if (string.IsNullOrWhiteSpace(countryCode))
            return "🌐";

        string upper = countryCode.Trim().ToUpperInvariant();
        if (upper == "LO") return "🏠";
        if (upper == "LAN") return "🏠";
        if (upper is "XX" or "ZZ" or "UN" or "UNKNOWN") return "🌐";

        if (upper.Length == 2 && upper[0] >= 'A' && upper[0] <= 'Z' && upper[1] >= 'A' && upper[1] <= 'Z')
        {
            int first = 0x1F1E6 + (upper[0] - 'A');
            int second = 0x1F1E6 + (upper[1] - 'A');
            return char.ConvertFromUtf32(first) + char.ConvertFromUtf32(second);
        }

        return "🌐";
    }

    public static IEnumerable<GeoIpRangeEntry> GetCuratedRanges()
    {
        var entries = new List<(string Cidr, string Cc, string Name, string Flag, int? Asn, string? Org)>
        {
            // --- Cloudflare (ASN 13335) ---
            ("1.1.1.0/24", "US", "United States", "🇺🇸", 13335, "Cloudflare, Inc."),
            ("1.0.0.0/24", "US", "United States", "🇺🇸", 13335, "Cloudflare, Inc."),
            ("104.16.0.0/12", "US", "United States", "🇺🇸", 13335, "Cloudflare, Inc."),
            ("172.64.0.0/13", "US", "United States", "🇺🇸", 13335, "Cloudflare, Inc."),
            ("162.158.0.0/15", "US", "United States", "🇺🇸", 13335, "Cloudflare, Inc."),
            ("198.41.128.0/17", "US", "United States", "🇺🇸", 13335, "Cloudflare, Inc."),
            ("141.101.64.0/18", "US", "United States", "🇺🇸", 13335, "Cloudflare, Inc."),
            ("108.162.192.0/18", "US", "United States", "🇺🇸", 13335, "Cloudflare, Inc."),

            // --- Google & Google Cloud (ASN 15169) ---
            ("8.8.8.0/24", "US", "United States", "🇺🇸", 15169, "Google LLC"),
            ("8.8.4.0/24", "US", "United States", "🇺🇸", 15169, "Google LLC"),
            ("8.8.0.0/16", "US", "United States", "🇺🇸", 15169, "Google LLC"),
            ("142.250.0.0/15", "US", "United States", "🇺🇸", 15169, "Google LLC"),
            ("172.217.0.0/16", "US", "United States", "🇺🇸", 15169, "Google LLC"),
            ("216.58.192.0/19", "US", "United States", "🇺🇸", 15169, "Google LLC"),
            ("34.64.0.0/10", "US", "United States", "🇺🇸", 15169, "Google Cloud"),
            ("35.184.0.0/13", "US", "United States", "🇺🇸", 15169, "Google Cloud"),
            ("35.192.0.0/12", "US", "United States", "🇺🇸", 15169, "Google Cloud"),
            ("35.208.0.0/12", "US", "United States", "🇺🇸", 15169, "Google Cloud"),
            ("35.224.0.0/12", "US", "United States", "🇺🇸", 15169, "Google Cloud"),

            // --- Microsoft & Azure (ASN 8075) ---
            ("13.107.4.0/24", "US", "United States", "🇺🇸", 8075, "Microsoft Corporation"),
            ("13.64.0.0/11", "US", "United States", "🇺🇸", 8075, "Microsoft Azure"),
            ("13.96.0.0/13", "US", "United States", "🇺🇸", 8075, "Microsoft Azure"),
            ("13.104.0.0/14", "US", "United States", "🇺🇸", 8075, "Microsoft Azure"),
            ("20.0.0.0/11", "US", "United States", "🇺🇸", 8075, "Microsoft Azure"),
            ("20.32.0.0/11", "US", "United States", "🇺🇸", 8075, "Microsoft Azure"),
            ("40.74.0.0/15", "US", "United States", "🇺🇸", 8075, "Microsoft Azure"),
            ("40.76.0.0/14", "US", "United States", "🇺🇸", 8075, "Microsoft Azure"),
            ("40.80.0.0/12", "US", "United States", "🇺🇸", 8075, "Microsoft Azure"),
            ("52.96.0.0/12", "US", "United States", "🇺🇸", 8075, "Microsoft Corporation"),
            ("52.112.0.0/14", "US", "United States", "🇺🇸", 8075, "Microsoft Corporation"),

            // --- Amazon AWS (ASN 16509) ---
            ("3.0.0.0/9", "US", "United States", "🇺🇸", 16509, "Amazon.com, Inc."),
            ("3.120.0.0/14", "US", "United States", "🇺🇸", 16509, "Amazon.com, Inc."),
            ("15.177.0.0/16", "US", "United States", "🇺🇸", 16509, "Amazon.com, Inc."),
            ("18.128.0.0/9", "US", "United States", "🇺🇸", 16509, "Amazon.com, Inc."),
            ("23.20.0.0/14", "US", "United States", "🇺🇸", 16509, "Amazon.com, Inc."),
            ("52.0.0.0/11", "US", "United States", "🇺🇸", 16509, "Amazon.com, Inc."),
            ("52.32.0.0/11", "US", "United States", "🇺🇸", 16509, "Amazon.com, Inc."),
            ("52.64.0.0/11", "US", "United States", "🇺🇸", 16509, "Amazon.com, Inc."),
            ("54.0.0.0/8", "US", "United States", "🇺🇸", 16509, "Amazon.com, Inc."),

            // --- Fastly (ASN 54113) ---
            ("151.101.0.0/16", "US", "United States", "🇺🇸", 54113, "Fastly, Inc."),
            ("199.232.0.0/16", "US", "United States", "🇺🇸", 54113, "Fastly, Inc."),

            // --- Akamai (ASN 20940) ---
            ("23.32.0.0/11", "US", "United States", "🇺🇸", 20940, "Akamai Technologies, Inc."),
            ("23.64.0.0/14", "US", "United States", "🇺🇸", 20940, "Akamai Technologies, Inc."),
            ("104.64.0.0/10", "US", "United States", "🇺🇸", 20940, "Akamai Technologies, Inc."),
            ("184.24.0.0/13", "US", "United States", "🇺🇸", 20940, "Akamai Technologies, Inc."),

            // --- Hetzner Online (ASN 24940) ---
            ("78.46.0.0/15", "DE", "Germany", "🇩🇪", 24940, "Hetzner Online GmbH"),
            ("88.198.0.0/16", "DE", "Germany", "🇩🇪", 24940, "Hetzner Online GmbH"),
            ("95.216.0.0/15", "FI", "Finland", "🇫🇮", 24940, "Hetzner Online GmbH"),
            ("136.243.0.0/16", "DE", "Germany", "🇩🇪", 24940, "Hetzner Online GmbH"),
            ("144.76.0.0/16", "DE", "Germany", "🇩🇪", 24940, "Hetzner Online GmbH"),
            ("148.251.0.0/16", "DE", "Germany", "🇩🇪", 24940, "Hetzner Online GmbH"),
            ("159.69.0.0/16", "DE", "Germany", "🇩🇪", 24940, "Hetzner Online GmbH"),
            ("168.119.0.0/16", "DE", "Germany", "🇩🇪", 24940, "Hetzner Online GmbH"),

            // --- OVH SAS (ASN 16276) ---
            ("51.254.0.0/15", "FR", "France", "🇫🇷", 16276, "OVH SAS"),
            ("54.36.0.0/14", "FR", "France", "🇫🇷", 16276, "OVH SAS"),
            ("137.74.0.0/16", "FR", "France", "🇫🇷", 16276, "OVH SAS"),
            ("145.239.0.0/16", "FR", "France", "🇫🇷", 16276, "OVH SAS"),
            ("151.80.0.0/16", "FR", "France", "🇫🇷", 16276, "OVH SAS"),
            ("178.32.0.0/15", "FR", "France", "🇫🇷", 16276, "OVH SAS"),
            ("188.165.0.0/16", "FR", "France", "🇫🇷", 16276, "OVH SAS"),

            // --- Global Layer B.V. (ASN 49453) ---
            ("185.190.140.0/22", "NL", "Netherlands", "🇳🇱", 49453, "Global Layer B.V."),

            // --- DigitalOcean (ASN 14061) ---
            ("104.248.0.0/16", "US", "United States", "🇺🇸", 14061, "DigitalOcean, LLC"),
            ("138.68.0.0/16", "US", "United States", "🇺🇸", 14061, "DigitalOcean, LLC"),
            ("142.93.0.0/16", "US", "United States", "🇺🇸", 14061, "DigitalOcean, LLC"),
            ("159.65.0.0/16", "US", "United States", "🇺🇸", 14061, "DigitalOcean, LLC"),
            ("165.227.0.0/16", "US", "United States", "🇺🇸", 14061, "DigitalOcean, LLC"),
            ("178.62.0.0/16", "GB", "United Kingdom", "🇬🇧", 14061, "DigitalOcean, LLC"),
            ("188.166.0.0/16", "NL", "Netherlands", "🇳🇱", 14061, "DigitalOcean, LLC"),

            // --- Linode / Akamai (ASN 63949) ---
            ("45.33.0.0/16", "US", "United States", "🇺🇸", 63949, "Linode, LLC"),
            ("45.56.0.0/16", "US", "United States", "🇺🇸", 63949, "Linode, LLC"),
            ("172.104.0.0/15", "US", "United States", "🇺🇸", 63949, "Linode, LLC"),

            // --- DNS & Root Servers ---
            ("9.9.9.0/24", "CH", "Switzerland", "🇨🇭", 19281, "Quad9"),
            ("149.112.112.0/24", "CH", "Switzerland", "🇨🇭", 19281, "Quad9"),
            ("208.67.220.0/22", "US", "United States", "🇺🇸", 36692, "Cisco OpenDNS LLC"),
            ("76.76.2.0/24", "CA", "Canada", "🇨🇦", 396982, "Control D"),
            ("198.41.0.0/24", "US", "United States", "🇺🇸", 20144, "VeriSign Global Registry Services (A-Root)"),
            ("199.9.14.0/24", "US", "United States", "🇺🇸", 394353, "USC-ISI (B-Root)"),
            ("192.33.4.0/24", "FR", "France", "🇫🇷", 2149, "Cogent Communications (C-Root)"),
            ("199.7.91.0/24", "US", "United States", "🇺🇸", 10886, "University of Maryland (D-Root)"),
            ("192.203.230.0/24", "US", "United States", "🇺🇸", 297, "NASA Ames Research Center (E-Root)"),
            ("192.5.5.0/24", "US", "United States", "🇺🇸", 3557, "Internet Systems Consortium, Inc. (F-Root)"),
            ("192.112.36.0/24", "US", "United States", "🇺🇸", 5927, "Defense Information Systems Agency (G-Root)"),
            ("198.97.190.0/24", "US", "United States", "🇺🇸", 1508, "U.S. Army Research Laboratory (H-Root)"),
            ("192.36.148.0/24", "SE", "Sweden", "🇸🇪", 8674, "Netnod (I-Root)"),
            ("192.58.128.0/24", "US", "United States", "🇺🇸", 26415, "VeriSign Global Registry Services (J-Root)"),
            ("193.0.14.0/24", "NL", "Netherlands", "🇳🇱", 25152, "RIPE NCC (K-Root)"),
            ("199.7.83.0/24", "US", "United States", "🇺🇸", 20144, "ICANN (L-Root)"),
            ("202.12.27.0/24", "JP", "Japan", "🇯🇵", 7500, "WIDE Project (M-Root)"),

            // --- Granular Country Allocations ---
            ("2.0.0.0/8", "FR", "France", "🇫🇷", null, "European Regional Allocation"),
            ("5.0.0.0/8", "DE", "Germany", "🇩🇪", null, "European Regional Allocation"),
            ("14.0.0.0/8", "JP", "Japan", "🇯🇵", null, "Asia-Pacific Regional Allocation"),
            ("27.0.0.0/8", "CN", "China", "🇨🇳", null, "Asia-Pacific Regional Allocation"),
            ("31.0.0.0/8", "GB", "United Kingdom", "🇬🇧", null, "European Regional Allocation"),
            ("46.0.0.0/8", "RU", "Russia", "🇷🇺", null, "European Regional Allocation"),
            ("49.0.0.0/8", "IN", "India", "🇮🇳", null, "Asia-Pacific Regional Allocation"),
            ("60.0.0.0/8", "AU", "Australia", "🇦🇺", null, "Asia-Pacific Regional Allocation"),
            ("80.0.0.0/8", "GB", "United Kingdom", "🇬🇧", null, "European Regional Allocation"),
            ("81.0.0.0/8", "DE", "Germany", "🇩🇪", null, "European Regional Allocation"),
            ("82.0.0.0/8", "FR", "France", "🇫🇷", null, "European Regional Allocation"),
            ("83.0.0.0/8", "ES", "Spain", "🇪🇸", null, "European Regional Allocation"),
            ("84.0.0.0/8", "NL", "Netherlands", "🇳🇱", null, "European Regional Allocation"),
            ("85.0.0.0/8", "CH", "Switzerland", "🇨🇭", null, "European Regional Allocation"),
            ("86.0.0.0/8", "GB", "United Kingdom", "🇬🇧", null, "European Regional Allocation"),
            ("87.0.0.0/8", "IT", "Italy", "🇮🇹", null, "European Regional Allocation"),
            ("88.0.0.0/8", "DE", "Germany", "🇩🇪", null, "European Regional Allocation"),
            ("89.0.0.0/8", "EU", "Europe", "🇪🇺", null, "European Regional Allocation"),
            ("90.0.0.0/8", "FR", "France", "🇫🇷", null, "European Regional Allocation"),
            ("91.0.0.0/8", "EU", "Europe", "🇪🇺", null, "European Regional Allocation"),
            ("92.0.0.0/8", "GB", "United Kingdom", "🇬🇧", null, "European Regional Allocation"),
            ("93.0.0.0/8", "IT", "Italy", "🇮🇹", null, "European Regional Allocation"),
            ("110.0.0.0/8", "CN", "China", "🇨🇳", null, "Asia-Pacific Regional Allocation"),
            ("111.0.0.0/8", "JP", "Japan", "🇯🇵", null, "Asia-Pacific Regional Allocation"),
            ("112.0.0.0/8", "KR", "South Korea", "🇰🇷", null, "Asia-Pacific Regional Allocation"),
            ("113.0.0.0/8", "CN", "China", "🇨🇳", null, "Asia-Pacific Regional Allocation"),
            ("114.0.0.0/8", "IN", "India", "🇮🇳", null, "Asia-Pacific Regional Allocation"),
            ("115.0.0.0/8", "CN", "China", "🇨🇳", null, "Asia-Pacific Regional Allocation"),
            ("116.0.0.0/8", "CN", "China", "🇨🇳", null, "Asia-Pacific Regional Allocation"),
            ("117.0.0.0/8", "IN", "India", "🇮🇳", null, "Asia-Pacific Regional Allocation"),
            ("118.0.0.0/8", "JP", "Japan", "🇯🇵", null, "Asia-Pacific Regional Allocation"),
            ("119.0.0.0/8", "JP", "Japan", "🇯🇵", null, "Asia-Pacific Regional Allocation"),
            ("120.0.0.0/8", "CN", "China", "🇨🇳", null, "Asia-Pacific Regional Allocation"),
            ("121.0.0.0/8", "CN", "China", "🇨🇳", null, "Asia-Pacific Regional Allocation"),
            ("122.0.0.0/8", "JP", "Japan", "🇯🇵", null, "Asia-Pacific Regional Allocation"),
            ("123.0.0.0/8", "CN", "China", "🇨🇳", null, "Asia-Pacific Regional Allocation"),
            ("124.0.0.0/8", "JP", "Japan", "🇯🇵", null, "Asia-Pacific Regional Allocation"),
            ("125.0.0.0/8", "JP", "Japan", "🇯🇵", null, "Asia-Pacific Regional Allocation"),
            ("126.0.0.0/8", "JP", "Japan", "🇯🇵", null, "Asia-Pacific Regional Allocation"),
            ("133.0.0.0/8", "JP", "Japan", "🇯🇵", 2500, "WIDE / JPNIC"),
            ("141.0.0.0/8", "DE", "Germany", "🇩🇪", null, "European Regional Allocation"),
            ("150.0.0.0/8", "JP", "Japan", "🇯🇵", null, "Asia-Pacific Regional Allocation"),
            ("153.0.0.0/8", "JP", "Japan", "🇯🇵", 4713, "NTT Communications"),
            ("175.0.0.0/8", "KR", "South Korea", "🇰🇷", null, "Asia-Pacific Regional Allocation"),
            ("180.0.0.0/8", "JP", "Japan", "🇯🇵", null, "Asia-Pacific Regional Allocation"),
            ("182.0.0.0/8", "IN", "India", "🇮🇳", null, "Asia-Pacific Regional Allocation"),
            ("183.0.0.0/8", "CN", "China", "🇨🇳", null, "Asia-Pacific Regional Allocation"),
            ("185.0.0.0/8", "EU", "Europe", "🇪🇺", null, "European Regional Allocation"),
            ("193.0.0.0/8", "EU", "Europe", "🇪🇺", null, "European Regional Allocation"),
            ("194.0.0.0/8", "GB", "United Kingdom", "🇬🇧", null, "European Regional Allocation"),
            ("195.0.0.0/8", "DE", "Germany", "🇩🇪", null, "European Regional Allocation"),
            ("200.0.0.0/8", "BR", "Brazil", "🇧🇷", null, "Latin America Regional Allocation"),
            ("201.0.0.0/8", "MX", "Mexico", "🇲🇽", null, "Latin America Regional Allocation"),
            ("202.0.0.0/8", "AU", "Australia", "🇦🇺", null, "Asia-Pacific Regional Allocation"),
            ("203.0.0.0/8", "JP", "Japan", "🇯🇵", null, "Asia-Pacific Regional Allocation"),
            ("210.0.0.0/8", "JP", "Japan", "🇯🇵", null, "Asia-Pacific Regional Allocation"),
            ("211.0.0.0/8", "KR", "South Korea", "🇰🇷", null, "Asia-Pacific Regional Allocation"),
            ("212.0.0.0/8", "GB", "United Kingdom", "🇬🇧", null, "European Regional Allocation"),
            ("213.0.0.0/8", "FR", "France", "🇫🇷", null, "European Regional Allocation"),
            ("217.0.0.0/8", "DE", "Germany", "🇩🇪", null, "European Regional Allocation"),
        };

        foreach (var item in entries)
        {
            var (start, end) = ParseCidr(item.Cidr);
            yield return new GeoIpRangeEntry(start, end, item.Cc, item.Name, item.Flag, item.Asn, item.Org);
        }
    }

    public static IEnumerable<GeoIpRangeEntryV6> GetCuratedRangesV6()
    {
        var entries = new List<(string Cidr, string Cc, string Name, string Flag, int? Asn, string? Org)>
        {
            // --- Google (ASN 15169) ---
            ("2001:4860::/32", "US", "United States", "🇺🇸", 15169, "Google LLC"),
            ("2607:f8b0::/32", "US", "United States", "🇺🇸", 15169, "Google LLC"),
            ("2a00:1450::/32", "US", "United States", "🇺🇸", 15169, "Google LLC"),

            // --- Cloudflare (ASN 13335) ---
            ("2606:4700::/32", "US", "United States", "🇺🇸", 13335, "Cloudflare, Inc."),
            ("2803:f800::/32", "US", "United States", "🇺🇸", 13335, "Cloudflare, Inc."),
            ("2a06:98c0::/29", "US", "United States", "🇺🇸", 13335, "Cloudflare, Inc."),

            // --- Microsoft Azure (ASN 8075) ---
            ("2603:1000::/24", "US", "United States", "🇺🇸", 8075, "Microsoft Corporation"),
            ("2a01:111::/32", "US", "United States", "🇺🇸", 8075, "Microsoft Corporation"),

            // --- Amazon AWS (ASN 16509) ---
            ("2600:1f00::/24", "US", "United States", "🇺🇸", 16509, "Amazon.com, Inc."),
            ("2600:9000::/28", "US", "United States", "🇺🇸", 16509, "Amazon.com, Inc."),

            // --- Quad9 (ASN 19281) ---
            ("2620:fe::/32", "CH", "Switzerland", "🇨🇭", 19281, "Quad9"),

            // --- Hetzner Online (ASN 24940) ---
            ("2a01:4f8::/32", "DE", "Germany", "🇩🇪", 24940, "Hetzner Online GmbH"),

            // --- OVH SAS (ASN 16276) ---
            ("2001:41d0::/32", "FR", "France", "🇫🇷", 16276, "OVH SAS"),

            // --- Broad Regional IPv6 Allocations ---
            ("2400::/12", "JP", "Japan", "🇯🇵", null, "Asia-Pacific Regional Allocation (APNIC)"),
            ("2600::/12", "US", "United States", "🇺🇸", null, "North America Regional Allocation (ARIN)"),
            ("2800::/12", "BR", "Brazil", "🇧🇷", null, "Latin America Regional Allocation (LACNIC)"),
            ("2a00::/12", "EU", "Europe", "🇪🇺", null, "European Regional Allocation (RIPE NCC)"),
            ("2c00::/12", "ZA", "South Africa", "🇿🇦", null, "African Regional Allocation (AFRINIC)")
        };

        foreach (var item in entries)
        {
            var (startHex, endHex) = ParseCidrV6(item.Cidr);
            yield return new GeoIpRangeEntryV6(startHex, endHex, item.Cc, item.Name, item.Flag, item.Asn, item.Org);
        }
    }

    private void SeedCuratedDataset()
    {
        InsertRangesBatch(GetCuratedRanges());
        InsertRangesBatchV6(GetCuratedRangesV6());
    }

    public void Dispose()
    {
        lock (_lock)
        {
            if (!_disposed && _db != IntPtr.Zero)
            {
                WinSqliteInterop.Close(_db);
                _db = IntPtr.Zero;
                _disposed = true;
            }
        }
    }
}
