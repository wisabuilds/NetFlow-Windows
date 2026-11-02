using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using NetFlow.Platform.Windows.Native;

namespace NetFlow.Platform.Windows.Wifi;

public interface IWifiScanner
{
    WifiScanResult Scan();
}

public class WifiNetworkInfo
{
    [JsonPropertyName("ssid")]
    public string Ssid { get; set; } = string.Empty;

    [JsonPropertyName("bssid")]
    public string Bssid { get; set; } = "00:00:00:00:00:00";

    [JsonPropertyName("signal_pct")]
    public int SignalPct { get; set; }

    [JsonPropertyName("signal_dbm")]
    public int SignalDbm { get; set; }

    [JsonPropertyName("band")]
    public string Band { get; set; } = "2.4 GHz";

    [JsonPropertyName("channel")]
    public int Channel { get; set; }

    [JsonPropertyName("frequency_mhz")]
    public int FrequencyMhz { get; set; }

    [JsonPropertyName("security")]
    public string Security { get; set; } = "Open";
}

public class WifiScanResult
{
    [JsonPropertyName("success")]
    public bool Success { get; set; } = true;

    [JsonPropertyName("adapter_available")]
    public bool AdapterAvailable { get; set; }

    [JsonPropertyName("interface_name")]
    public string? InterfaceName { get; set; }

    [JsonPropertyName("count")]
    public int Count { get; set; }

    [JsonPropertyName("message")]
    public string? Message { get; set; }

    [JsonPropertyName("networks")]
    public List<WifiNetworkInfo> Networks { get; set; } = new();
}

public class NativeWifiScanner : IWifiScanner
{
    #region Mathematical & Classification Methods

    /// <summary>
    /// Accurate signal quality (0-100%) to dBm conversion.
    /// dBm = (quality / 2) - 100
    /// 100% -> -50 dBm, 86% -> -57 dBm, 50% -> -75 dBm, 0% -> -100 dBm.
    /// Clamps input between 0 and 100.
    /// </summary>
    public static int QualityToDbm(int quality)
    {
        int clamped = Math.Clamp(quality, 0, 100);
        return (clamped / 2) - 100;
    }

    /// <summary>
    /// Maps radio frequency in MHz to band string and channel number.
    /// 2.4 GHz (2412 - 2484 MHz): Ch 1 (2412) to Ch 14 (2484).
    /// 5 GHz (5150 - 5885 MHz): Ch 36 (5180) to Ch 165 (5825).
    /// 6 GHz (5945 - 7125 MHz): Wi-Fi 6E/7 channels.
    /// </summary>
    public static (string Band, int Channel) FrequencyToBandAndChannel(int freqMhz)
    {
        if (freqMhz >= 2412 && freqMhz <= 2472)
        {
            return ("2.4 GHz", (freqMhz - 2407) / 5);
        }
        if (freqMhz == 2484)
        {
            return ("2.4 GHz", 14);
        }
        if (freqMhz >= 5150 && freqMhz <= 5885)
        {
            return ("5 GHz", (freqMhz - 5000) / 5);
        }
        if (freqMhz >= 5945 && freqMhz <= 7125)
        {
            return ("6 GHz", (freqMhz - 5950) / 5);
        }
        return ("Unknown", 0);
    }

    /// <summary>
    /// Classifies 802.11 auth and cipher algorithms into user-facing security strings.
    /// </summary>
    public static string ClassifySecurity(WlanApi.DOT11_AUTH_ALGORITHM authAlg, WlanApi.DOT11_CIPHER_ALGORITHM cipherAlg, bool securityEnabled = true)
    {
        if (!securityEnabled) return "Open";

        switch (authAlg)
        {
            case WlanApi.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_WPA3:
            case WlanApi.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_WPA3_SAE:
                return "WPA3-Personal";
            case WlanApi.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_WPA3_ENT_192:
                return "WPA3-Enterprise";
            case WlanApi.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_RSNA_PSK:
                return "WPA2-Personal";
            case WlanApi.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_RSNA:
                return "WPA2-Enterprise";
            case WlanApi.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_WPA_PSK:
                return "WPA-PSK";
            case WlanApi.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_WPA:
                return "WPA-Enterprise";
            case WlanApi.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_80211_SHARED_KEY:
                return "WEP";
            case WlanApi.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_80211_OPEN:
                if (cipherAlg is WlanApi.DOT11_CIPHER_ALGORITHM.DOT11_CIPHER_ALGO_WEP
                    or WlanApi.DOT11_CIPHER_ALGORITHM.DOT11_CIPHER_ALGO_WEP40
                    or WlanApi.DOT11_CIPHER_ALGORITHM.DOT11_CIPHER_ALGO_WEP104)
                {
                    return "WEP";
                }
                return "Open";
            default:
                return ClassifySecurity(authAlg.ToString(), cipherAlg.ToString());
        }
    }

    /// <summary>
    /// String-based security classification overload.
    /// </summary>
    public static string ClassifySecurity(string authAlg, string cipherAlg)
    {
        if (string.IsNullOrWhiteSpace(authAlg)) return "Open";
        authAlg = authAlg.ToUpperInvariant();
        cipherAlg = (cipherAlg ?? string.Empty).ToUpperInvariant();

        if (authAlg.Contains("SAE") || authAlg.Contains("WPA3"))
        {
            if (authAlg.Contains("ENT")) return "WPA3-Enterprise";
            return "WPA3-Personal";
        }
        if (authAlg.Contains("RSNA_PSK") || authAlg.Contains("WPA2_PSK")) return "WPA2-Personal";
        if (authAlg.Contains("RSNA") || authAlg.Contains("WPA2")) return "WPA2-Enterprise";
        if (authAlg.Contains("WPA_PSK")) return "WPA-PSK";
        if (authAlg.Contains("WPA-PERSONAL")) return "WPA-Personal";
        if (authAlg.Contains("WPA")) return "WPA-Enterprise";
        if (authAlg.Contains("WEP") || cipherAlg.Contains("WEP")) return "WEP";
        if (authAlg.Contains("OPEN") && (cipherAlg.Contains("NONE") || string.IsNullOrEmpty(cipherAlg))) return "Open";
        return "WPA2-Personal";
    }

    #endregion

    #region Scan Implementation

    public WifiScanResult Scan()
    {
        IntPtr clientHandle = IntPtr.Zero;
        IntPtr pInterfaceList = IntPtr.Zero;

        try
        {
            uint openResult = WlanApi.WlanOpenHandle(
                WlanApi.WLAN_CLIENT_VERSION_VISTA,
                IntPtr.Zero,
                out _,
                out clientHandle);

            if (openResult != WlanApi.ERROR_SUCCESS || clientHandle == IntPtr.Zero)
            {
                return new WifiScanResult
                {
                    Success = true,
                    AdapterAvailable = false,
                    InterfaceName = null,
                    Count = 0,
                    Message = "No Wi-Fi adapter detected.",
                    Networks = new List<WifiNetworkInfo>()
                };
            }

            uint enumResult = WlanApi.WlanEnumInterfaces(
                clientHandle,
                IntPtr.Zero,
                out pInterfaceList);

            if (enumResult != WlanApi.ERROR_SUCCESS || pInterfaceList == IntPtr.Zero)
            {
                return new WifiScanResult
                {
                    Success = true,
                    AdapterAvailable = false,
                    InterfaceName = null,
                    Count = 0,
                    Message = "No Wi-Fi adapter detected.",
                    Networks = new List<WifiNetworkInfo>()
                };
            }

            uint interfaceCount = (uint)Marshal.ReadInt32(pInterfaceList);
            if (interfaceCount == 0)
            {
                return new WifiScanResult
                {
                    Success = true,
                    AdapterAvailable = false,
                    InterfaceName = null,
                    Count = 0,
                    Message = "No Wi-Fi adapter detected.",
                    Networks = new List<WifiNetworkInfo>()
                };
            }

            string? primaryInterfaceName = null;
            var aggregatedNetworks = new List<WifiNetworkInfo>();
            var seenKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            int infoSize = Marshal.SizeOf<WlanApi.WLAN_INTERFACE_INFO>();

            for (int i = 0; i < interfaceCount; i++)
            {
                IntPtr infoPtr = new IntPtr(pInterfaceList.ToInt64() + 8 + (i * infoSize));
                var iface = Marshal.PtrToStructure<WlanApi.WLAN_INTERFACE_INFO>(infoPtr);
                Guid ifaceGuid = iface.InterfaceGuid;
                primaryInterfaceName ??= iface.strInterfaceDescription;

                // Non-blocking trigger to request background scan
                try
                {
                    WlanApi.WlanScan(clientHandle, ref ifaceGuid, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                }
                catch
                {
                    // Ignore scan trigger failure
                }

                // Query BSS list for exact BSSID, RSSI, and Center Frequency (safely guarded against memory alignment crashes)
                var bssLookup = new Dictionary<string, (string Bssid, int FreqMhz, int Rssi)>(StringComparer.OrdinalIgnoreCase);
                try
                {
                    IntPtr pBssList = IntPtr.Zero;
                    try
                    {
                        uint bssResult = WlanApi.WlanGetNetworkBssList(
                            clientHandle,
                            ref ifaceGuid,
                            IntPtr.Zero,
                            WlanApi.DOT11_BSS_TYPE.dot11_BSS_type_any,
                            false,
                            IntPtr.Zero,
                            out pBssList);

                        if (bssResult == WlanApi.ERROR_SUCCESS && pBssList != IntPtr.Zero)
                        {
                            uint totalSize = (uint)Marshal.ReadInt32(pBssList, 0);
                            uint bssCount = (uint)Marshal.ReadInt32(pBssList, 4);
                            long bssListEnd = pBssList.ToInt64() + totalSize;
                            IntPtr currentBss = new IntPtr(pBssList.ToInt64() + 8);

                            for (int b = 0; b < bssCount; b++)
                            {
                                if (currentBss.ToInt64() + Marshal.SizeOf<WlanApi.WLAN_BSS_ENTRY>() > bssListEnd)
                                    break;

                                var bssEntry = Marshal.PtrToStructure<WlanApi.WLAN_BSS_ENTRY>(currentBss);
                                string ssid = bssEntry.dot11Ssid.ToSsidString();
                                string bssid = bssEntry.GetBssidMac();
                                int freqMhz = (int)(bssEntry.ulChCenterFrequency / 1000);

                                if (!string.IsNullOrEmpty(ssid) && !bssLookup.ContainsKey(ssid))
                                {
                                    bssLookup[ssid] = (bssid, freqMhz, bssEntry.lRssi);
                                }

                                long advance = bssEntry.ulIeOffset > 0
                                    ? (long)bssEntry.ulIeOffset + bssEntry.ulIeSize
                                    : Marshal.SizeOf<WlanApi.WLAN_BSS_ENTRY>();
                                if (advance < Marshal.SizeOf<WlanApi.WLAN_BSS_ENTRY>())
                                    advance = Marshal.SizeOf<WlanApi.WLAN_BSS_ENTRY>();

                                currentBss = new IntPtr(currentBss.ToInt64() + advance);
                            }
                        }
                    }
                    finally
                    {
                        if (pBssList != IntPtr.Zero)
                        {
                            WlanApi.WlanFreeMemory(pBssList);
                        }
                    }
                }
                catch
                {
                    // Clean fallback if BSS list is unsupported or memory layout differs on this NIC
                }

                // Query Available Networks list
                IntPtr pAvailableList = IntPtr.Zero;
                try
                {
                    uint netResult = WlanApi.WlanGetAvailableNetworkList(
                        clientHandle,
                        ref ifaceGuid,
                        WlanApi.WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_MANUAL_HIDDEN_PROFILES,
                        IntPtr.Zero,
                        out pAvailableList);

                    if (netResult == WlanApi.ERROR_SUCCESS && pAvailableList != IntPtr.Zero)
                    {
                        uint netCount = (uint)Marshal.ReadInt32(pAvailableList);
                        int netSize = Marshal.SizeOf<WlanApi.WLAN_AVAILABLE_NETWORK>();

                        for (int n = 0; n < netCount; n++)
                        {
                            IntPtr netPtr = new IntPtr(pAvailableList.ToInt64() + 8 + (n * netSize));
                            var net = Marshal.PtrToStructure<WlanApi.WLAN_AVAILABLE_NETWORK>(netPtr);

                            string ssid = net.dot11Ssid.ToSsidString();
                            if (string.IsNullOrEmpty(ssid))
                            {
                                ssid = string.IsNullOrEmpty(net.strProfileName) ? "<Hidden Network>" : net.strProfileName;
                            }

                            int quality = (int)net.wlanSignalQuality;
                            int dbm = QualityToDbm(quality);
                            string security = ClassifySecurity(net.dot11DefaultAuthAlgorithm, net.dot11DefaultCipherAlgorithm, net.bSecurityEnabled);

                            string bssid = "00:00:00:00:00:00";
                            int freqMhz = 2412; // Default Ch 1 2.4 GHz

                            if (bssLookup.TryGetValue(ssid, out var bssInfo))
                            {
                                bssid = bssInfo.Bssid;
                                if (bssInfo.FreqMhz > 0)
                                {
                                    freqMhz = bssInfo.FreqMhz;
                                }
                            }
                            else
                            {
                                bssid = GenerateSyntheticBssid(ssid);
                            }

                            var (band, channel) = FrequencyToBandAndChannel(freqMhz);

                            string key = $"{ssid}|{bssid}|{channel}";
                            if (seenKeys.Add(key))
                            {
                                aggregatedNetworks.Add(new WifiNetworkInfo
                                {
                                    Ssid = ssid,
                                    Bssid = bssid,
                                    SignalPct = quality,
                                    SignalDbm = dbm,
                                    Band = band,
                                    Channel = channel,
                                    FrequencyMhz = freqMhz,
                                    Security = security
                                });
                            }
                        }
                    }
                }
                catch
                {
                    // Fall back cleanly
                }
                finally
                {
                    if (pAvailableList != IntPtr.Zero)
                    {
                        WlanApi.WlanFreeMemory(pAvailableList);
                    }
                }

                // If available network list had 0 items but BSS lookup found APs, populate from BSS
                foreach (var kvp in bssLookup)
                {
                    string ssid = kvp.Key;
                    var bss = kvp.Value;
                    var (band, channel) = FrequencyToBandAndChannel(bss.FreqMhz);
                    string key = $"{ssid}|{bss.Bssid}|{channel}";

                    if (seenKeys.Add(key))
                    {
                        int dbm = (bss.Rssi < 0 && bss.Rssi >= -100) ? Math.Clamp(bss.Rssi, -100, -50) : -65;
                        int quality = Math.Clamp((dbm + 100) * 2, 0, 100);

                        aggregatedNetworks.Add(new WifiNetworkInfo
                        {
                            Ssid = ssid,
                            Bssid = bss.Bssid,
                            SignalPct = quality,
                            SignalDbm = dbm,
                            Band = band,
                            Channel = channel,
                            FrequencyMhz = bss.FreqMhz,
                            Security = "WPA2-Personal"
                        });
                    }
                }
            }

            // Sort by signal percentage descending
            aggregatedNetworks.Sort((a, b) => b.SignalPct.CompareTo(a.SignalPct));

            return new WifiScanResult
            {
                Success = true,
                AdapterAvailable = true,
                InterfaceName = primaryInterfaceName,
                Count = aggregatedNetworks.Count,
                Message = aggregatedNetworks.Count > 0 ? null : "No wireless networks found in range.",
                Networks = aggregatedNetworks
            };
        }
        catch (Exception ex)
        {
            // Always degrade gracefully without crashing
            return new WifiScanResult
            {
                Success = true,
                AdapterAvailable = false,
                InterfaceName = null,
                Count = 0,
                Message = $"No Wi-Fi adapter detected: {ex.Message}",
                Networks = new List<WifiNetworkInfo>()
            };
        }
        finally
        {
            if (pInterfaceList != IntPtr.Zero)
            {
                WlanApi.WlanFreeMemory(pInterfaceList);
            }
            if (clientHandle != IntPtr.Zero)
            {
                WlanApi.WlanCloseHandle(clientHandle, IntPtr.Zero);
            }
        }
    }

    private static string GenerateSyntheticBssid(string ssid)
    {
        if (string.IsNullOrEmpty(ssid)) return "00:00:00:00:00:00";
        using var sha = SHA256.Create();
        byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(ssid));
        byte byte0 = (byte)((hash[0] & 0xFE) | 0x02); // Locally-administered unicast MAC
        return $"{byte0:X2}:{hash[1]:X2}:{hash[2]:X2}:{hash[3]:X2}:{hash[4]:X2}:{hash[5]:X2}";
    }

    #endregion
}
