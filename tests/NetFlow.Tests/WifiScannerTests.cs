using System.Text.Json;
using NetFlow.Platform.Windows.Native;
using NetFlow.Platform.Windows.Wifi;
using NetFlow.Server;
using Xunit;

namespace NetFlow.Tests;

public class WifiScannerTests
{
    #region Signal Quality to dBm Conversion Tests

    [Theory]
    [InlineData(100, -50)]
    [InlineData(86, -57)]
    [InlineData(50, -75)]
    [InlineData(0, -100)]
    public void QualityToDbm_StandardValues_MatchExpectedDbm(int quality, int expectedDbm)
    {
        int actualDbm = NativeWifiScanner.QualityToDbm(quality);
        Assert.Equal(expectedDbm, actualDbm);
    }

    [Theory]
    [InlineData(-50, -100)]
    [InlineData(-1, -100)]
    [InlineData(101, -50)]
    [InlineData(200, -50)]
    public void QualityToDbm_OutOfRange_ClampedCorrectly(int quality, int expectedDbm)
    {
        int actualDbm = NativeWifiScanner.QualityToDbm(quality);
        Assert.Equal(expectedDbm, actualDbm);
    }

    [Fact]
    public void QualityToDbm_MonotonicallyIncreases()
    {
        int prevDbm = NativeWifiScanner.QualityToDbm(0);
        for (int q = 2; q <= 100; q += 2)
        {
            int currentDbm = NativeWifiScanner.QualityToDbm(q);
            Assert.True(currentDbm >= prevDbm, $"dBm at {q}% ({currentDbm}) must be >= dBm at {q - 2}% ({prevDbm})");
            prevDbm = currentDbm;
        }
    }

    #endregion

    #region Frequency to Band & Channel Mapping Tests

    [Theory]
    [InlineData(2412, "2.4 GHz", 1)]
    [InlineData(2417, "2.4 GHz", 2)]
    [InlineData(2437, "2.4 GHz", 6)]
    [InlineData(2462, "2.4 GHz", 11)]
    [InlineData(2472, "2.4 GHz", 13)]
    [InlineData(2484, "2.4 GHz", 14)]
    public void FrequencyToBandAndChannel_24GHz_MapsCorrectly(int freqMhz, string expectedBand, int expectedChannel)
    {
        var (band, channel) = NativeWifiScanner.FrequencyToBandAndChannel(freqMhz);
        Assert.Equal(expectedBand, band);
        Assert.Equal(expectedChannel, channel);
    }

    [Theory]
    [InlineData(5180, "5 GHz", 36)]
    [InlineData(5200, "5 GHz", 40)]
    [InlineData(5240, "5 GHz", 48)]
    [InlineData(5260, "5 GHz", 52)]
    [InlineData(5500, "5 GHz", 100)]
    [InlineData(5745, "5 GHz", 149)]
    [InlineData(5825, "5 GHz", 165)]
    public void FrequencyToBandAndChannel_5GHz_MapsCorrectly(int freqMhz, string expectedBand, int expectedChannel)
    {
        var (band, channel) = NativeWifiScanner.FrequencyToBandAndChannel(freqMhz);
        Assert.Equal(expectedBand, band);
        Assert.Equal(expectedChannel, channel);
    }

    [Theory]
    [InlineData(5955, "6 GHz", 1)]
    [InlineData(5975, "6 GHz", 5)]
    [InlineData(6115, "6 GHz", 33)]
    [InlineData(6535, "6 GHz", 117)]
    [InlineData(7115, "6 GHz", 233)]
    public void FrequencyToBandAndChannel_6GHz_MapsCorrectly(int freqMhz, string expectedBand, int expectedChannel)
    {
        var (band, channel) = NativeWifiScanner.FrequencyToBandAndChannel(freqMhz);
        Assert.Equal(expectedBand, band);
        Assert.Equal(expectedChannel, channel);
    }

    [Theory]
    [InlineData(900)]
    [InlineData(2400)]
    [InlineData(5000)]
    [InlineData(8000)]
    public void FrequencyToBandAndChannel_OutOfRange_ReturnsUnknown(int freqMhz)
    {
        var (band, channel) = NativeWifiScanner.FrequencyToBandAndChannel(freqMhz);
        Assert.Equal("Unknown", band);
        Assert.Equal(0, channel);
    }

    #endregion

    #region Security Algorithm Mapping Tests

    [Fact]
    public void ClassifySecurity_Wpa3Personal_Mapped()
    {
        string sec1 = NativeWifiScanner.ClassifySecurity(
            WlanApi.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_WPA3,
            WlanApi.DOT11_CIPHER_ALGORITHM.DOT11_CIPHER_ALGO_CCMP);
        Assert.Equal("WPA3-Personal", sec1);

        string sec2 = NativeWifiScanner.ClassifySecurity(
            WlanApi.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_WPA3_SAE,
            WlanApi.DOT11_CIPHER_ALGORITHM.DOT11_CIPHER_ALGO_CCMP);
        Assert.Equal("WPA3-Personal", sec2);

        string secStr = NativeWifiScanner.ClassifySecurity("DOT11_AUTH_ALGO_WPA3_SAE", "DOT11_CIPHER_ALGO_CCMP");
        Assert.Equal("WPA3-Personal", secStr);
    }

    [Fact]
    public void ClassifySecurity_Wpa3Enterprise_Mapped()
    {
        string sec = NativeWifiScanner.ClassifySecurity(
            WlanApi.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_WPA3_ENT_192,
            WlanApi.DOT11_CIPHER_ALGORITHM.DOT11_CIPHER_ALGO_CCMP);
        Assert.Equal("WPA3-Enterprise", sec);

        string secStr = NativeWifiScanner.ClassifySecurity("DOT11_AUTH_ALGO_WPA3_ENT_192", "DOT11_CIPHER_ALGO_GCMP_256");
        Assert.Equal("WPA3-Enterprise", secStr);
    }

    [Fact]
    public void ClassifySecurity_Wpa2Personal_Mapped()
    {
        string sec = NativeWifiScanner.ClassifySecurity(
            WlanApi.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_RSNA_PSK,
            WlanApi.DOT11_CIPHER_ALGORITHM.DOT11_CIPHER_ALGO_CCMP);
        Assert.Equal("WPA2-Personal", sec);

        string secStr = NativeWifiScanner.ClassifySecurity("DOT11_AUTH_ALGO_RSNA_PSK", "DOT11_CIPHER_ALGO_CCMP");
        Assert.Equal("WPA2-Personal", secStr);
    }

    [Fact]
    public void ClassifySecurity_Wpa2Enterprise_Mapped()
    {
        string sec = NativeWifiScanner.ClassifySecurity(
            WlanApi.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_RSNA,
            WlanApi.DOT11_CIPHER_ALGORITHM.DOT11_CIPHER_ALGO_CCMP);
        Assert.Equal("WPA2-Enterprise", sec);

        string secStr = NativeWifiScanner.ClassifySecurity("DOT11_AUTH_ALGO_RSNA", "DOT11_CIPHER_ALGO_CCMP");
        Assert.Equal("WPA2-Enterprise", secStr);
    }

    [Fact]
    public void ClassifySecurity_WpaPsk_Mapped()
    {
        string sec = NativeWifiScanner.ClassifySecurity(
            WlanApi.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_WPA_PSK,
            WlanApi.DOT11_CIPHER_ALGORITHM.DOT11_CIPHER_ALGO_TKIP);
        Assert.Equal("WPA-PSK", sec);

        string secStr = NativeWifiScanner.ClassifySecurity("DOT11_AUTH_ALGO_WPA_PSK", "DOT11_CIPHER_ALGO_TKIP");
        Assert.Equal("WPA-PSK", secStr);
    }

    [Fact]
    public void ClassifySecurity_Wep_Mapped()
    {
        string secShared = NativeWifiScanner.ClassifySecurity(
            WlanApi.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_80211_SHARED_KEY,
            WlanApi.DOT11_CIPHER_ALGORITHM.DOT11_CIPHER_ALGO_WEP);
        Assert.Equal("WEP", secShared);

        string secOpenWep = NativeWifiScanner.ClassifySecurity(
            WlanApi.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_80211_OPEN,
            WlanApi.DOT11_CIPHER_ALGORITHM.DOT11_CIPHER_ALGO_WEP40);
        Assert.Equal("WEP", secOpenWep);

        string secStr = NativeWifiScanner.ClassifySecurity("DOT11_AUTH_ALGO_80211_OPEN", "DOT11_CIPHER_ALGO_WEP");
        Assert.Equal("WEP", secStr);
    }

    [Fact]
    public void ClassifySecurity_Open_Mapped()
    {
        string sec = NativeWifiScanner.ClassifySecurity(
            WlanApi.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_80211_OPEN,
            WlanApi.DOT11_CIPHER_ALGORITHM.DOT11_CIPHER_ALGO_NONE);
        Assert.Equal("Open", sec);

        string secDisabled = NativeWifiScanner.ClassifySecurity(
            WlanApi.DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_RSNA_PSK,
            WlanApi.DOT11_CIPHER_ALGORITHM.DOT11_CIPHER_ALGO_CCMP,
            securityEnabled: false);
        Assert.Equal("Open", secDisabled);

        string secStr = NativeWifiScanner.ClassifySecurity("DOT11_AUTH_ALGO_80211_OPEN", "DOT11_CIPHER_ALGO_NONE");
        Assert.Equal("Open", secStr);
    }

    #endregion

    #region Graceful Degradation & Scanner Execution Tests

    [Fact]
    public void Scan_ExecutesWithoutThrowing()
    {
        var scanner = new NativeWifiScanner();
        var result = scanner.Scan();

        Assert.NotNull(result);
        Assert.True(result.Success);
        Assert.NotNull(result.Networks);

        if (!result.AdapterAvailable)
        {
            Assert.Equal(0, result.Count);
            Assert.Empty(result.Networks);
            Assert.False(string.IsNullOrWhiteSpace(result.Message));
        }
        else
        {
            Assert.Equal(result.Count, result.Networks.Count);
            foreach (var net in result.Networks)
            {
                Assert.False(string.IsNullOrEmpty(net.Ssid));
                Assert.Equal(17, net.Bssid.Length); // XX:XX:XX:XX:XX:XX
                Assert.InRange(net.SignalPct, 0, 100);
                Assert.InRange(net.SignalDbm, -100, -50);
                Assert.False(string.IsNullOrEmpty(net.Band));
                Assert.False(string.IsNullOrEmpty(net.Security));
            }
        }
    }

    [Fact]
    public void WifiScanResult_Serialization_PreservesContractFields()
    {
        var scanResult = new WifiScanResult
        {
            Success = true,
            AdapterAvailable = true,
            InterfaceName = "Wi-Fi Adapter",
            Count = 1,
            Message = null,
            Networks = new List<WifiNetworkInfo>
            {
                new()
                {
                    Ssid = "Test_Net_5G",
                    Bssid = "00:11:22:33:44:55",
                    SignalPct = 86,
                    SignalDbm = -57,
                    Band = "5 GHz",
                    Channel = 36,
                    FrequencyMhz = 5180,
                    Security = "WPA2-Personal"
                }
            }
        };

        string json = JsonSerializer.Serialize(scanResult);
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.GetProperty("success").GetBoolean());
        Assert.True(root.GetProperty("adapter_available").GetBoolean());
        Assert.Equal("Wi-Fi Adapter", root.GetProperty("interface_name").GetString());
        Assert.Equal(1, root.GetProperty("count").GetInt32());

        var netEl = root.GetProperty("networks")[0];
        Assert.Equal("Test_Net_5G", netEl.GetProperty("ssid").GetString());
        Assert.Equal("00:11:22:33:44:55", netEl.GetProperty("bssid").GetString());
        Assert.Equal(86, netEl.GetProperty("signal_pct").GetInt32());
        Assert.Equal(-57, netEl.GetProperty("signal_dbm").GetInt32());
        Assert.Equal("5 GHz", netEl.GetProperty("band").GetString());
        Assert.Equal(36, netEl.GetProperty("channel").GetInt32());
        Assert.Equal(5180, netEl.GetProperty("frequency_mhz").GetInt32());
        Assert.Equal("WPA2-Personal", netEl.GetProperty("security").GetString());
    }

    [Fact]
    public void DiagnosticsWifi_Scanner_ReturnsValidContract()
    {
        var scanner = new NativeWifiScanner();
        var result = scanner.Scan();

        Assert.NotNull(result);
        Assert.True(result.Success);
        Assert.NotNull(result.Networks);
    }

    #endregion
}
