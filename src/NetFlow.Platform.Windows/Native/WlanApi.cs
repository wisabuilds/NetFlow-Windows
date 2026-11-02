using System.Runtime.InteropServices;
using System.Text;

namespace NetFlow.Platform.Windows.Native;

public static class WlanApi
{
    public const uint WLAN_CLIENT_VERSION_VISTA = 2;
    public const uint WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_ADHOC_PROFILES = 0x00000001;
    public const uint WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_MANUAL_HIDDEN_PROFILES = 0x00000002;

    public const uint ERROR_SUCCESS = 0;
    public const uint ERROR_INVALID_PARAMETER = 87;
    public const uint ERROR_SERVICE_NOT_ACTIVE = 1062;
    public const uint ERROR_NOT_SUPPORTED = 50;

    #region P/Invoke Methods

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern uint WlanOpenHandle(
        uint dwClientVersion,
        IntPtr pReserved,
        out uint pdwNegotiatedVersion,
        out IntPtr phClientHandle);

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern uint WlanCloseHandle(
        IntPtr hClientHandle,
        IntPtr pReserved);

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern uint WlanEnumInterfaces(
        IntPtr hClientHandle,
        IntPtr pReserved,
        out IntPtr ppInterfaceList);

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern uint WlanGetAvailableNetworkList(
        IntPtr hClientHandle,
        ref Guid pInterfaceGuid,
        uint dwFlags,
        IntPtr pReserved,
        out IntPtr ppAvailableNetworkList);

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern uint WlanGetNetworkBssList(
        IntPtr hClientHandle,
        ref Guid pInterfaceGuid,
        IntPtr pDot11Ssid,
        DOT11_BSS_TYPE dot11BssType,
        [MarshalAs(UnmanagedType.Bool)] bool bSecurityEnabled,
        IntPtr pReserved,
        out IntPtr ppWlanBssList);

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern uint WlanQueryInterface(
        IntPtr hClientHandle,
        ref Guid pInterfaceGuid,
        WLAN_INTF_OPCODE OpCode,
        IntPtr pReserved,
        out uint pdwDataSize,
        out IntPtr ppData,
        out WLAN_OPCODE_VALUE_TYPE pWlanOpcodeValueType);

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern uint WlanScan(
        IntPtr hClientHandle,
        ref Guid pInterfaceGuid,
        IntPtr pDot11Ssid,
        IntPtr pIeData,
        IntPtr pReserved);

    [DllImport("wlanapi.dll")]
    public static extern void WlanFreeMemory(IntPtr pMemory);

    #endregion

    #region Enums & Structs

    [StructLayout(LayoutKind.Sequential)]
    public struct DOT11_SSID
    {
        public uint uSSIDLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] ucSSID;

        public string ToSsidString()
        {
            if (uSSIDLength == 0 || ucSSID == null) return string.Empty;
            int len = Math.Min((int)uSSIDLength, 32);
            return Encoding.UTF8.GetString(ucSSID, 0, len);
        }
    }

    public enum DOT11_BSS_TYPE : uint
    {
        dot11_BSS_type_infrastructure = 1,
        dot11_BSS_type_independent = 2,
        dot11_BSS_type_any = 3
    }

    public enum DOT11_AUTH_ALGORITHM : uint
    {
        DOT11_AUTH_ALGO_80211_OPEN = 1,
        DOT11_AUTH_ALGO_80211_SHARED_KEY = 2,
        DOT11_AUTH_ALGO_WPA = 3,
        DOT11_AUTH_ALGO_WPA_PSK = 4,
        DOT11_AUTH_ALGO_WPA_NONE = 5,
        DOT11_AUTH_ALGO_RSNA = 6,
        DOT11_AUTH_ALGO_RSNA_PSK = 7,
        DOT11_AUTH_ALGO_WPA3 = 8,
        DOT11_AUTH_ALGO_WPA3_ENT_192 = 9,
        DOT11_AUTH_ALGO_WPA3_SAE = 10,
        DOT11_AUTH_ALGO_OWE = 11,
        DOT11_AUTH_ALGO_IHV_START = 0x80000000,
        DOT11_AUTH_ALGO_IHV_END = 0xffffffff
    }

    public enum DOT11_CIPHER_ALGORITHM : uint
    {
        DOT11_CIPHER_ALGO_NONE = 0x00,
        DOT11_CIPHER_ALGO_WEP40 = 0x01,
        DOT11_CIPHER_ALGO_TKIP = 0x02,
        DOT11_CIPHER_ALGO_CCMP = 0x04,
        DOT11_CIPHER_ALGO_WEP104 = 0x05,
        DOT11_CIPHER_ALGO_WPA_USE_GROUP = 0x100,
        DOT11_CIPHER_ALGO_RSN_USE_GROUP = 0x100,
        DOT11_CIPHER_ALGO_WEP = 0x101,
        DOT11_CIPHER_ALGO_IHV_START = 0x80000000,
        DOT11_CIPHER_ALGO_IHV_END = 0xffffffff
    }

    public enum DOT11_PHY_TYPE : uint
    {
        dot11_phy_type_unknown = 0,
        dot11_phy_type_any = 0,
        dot11_phy_type_fhss = 1,
        dot11_phy_type_dsss = 2,
        dot11_phy_type_irbaseband = 3,
        dot11_phy_type_ofdm = 4,
        dot11_phy_type_hrdsss = 5,
        dot11_phy_type_erp = 6,
        dot11_phy_type_ht = 7,
        dot11_phy_type_vht = 8,
        dot11_phy_type_he = 9,
        dot11_phy_type_eht = 10,
        dot11_phy_type_IHV_start = 0x80000000,
        dot11_phy_type_IHV_end = 0xffffffff
    }

    public enum WLAN_INTERFACE_STATE : uint
    {
        wlan_interface_state_not_ready = 0,
        wlan_interface_state_connected = 1,
        wlan_interface_state_ad_hoc_network_formed = 2,
        wlan_interface_state_disconnecting = 3,
        wlan_interface_state_disconnected = 4,
        wlan_interface_state_associating = 5,
        wlan_interface_state_discovering = 6,
        wlan_interface_state_authenticating = 7
    }

    public enum WLAN_INTF_OPCODE : uint
    {
        wlan_intf_opcode_autoconf_start = 0x00000000,
        wlan_intf_opcode_autoconf_enabled,
        wlan_intf_opcode_background_scan_enabled,
        wlan_intf_opcode_media_streaming_mode,
        wlan_intf_opcode_radio_state,
        wlan_intf_opcode_bss_type,
        wlan_intf_opcode_interface_state,
        wlan_intf_opcode_current_connection,
        wlan_intf_opcode_channel_number,
        wlan_intf_opcode_supported_infrastructure_auth_cipher_pairs,
        wlan_intf_opcode_supported_adhoc_auth_cipher_pairs,
        wlan_intf_opcode_supported_country_or_region_string_list,
        wlan_intf_opcode_current_operation_mode,
        wlan_intf_opcode_supported_safe_mode,
        wlan_intf_opcode_certified_safe_mode,
        wlan_intf_opcode_hosted_network_capable,
        wlan_intf_opcode_management_frame_protection_capable,
        wlan_intf_opcode_autoconf_end = 0x0fffffff
    }

    public enum WLAN_OPCODE_VALUE_TYPE : uint
    {
        wlan_opcode_value_type_query_only = 0,
        wlan_opcode_value_type_set_by_group_policy = 1,
        wlan_opcode_value_type_set_by_user = 2,
        wlan_opcode_value_type_invalid = 3
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WLAN_INTERFACE_INFO
    {
        public Guid InterfaceGuid;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string strInterfaceDescription;
        public WLAN_INTERFACE_STATE isState;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_INTERFACE_INFO_LIST
    {
        public uint dwNumberOfItems;
        public uint dwIndex;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WLAN_AVAILABLE_NETWORK
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string strProfileName;
        public DOT11_SSID dot11Ssid;
        public DOT11_BSS_TYPE dot11BssType;
        public uint uNumberOfBssids;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bNetworkConnectable;
        public uint wlanNotConnectableReason;
        public uint uNumberOfPhyTypes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public DOT11_PHY_TYPE[] dot11PhyTypes;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bMorePhyTypes;
        public uint wlanSignalQuality;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bSecurityEnabled;
        public DOT11_AUTH_ALGORITHM dot11DefaultAuthAlgorithm;
        public DOT11_CIPHER_ALGORITHM dot11DefaultCipherAlgorithm;
        public uint dwFlags;
        public uint dwReserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_AVAILABLE_NETWORK_LIST
    {
        public uint dwNumberOfItems;
        public uint dwIndex;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_BSS_ENTRY
    {
        public DOT11_SSID dot11Ssid;
        public uint uPhyId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] dot11Bssid;
        public DOT11_BSS_TYPE dot11BssType;
        public DOT11_PHY_TYPE dot11BssPhyType;
        public int lRssi;
        public uint uLinkQuality;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bInRegDomain;
        public ushort usBeaconPeriod;
        public ulong ullTimestamp;
        public ulong ullHostTimestamp;
        public ushort usCapabilityInformation;
        public uint ulChCenterFrequency; // In kHz
        public uint uRateSetLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 126)]
        public ushort[] usRateSet;
        public uint ulIeOffset;
        public uint ulIeSize;

        public string GetBssidMac()
        {
            if (dot11Bssid == null || dot11Bssid.Length < 6) return "00:00:00:00:00:00";
            return $"{dot11Bssid[0]:X2}:{dot11Bssid[1]:X2}:{dot11Bssid[2]:X2}:{dot11Bssid[3]:X2}:{dot11Bssid[4]:X2}:{dot11Bssid[5]:X2}";
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_BSS_LIST
    {
        public uint dwTotalSize;
        public uint dwNumberOfItems;
    }

    #endregion
}
