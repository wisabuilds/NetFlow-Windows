namespace NetFlow.Core.Services;

/// <summary>
/// Service namespace bridge forwarding to NetFlow.Core.Telemetry.GeoIpService.
/// </summary>
public class GeoIpService : NetFlow.Core.Telemetry.GeoIpService
{
    public GeoIpService(NetFlow.Core.Storage.GeoIpDatabase? database = null) : base(database)
    {
    }
}
