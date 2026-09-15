using System.Net;
using System.Net.NetworkInformation;

namespace Ensou.Dsh.Enterprise.Installation;

public static class EnterpriseHarnessWriterGuard
{
    public static void RequireQuiescentLoopbackPort(int port)
    {
        if (port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port));
        }
        var listeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
        if (listeners.Any(endpoint => endpoint.Port == port
            && (IPAddress.IsLoopback(endpoint.Address)
                || endpoint.Address.Equals(IPAddress.Any)
                || endpoint.Address.Equals(IPAddress.IPv6Any))))
        {
            throw new InvalidOperationException(
                $"Enterprise Harness port {port} is still in use. Stop the existing or foreign DSH process before updating.");
        }
    }
}
