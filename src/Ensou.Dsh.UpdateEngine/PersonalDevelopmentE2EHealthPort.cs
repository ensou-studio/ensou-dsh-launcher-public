using System.Globalization;

namespace Ensou.Dsh.UpdateEngine;

/// <summary>
/// Allows an explicitly admitted development layout to avoid the user's live
/// Harness port. Production callers ignore this test-only environment input.
/// </summary>
public static class PersonalDevelopmentE2EHealthPort
{
    public const string EnvironmentVariable = "ENSOU_DSH_DEV_E2E_HEALTH_PORT";

    public static int Resolve(int normalPort, bool developmentLayoutAdmitted)
    {
        if (!developmentLayoutAdmitted)
        {
            return normalPort;
        }

        var configured = Environment.GetEnvironmentVariable(EnvironmentVariable);
        if (configured is null)
        {
            return normalPort;
        }
        if (configured.Length != 5
            || !int.TryParse(configured, NumberStyles.None, CultureInfo.InvariantCulture, out var port)
            || port is < 49152 or > 65535)
        {
            throw new InvalidDataException(
                "Personal development E2E health port must be a canonical high TCP port.");
        }
        return port;
    }
}
