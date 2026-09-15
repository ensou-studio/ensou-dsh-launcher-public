using Ensou.Dsh.UpdateEngine;

namespace Ensou.Dsh.Personal.UpdateTests;

internal static class PersonalDevelopmentE2EHealthPortTests
{
    internal static Task RunAsync()
    {
        var variable = PersonalDevelopmentE2EHealthPort.EnvironmentVariable;
        var original = Environment.GetEnvironmentVariable(variable);
        try
        {
            foreach (var invalid in new[] { "bad", "3080", "49151", "65536", "049152", "+49152", "49152 ", " 49152", "49,152" })
            {
                Environment.SetEnvironmentVariable(variable, invalid);
                Require(PersonalDevelopmentE2EHealthPort.Resolve(3080, false) == 3080,
                    "Production default port must ignore test configuration.");
                Require(PersonalDevelopmentE2EHealthPort.Resolve(3081, false) == 3081,
                    "Production configured port must ignore test configuration.");
                try
                {
                    _ = PersonalDevelopmentE2EHealthPort.Resolve(3080, true);
                    throw new InvalidOperationException("Invalid development port was admitted.");
                }
                catch (InvalidDataException)
                {
                    // Invalid values must fail before any health process or socket starts.
                }
            }
            foreach (var port in new[] { 49152, 54321, 65535 })
            {
                Environment.SetEnvironmentVariable(variable, port.ToString(System.Globalization.CultureInfo.InvariantCulture));
                Require(PersonalDevelopmentE2EHealthPort.Resolve(3080, true) == port,
                    "Development health must use the exact private port.");
                Require(PersonalDevelopmentE2EHealthPort.Resolve(3080, false) == 3080,
                    "A valid development override must still be ignored in production.");
            }
            Environment.SetEnvironmentVariable(variable, null);
            Require(PersonalDevelopmentE2EHealthPort.Resolve(3080, true) == 3080,
                "An absent override must preserve the legacy development default.");
        }
        finally
        {
            Environment.SetEnvironmentVariable(variable, original);
        }
        return Task.CompletedTask;
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) { throw new InvalidOperationException(message); }
    }
}
