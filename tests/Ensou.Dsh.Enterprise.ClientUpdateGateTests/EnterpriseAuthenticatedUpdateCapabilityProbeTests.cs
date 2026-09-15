using System.Text;
using Ensou.Dsh.Enterprise.Client;

namespace Ensou.Dsh.Enterprise.ClientUpdateGateTests;

internal static class EnterpriseAuthenticatedUpdateCapabilityProbeTests
{
    public static Task RunAsync()
    {
        AssertTrue(EnterpriseAuthenticatedUpdateCapabilityProbeContract.IsExactCommand(
            [EnterpriseAuthenticatedUpdateCapabilityProbeContract.Command]));
        AssertFalse(EnterpriseAuthenticatedUpdateCapabilityProbeContract.IsExactCommand(
            [EnterpriseAuthenticatedUpdateCapabilityProbeContract.Command, "unexpected"]));
        AssertFalse(EnterpriseAuthenticatedUpdateCapabilityProbeContract.IsExactCommand([]));
        AssertFalse(EnterpriseAuthenticatedUpdateCapabilityProbeContract.IsExactCommand(
            ["--authenticated-update-capability-self-check"]));

        var canonical = EnterpriseAuthenticatedUpdateCapabilityProbeContract
            .SerializeCanonical(
                EnterpriseAuthenticatedUpdateCapabilityProbeContract.Create());
        var expected =
            "{\"schemaVersion\":1,\"probeType\":\"ensou-dsh-enterprise-authenticated-stable-update-capability-v1\",\"edition\":\"Enterprise\",\"channel\":\"stable\",\"manifestPath\":\"/v2/channels/stable/release-set.v2.json\",\"freshAuthorizationRequired\":true,\"admittedClientStates\":[\"Ready\",\"UpdateRequired\"],\"transportContract\":\"authenticated-dpop-transaction-v1\",\"transactionClientLifetime\":\"single-check\",\"unauthorizedBehavior\":\"clear-token-lock-session\",\"forbiddenReadyBehavior\":\"continue-verified-stable\",\"forbiddenUpdateRequiredBehavior\":\"remain-locked\",\"bootstrapHealthBehavior\":\"restart-through-stable-bootstrapper\",\"sideEffectContract\":\"no-secrets-no-network-no-mutation\"}";
        AssertEqual(expected, Encoding.UTF8.GetString(canonical));
        AssertTrue(canonical.Length
            <= EnterpriseAuthenticatedUpdateCapabilityProbeContract.MaximumCanonicalBytes);
        AssertFalse(canonical.Contains((byte)'\r'));
        AssertFalse(canonical.Contains((byte)'\n'));
        _ = EnterpriseAuthenticatedUpdateCapabilityProbeContract.ParseCanonical(canonical);

        AssertThrows<InvalidDataException>(() =>
            EnterpriseAuthenticatedUpdateCapabilityProbeContract.ParseCanonical(
                Encoding.UTF8.GetBytes(expected + "\n")));
        AssertThrows<InvalidDataException>(() =>
            EnterpriseAuthenticatedUpdateCapabilityProbeContract.ParseCanonical(
                Encoding.UTF8.GetBytes(expected.Insert(1, "\"unknown\":true,"))));
        AssertThrows<InvalidDataException>(() =>
            EnterpriseAuthenticatedUpdateCapabilityProbeContract.ParseCanonical(
                Encoding.UTF8.GetBytes(expected.Insert(1, "\"schemaVersion\":1,"))));
        AssertThrows<InvalidDataException>(() =>
            EnterpriseAuthenticatedUpdateCapabilityProbeContract.ParseCanonical(
                [0xEF, 0xBB, 0xBF, .. canonical]));

        var text = Encoding.UTF8.GetString(canonical);
        foreach (var forbidden in new[]
                 {
                     "accessToken",
                     "bindingId",
                     "authorizationSecret",
                     "refreshToken",
                     "https://",
                 })
        {
            AssertFalse(text.Contains(forbidden, StringComparison.OrdinalIgnoreCase));
        }

        return Task.CompletedTask;
    }

    private static void AssertThrows<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }

    private static void AssertTrue(bool condition)
    {
        if (!condition)
        {
            throw new InvalidOperationException("Expected true.");
        }
    }

    private static void AssertFalse(bool condition) => AssertTrue(!condition);

    private static void AssertEqual<T>(T expected, T actual)
        where T : notnull
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException(
                $"Expected '{expected}', actual '{actual}'.");
        }
    }
}
