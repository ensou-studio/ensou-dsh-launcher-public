using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.Personal.UpdateTests;

internal static class AtomicHomeCompatibilityTests
{
    internal static IReadOnlyList<(string Name, Func<Task> Run)> Cases { get; } =
    [
        ("atomic home refuses a signed range admitting a legacy Stub", () =>
        {
            foreach (var minimum in new[] { "1.0.0", "1.1.0", "1.2.0-beta.1" })
            {
                var rejected = false;
                try { Require(minimum, "2.0.0"); }
                catch (InvalidDataException) { rejected = true; }
                if (!rejected) throw new InvalidOperationException("Legacy Stub range was admitted to atomic home.");
            }
            return Task.CompletedTask;
        }),
        ("atomic home admits a compatible Stub floor", () =>
        {
            Require("1.2.0", "1.2.0");
            Require("1.2.1", "2.0.0");
            return Task.CompletedTask;
        }),
        ("atomic home rejects an inverted Stub range", () =>
        {
            try { Require("2.0.0", "1.2.0"); }
            catch (InvalidDataException) { return Task.CompletedTask; }
            throw new InvalidOperationException("Inverted Stub range was admitted.");
        }),
    ];

    private static void Require(string minimum, string maximum) =>
        PersonalAtomicHomeCompatibility.RequireCompatibleStartupStub(new PersonalStartupStubCompatibility
        { MinimumVersion = minimum, MaximumVersion = maximum });
}
