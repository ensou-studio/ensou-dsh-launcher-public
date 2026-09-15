namespace Ensou.Dsh.Contracts;

/// <summary>Fences schema-v2 home recovery to the Startup Stub that can restore legacy enrollment.</summary>
public static class PersonalAtomicHomeCompatibility
{
    public const string MinimumStartupStubVersion = "1.2.0";

    public static void RequireCompatibleStartupStub(PersonalStartupStubCompatibility compatibility)
    {
        ArgumentNullException.ThrowIfNull(compatibility);
        if (PersonalReleaseVersion.Compare(compatibility.MinimumVersion, MinimumStartupStubVersion) < 0
            || PersonalReleaseVersion.Compare(compatibility.MaximumVersion, compatibility.MinimumVersion) < 0)
        {
            throw new InvalidDataException(
                "PERSONAL_ATOMIC_HOME_STUB_REQUIRED: Atomic home recovery requires a signed release with Startup Stub 1.2.0 or later. Install the current Personal Installer before updating this client.");
        }
    }
}
