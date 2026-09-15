namespace Ensou.Dsh.Enterprise.Client;

public sealed record EnterpriseEnrollmentDeviceContext(
    EnterpriseInstallationIdentity Installation,
    EnterpriseDevicePublicIdentity DeviceKey);

public sealed class EnterpriseDeviceEnrollmentPreparation
{
    private readonly EnterpriseInstallationIdentityStore _installationStore;
    private readonly IEnterpriseDeviceProofKeyStore _deviceKeyStore;

    public EnterpriseDeviceEnrollmentPreparation(
        EnterpriseInstallationIdentityStore installationStore,
        IEnterpriseDeviceProofKeyStore deviceKeyStore)
    {
        _installationStore = installationStore
            ?? throw new ArgumentNullException(nameof(installationStore));
        _deviceKeyStore = deviceKeyStore
            ?? throw new ArgumentNullException(nameof(deviceKeyStore));
    }

    public async Task<EnterpriseEnrollmentDeviceContext> PrepareAsync(
        CancellationToken cancellationToken = default)
    {
        var installation = await _installationStore.GetOrCreateAsync(cancellationToken)
            .ConfigureAwait(false);
        var deviceKey = _deviceKeyStore.GetOrCreatePublicIdentity();
        return new EnterpriseEnrollmentDeviceContext(installation, deviceKey);
    }
}
