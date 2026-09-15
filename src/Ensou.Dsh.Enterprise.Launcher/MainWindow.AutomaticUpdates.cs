using System.Diagnostics;
using System.Net.NetworkInformation;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.Enterprise.Client;
using Ensou.Dsh.Enterprise.Contracts;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.Launcher;

public partial class MainWindow
{
    private readonly int _automaticHarnessPort;
    private AutomaticUpdateScheduler? _automaticUpdateScheduler;
    private int _automaticUpdatesClosed;

    private void InitializeAutomaticUpdates()
    {
        if (Volatile.Read(ref _automaticUpdatesClosed) != 0
            || _automaticUpdateScheduler is not null
            || _authorizationLifecycle is null)
            return;

        var scheduler = new AutomaticUpdateScheduler(RunAutomaticUpdateAsync);
        _automaticUpdateScheduler = scheduler;
        var subscribed = false;
        try
        {
            NetworkChange.NetworkAvailabilityChanged += OnAutomaticNetworkAvailabilityChanged;
            subscribed = true;
            scheduler.Start();
        }
        catch
        {
            if (subscribed)
                NetworkChange.NetworkAvailabilityChanged -= OnAutomaticNetworkAvailabilityChanged;
            scheduler.Dispose();
            _automaticUpdateScheduler = null;
            throw;
        }
    }

    private void OnAutomaticNetworkAvailabilityChanged(object? sender, NetworkAvailabilityEventArgs args)
    {
        if (args.IsAvailable && Volatile.Read(ref _automaticUpdatesClosed) == 0)
            _automaticUpdateScheduler?.NotifyReconnect();
    }

    private void ShutdownAutomaticUpdates()
    {
        Interlocked.Exchange(ref _automaticUpdatesClosed, 1);
        NetworkChange.NetworkAvailabilityChanged -= OnAutomaticNetworkAvailabilityChanged;
        _automaticUpdateScheduler?.Dispose();
        _automaticUpdateScheduler = null;
    }

    private async Task<AutomaticUpdatePipelineResult> RunAutomaticUpdateAsync(
        AutomaticUpdateTrigger trigger,
        CancellationToken cancellationToken)
    {
        try
        {
            if (Volatile.Read(ref _automaticUpdatesClosed) != 0)
                return AutomaticUpdatePipelineResult.Success;

            // The entire asynchronous operation owns the UI admission flag on the
            // dispatcher. Awaiting network I/O does not block the dispatcher.
            return await Dispatcher.InvokeAsync(
                () => RunAutomaticUpdateOnDispatcherAsync(trigger, cancellationToken),
                System.Windows.Threading.DispatcherPriority.Background,
                cancellationToken).Task.Unwrap().ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return AutomaticUpdatePipelineResult.Success;
        }
        catch (Exception exception)
        {
            // Dispatcher shutdown and unexpected failures must not escape a timer
            // callback or open a Windows application-error dialog.
            Debug.WriteLine($"Enterprise automatic update callback: {exception.GetType().Name}");
            return AutomaticUpdatePipelineResult.Failure;
        }
    }

    private async Task<AutomaticUpdatePipelineResult> RunAutomaticUpdateOnDispatcherAsync(
        AutomaticUpdateTrigger trigger,
        CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _automaticUpdatesClosed) != 0)
            return AutomaticUpdatePipelineResult.Success;
        cancellationToken.ThrowIfCancellationRequested();
        if (_operationRunning)
            return AutomaticUpdatePipelineResult.DeferredBusy;
        if (_authorizationLifecycle is null)
            return AutomaticUpdatePipelineResult.Success;

        _operationRunning = true;
        ApplyDecision(_session.CurrentDecision);
        try
        {
            var device = await _devicePreparation.PrepareAsync(cancellationToken);
            ThrowIfAutomaticUpdatesStopped(cancellationToken);
            var authorization = await _authorizationLifecycle.RefreshInPlaceAsync(device, cancellationToken);
            ThrowIfAutomaticUpdatesStopped(cancellationToken);
            ApplyDecision(_session.CurrentDecision);
            if (IsVerifiedAutomaticAuthenticationRecovery(
                    authorization.HasCommittedBinding,
                    authorization.RefreshCompleted,
                    authorization.AccessDecision == _session.CurrentDecision,
                    authorization.AccessDecision.ClientState))
            {
                // Only the existing authenticated refresh authority may recover a
                // session locked by a previous update-feed authentication loss.
                _updateAuthenticationRestartRequired = false;
            }
            if (!authorization.HasCommittedBinding)
            {
                StatusTitleText.Text = "需要企业微信登录";
                StatusDetailText.Text = "此设备尚未绑定；后台检查不会绕过首次登录。";
                return AutomaticUpdatePipelineResult.Success;
            }
            if (_authenticatedReleaseUpdateCoordinator is null)
            {
                UpdateStatusText.Text = "企业更新源尚未配置；在线授权已刷新";
                return AutomaticUpdatePipelineResult.Success;
            }
            if (!authorization.RefreshCompleted
                || authorization.AccessDecision.ClientState is not
                    (EnterpriseClientState.Ready or EnterpriseClientState.UpdateRequired))
                return AutomaticUpdatePipelineResult.Success;

            UpdateStatusText.Text = "正在后台验证企业签名更新";
            var automaticUpdate = new EnterpriseAutomaticReleaseUpdateCoordinator(
                _authenticatedReleaseUpdateCoordinator,
                async (operationId, token) =>
                {
                    var drain = await (_tryStopRuntimeForManagedUpdate
                        ?? throw new InvalidOperationException(
                            "Enterprise automatic update cannot prove managed Runtime drain capability."))
                        (operationId, token).ConfigureAwait(false);
                    return drain == ManagedRuntimeUpdateDrainDisposition.StoppedExactRuntime
                        ? EnterpriseManagedRuntimeDrainDisposition.StoppedExactRuntime
                        : EnterpriseManagedRuntimeDrainDisposition.NoRuntimeToStop;
                },
                () => Dispatcher.Invoke(() =>
                    {
                        ThrowIfAutomaticUpdatesStopped(cancellationToken);
                        // A missing owned Host is not authority to stage beside an
                        // external listener. The independent loopback guard remains
                        // the proof for both Launcher-only and Runtime changes.
                        EnterpriseHarnessWriterGuard.RequireQuiescentLoopbackPort(
                            _automaticHarnessPort);
                        UpdateStatusText.Text = "DSH 已安全停止；正在独占安装企业签名更新";
                    },
                    System.Windows.Threading.DispatcherPriority.Background),
                async _ =>
                {
                    if (Volatile.Read(ref _automaticUpdatesClosed) == 0)
                    {
                        await Dispatcher.InvokeAsync(
                                RestoreRuntimeAfterUncommittedAutomaticUpdateAsync,
                                System.Windows.Threading.DispatcherPriority.Background)
                            .Task.Unwrap()
                            .ConfigureAwait(false);
                    }
                });
            var result = await automaticUpdate.RunAsync(
                authorization.RefreshCompleted,
                authorization.AccessDecision,
                cancellationToken);
            return CompleteAutomaticUpdate(result);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested
            || Volatile.Read(ref _automaticUpdatesClosed) != 0)
        {
            return AutomaticUpdatePipelineResult.Success;
        }
        catch (Exception exception)
        {
            if (Volatile.Read(ref _automaticUpdatesClosed) == 0
                && exception is not AutomaticRuntimeRecoveryException)
            {
                ApplyDecision(_session.CurrentDecision);
                UpdateStatusText.Text = "后台授权或更新未完成；将自动重试，原授权到期限制仍然生效";
                LastActivityText.Text = $"{DateTime.Now:HH:mm:ss} AUTO_UPDATE_{exception.GetType().Name}";
            }
            return AutomaticUpdatePipelineResult.Failure;
        }
        finally
        {
            _operationRunning = false;
            if (Volatile.Read(ref _automaticUpdatesClosed) == 0)
                ApplyDecision(_session.CurrentDecision);
        }
    }

    private AutomaticUpdatePipelineResult CompleteAutomaticUpdate(
        EnterpriseAuthenticatedReleaseUpdateResult result)
    {
        if (Volatile.Read(ref _automaticUpdatesClosed) != 0)
            return AutomaticUpdatePipelineResult.Success;
        ApplyAuthenticatedReleaseUpdateResult(
            result,
            "企业授权与后台更新检查完成",
            "已使用本次在线授权检查本设备的受管更新通道。");
        return ToAutomaticUpdatePipelineResult(result.Disposition);
    }

    internal static bool IsVerifiedAutomaticAuthenticationRecovery(
        bool hasCommittedBinding,
        bool refreshCompleted,
        bool decisionMatchesCurrentSession,
        EnterpriseClientState clientState) =>
        hasCommittedBinding
        && refreshCompleted
        && decisionMatchesCurrentSession
        && clientState is EnterpriseClientState.Ready or EnterpriseClientState.UpdateRequired;

    internal static AutomaticUpdatePipelineResult ToAutomaticUpdatePipelineResult(
        EnterpriseAuthenticatedReleaseUpdateDisposition disposition) =>
        disposition is EnterpriseAuthenticatedReleaseUpdateDisposition.Completed
                or EnterpriseAuthenticatedReleaseUpdateDisposition.Restarting
                or EnterpriseAuthenticatedReleaseUpdateDisposition.NotEligible
            ? AutomaticUpdatePipelineResult.Success
            : AutomaticUpdatePipelineResult.Failure;

    private async Task RestoreRuntimeAfterUncommittedAutomaticUpdateAsync()
    {
        try
        {
            // Never bypass EnterpriseHarnessSession: it reevaluates the current
            // authorization immediately before and after Host start admission.
            _ = await _session.EnsureStartedAsync(CancellationToken.None);
        }
        catch (Exception exception)
        {
            ApplyDecision(_session.CurrentDecision);
            UpdateStatusText.Text = "后台更新未提交且 DSH 无法按当前授权安全恢复；保持锁定";
            LastActivityText.Text =
                $"{DateTime.Now:HH:mm:ss} AUTO_UPDATE_RUNTIME_RECOVERY_{exception.GetType().Name}";
            throw new AutomaticRuntimeRecoveryException(
                "Managed Runtime was stopped for an automatic update but could not be safely restored through the current Enterprise session authorization.",
                exception);
        }
    }

    private sealed class AutomaticRuntimeRecoveryException(
        string message,
        Exception innerException) : Exception(message, innerException);

    private void ShowAutomaticUpdateWaiting()
    {
        UpdateStatusText.Text = "后台更新等待本机 DSH 安全停止；不会自动终止当前工作";
    }

    private void ThrowIfAutomaticUpdatesStopped(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Volatile.Read(ref _automaticUpdatesClosed) != 0)
            throw new OperationCanceledException("Enterprise Launcher is closing.");
    }
}
