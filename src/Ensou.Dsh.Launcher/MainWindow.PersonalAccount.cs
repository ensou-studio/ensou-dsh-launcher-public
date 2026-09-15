using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Threading;
using Ensou.Dsh.Personal.Client;
using Ensou.Dsh.Personal.Windows;
using Ensou.Dsh.UpdateEngine;

namespace Ensou.Dsh.Launcher;

public partial class MainWindow
{
    private readonly CancellationTokenSource _accountLifetime = new();
    private PersonalAuthorizationCoordinator? _accounts;
    private PersonalAccountClient? _accountClient;
    private WindowsPersonalDeviceProofKey? _accountKey;
    private DispatcherTimer? _accountTimer;
    private bool _accountTickRunning;
    private volatile bool _accountRuntimeActive;

    private PersonalAuthorizationCoordinator RequireAccounts()
    {
        if (_accounts is not null) return _accounts;
        // Signed Launcher bytes carry this endpoint. Never read it from user settings or the environment.
        Uri origin;
        try
        {
            origin = PersonalAccountEndpoint.RequireCompiledOrigin(
                typeof(MainWindow).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
                    .Select(item => new KeyValuePair<string, string?>(item.Key, item.Value)));
        }
        catch (ArgumentException)
        {
            throw new InvalidDataException("This Launcher has no valid authenticated personal account endpoint.");
        }
        var layout = PersonalInstallationLayout.CreateDefault();
        // Login must not repair or replace a missing installation identity.
        var identity = new PersonalInstallationIdentityStore(layout).ReadRequired();
        _accountKey = new WindowsPersonalDeviceProofKey(origin, identity.InstallationId);
        var store = new WindowsPersonalAccountSessionStore(layout.StateRoot, origin, identity.InstallationId);
        _accountClient = new PersonalAccountClient(origin, identity.InstallationId, _accountKey);
        _accounts = new PersonalAuthorizationCoordinator(_accountClient, store, StopAccountOwnedRuntimeAsync);
        return _accounts;
    }

    private void InitializeAccountMonitor()
    {
        _accountTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
        _accountTimer.Tick += async (_, _) => await RunUiEventAsync(MonitorAccountAsync);
        _accountTimer.Start();
    }

    private async Task RequireAccountAccessAsync()
    {
        try
        {
            await RequireAccounts().EnsureAuthorizedAsync(_accountLifetime.Token);
            AccountStatusText.Text = "个人账号已验证";
        }
        catch (PersonalAccountException exception) when (exception.Failure == PersonalAccountFailure.Busy)
        {
            // Refuse this new action, without stopping a runtime whose monitor is already validating it.
            throw new InvalidOperationException(PersonalAccountMessages.For(exception));
        }
        catch (Exception exception)
        {
            AccountStatusText.Text = "需要登录或重新验证";
            try { await StopAccountOwnedRuntimeAsync(CancellationToken.None); }
            catch
            {
                _accountRuntimeActive = true;
                throw new InvalidOperationException("授权未通过，且后台服务停止未完成。请退出 Launcher 后重试。");
            }
            throw new InvalidOperationException(PersonalAccountMessages.For(exception));
        }
    }

    private async Task StopAccountOwnedRuntimeAsync(CancellationToken cancellationToken)
    {
        // A failed stop stays pending and is retried by the account monitor.
        _accountRuntimeActive = true;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        await _hostService.StopOwnedProcessAsync(deadline.Token);
        _accountRuntimeActive = false;
    }

    private async Task MonitorAccountAsync()
    {
        if (_accountTickRunning || !_accountRuntimeActive || _accountLifetime.IsCancellationRequested) return;
        _accountTickRunning = true;
        try
        {
            await RequireAccounts().CheckRuntimeAuthorizationAsync(_accountLifetime.Token);
        }
        catch (PersonalAccountException exception) when (exception.Failure == PersonalAccountFailure.Busy)
        {
            // The coordinator also enforces the last online check's expiry on contention.
        }
        catch (Exception exception)
        {
            AccountStatusText.Text = "授权未通过";
            try
            {
                await StopAccountOwnedRuntimeAsync(CancellationToken.None);
                SetHealth(false, "已停止");
                SetStatus("需要重新登录", PersonalAccountMessages.For(exception), 0);
            }
            catch
            {
                SetHealth(false, "停止待重试");
                SetStatus("授权未通过，正在停止后台服务", "停止尚未完成，将继续重试；也可退出 Launcher。", 0);
            }
        }
        finally { _accountTickRunning = false; }
    }

    private async void AccountButton_Click(object sender, RoutedEventArgs e)
        => await RunUiEventAsync(async () =>
        {
            if (_operationRunning) return;
            _operationRunning = true;
            AccountButton.IsEnabled = false;
            try
            {
                var accounts = RequireAccounts();
                var dialog = new PersonalLoginWindow(accounts, () => _accountKey!.EnsureCreated()) { Owner = this };
                if (dialog.ShowDialog() == true)
                {
                    await RequireAccountAccessAsync();
                    AccountStatusText.Text = "个人账号已验证";
                    SetStatus("登录成功", "现在可以启动本机 DSH。模型 token 仍由你单独配置。", 100);
                }
            }
            catch (Exception exception)
            {
                AccountStatusText.Text = "登录未完成";
                SetStatus("暂时无法登录", PersonalAccountMessages.For(exception), 0);
            }
            finally
            {
                AccountButton.IsEnabled = true;
                _operationRunning = false;
            }
        });

    private async void SignOutButton_Click(object sender, RoutedEventArgs e)
        => await RunUiEventAsync(async () =>
        {
            if (_operationRunning) return;
            await RunOperationAsync(async () =>
            {
                await RequireAccounts().SignOutAsync(_accountLifetime.Token);
                AccountStatusText.Text = "已退出登录";
                SetHealth(false, "已停止");
                SetStatus("已退出个人账号", "本机聊天和工作区已保留。模型 token 不受此操作影响。", 0);
            });
        });

    internal void ShutdownAccountMonitor()
    {
        _accountTimer?.Stop();
        _accountLifetime.Cancel();
        _accountClient?.Dispose();
    }
}
