using System.Windows;
using System.Windows.Controls;
using Ensou.Dsh.Personal.Client;

namespace Ensou.Dsh.Launcher;

public partial class PersonalLoginWindow : Window
{
    private readonly PersonalAuthorizationCoordinator _accounts;
    private readonly Action _ensureEnrollmentKey;
    private readonly CancellationTokenSource _lifetime = new();
    private PersonalEmailChallenge? _challenge;
    private bool _busy;
    private bool _closed;

    internal PersonalLoginWindow(PersonalAuthorizationCoordinator accounts, Action ensureEnrollmentKey)
    {
        _accounts = accounts;
        _ensureEnrollmentKey = ensureEnrollmentKey;
        InitializeComponent();
        Icon = LauncherBrandAssets.LoadWindowIcon();
        Loaded += (_, _) => EmailInput.Focus();
    }

    protected override void OnClosed(EventArgs e)
    {
        _closed = true;
        _lifetime.Cancel();
        CodeInput.Clear();
        _challenge = null;
        base.OnClosed(e);
    }

    private void EmailInput_TextChanged(object sender, TextChangedEventArgs e)
    {
        _challenge = null;
        CodeInput?.Clear();
    }

    private async void RequestCodeButton_Click(object sender, RoutedEventArgs e)
        => await RunAsync(async () =>
        {
            var email = PersonalAccountFormat.CanonicalizeEmail(EmailInput.Text);
            _challenge = null;
            CodeInput.Clear();
            // Key enrollment is an explicit user action, never a startup side effect.
            _ensureEnrollmentKey();
            _challenge = await _accounts.RequestEmailAsync(email, _lifetime.Token);
            if (_closed) return;
            MessageText.Text = "如该邮箱已获批准，验证码将发送到收件箱。请同时检查垃圾邮件。";
            CodeInput.Focus();
        });

    private async void SignInButton_Click(object sender, RoutedEventArgs e)
        => await RunAsync(async () =>
        {
            if (_challenge is null)
            {
                MessageText.Text = "请先为当前邮箱发送验证码。";
                return;
            }
            var code = CodeInput.Password;
            if (code.Length != 6 || code.Any(character => character is < '0' or > '9'))
            {
                MessageText.Text = "请输入邮件中的六位数字验证码。";
                return;
            }
            var challenge = _challenge;
            _challenge = null;
            CodeInput.Clear();
            await _accounts.SignInAsync(challenge, code, _lifetime.Token);
            if (!_closed) DialogResult = true;
        });

    private async Task RunAsync(Func<Task> action)
    {
        if (_busy || _closed) return;
        _busy = true;
        RequestCodeButton.IsEnabled = false;
        SignInButton.IsEnabled = false;
        EmailInput.IsEnabled = false;
        try
        {
            await action();
        }
        catch (Exception exception)
        {
            if (!_closed) MessageText.Text = PersonalAccountMessages.For(exception);
        }
        finally
        {
            _busy = false;
            if (!_closed)
            {
                RequestCodeButton.IsEnabled = true;
                SignInButton.IsEnabled = true;
                EmailInput.IsEnabled = true;
            }
        }
    }
}

internal static class PersonalAccountMessages
{
    public static string For(Exception exception) => exception switch
    {
        PersonalAccountException { Failure: PersonalAccountFailure.Denied } =>
            "登录或授权未通过。请重新获取验证码；尚未登记或已被停用，请联系 ensou。",
        PersonalAccountException { Failure: PersonalAccountFailure.RateLimited } =>
            "请求过于频繁，请稍后再试。",
        PersonalAccountException { Failure: PersonalAccountFailure.Busy } =>
            "正在处理账号请求，请稍后再试。",
        PersonalAccountException { Failure: PersonalAccountFailure.ReauthenticationRequired } =>
            "登录状态需要重新确认，请重新获取验证码登录。",
        ArgumentException => "邮箱格式不正确，请检查后重试。",
        _ => "账号服务或本机登录凭证暂不可用，请检查网络后重试；仍有问题请联系 ensou。"
    };
}
