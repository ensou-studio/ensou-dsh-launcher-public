using System.Globalization;
using System.Text.Json.Nodes;
using Ensou.Dsh.Enterprise.Client;

namespace Ensou.Dsh.CoreTests;

internal static partial class Program
{
    private static async Task EnterpriseQrValidityDiagnosticsAsync()
    {
        // The observed failure's 216-second remaining lifetime is synthetic here.
        // No HTTP connection, native device key, clock change, or file write occurs.
        var now = new DateTimeOffset(2026, 9, 7, 23, 33, 26, TimeSpan.Zero);
        foreach (var seconds in new[] { -1, 0, 1, 120, 121, 216 })
        {
            var failure = await RejectOrAcceptAsync(seconds);
            if (seconds is 1 or 120)
            {
                AssertTrue(failure is null);
                continue;
            }
            AssertTrue(failure is not null);
            AssertTrue(failure!.InnerException is EnterpriseQrSessionValidityException);
            var diagnostic = (EnterpriseQrSessionValidityException)failure.InnerException!;
            AssertEqual(seconds <= 0
                ? EnterpriseQrSessionValidityReason.Expired
                : EnterpriseQrSessionValidityReason.ExceedsLocalMaximum, diagnostic.Reason);
            AssertTrue(diagnostic.InnerException is null);
            AssertEqual(0, diagnostic.Data.Count);
            AssertEqual("无法安全确认企业登录有效期", diagnostic.UserTitle);
            AssertEqual(seconds <= 0
                ? "按本机时间，本次登录已过期，请重新扫码。若反复出现，可能是电脑或服务器时间不同步，也可能是登录响应异常；请联系管理员。"
                : "服务返回的登录有效期超出本机允许范围，已停止登录。可能是电脑或服务器时间不同步，也可能是登录响应异常；请联系管理员检查，确认后重新扫码。",
                diagnostic.UserMessage);
            foreach (var secret in new[]
            {
                QrPollSecretVector, BindingSessionId, QrConfirmationCode,
                QrDeviceDisplayName, "login.example.test", "2026-09-07", "216",
            })
            {
                AssertFalse(failure.Message.Contains(secret, StringComparison.Ordinal));
                AssertFalse(diagnostic.Message.Contains(secret, StringComparison.Ordinal));
                AssertFalse(diagnostic.UserMessage.Contains(secret, StringComparison.Ordinal));
            }
        }

        // Independent trust failures must not be presented as local clock evidence,
        // even when the same response also has an excessive lifetime.
        foreach (var mutation in new Action<JsonObject>[]
        {
            value => value["authorization_url"] = "https://other.example.test/activate",
            value => value["poll_after_seconds"] = 1,
            value => value["poll_after_seconds"] = 16,
            value => value["device_display_name"] = "Different device",
        })
        {
            var failure = await RejectOrAcceptAsync(216, mutation);
            AssertTrue(failure is not null);
            AssertFalse(failure!.InnerException is EnterpriseQrSessionValidityException);
        }

        async Task<InvalidDataException?> RejectOrAcceptAsync(
            int remainingSeconds, Action<JsonObject>? mutate = null)
        {
            using var keys = new EphemeralDeviceProofKeyStore();
            var body = new JsonObject
            {
                ["session_id"] = BindingSessionId,
                ["poll_secret"] = QrPollSecretVector,
                ["authorization_url"] = "https://login.example.test/activate",
                ["device_display_name"] = QrDeviceDisplayName,
                ["confirmation_code"] = QrConfirmationCode,
                ["expires_at"] = now.AddSeconds(remainingSeconds)
                    .ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
                ["poll_after_seconds"] = 2,
            };
            mutate?.Invoke(body);
            var calls = 0;
            using var http = new HttpClient(new DelegateHandler(_ =>
            {
                calls++;
                return CreatedJsonResponse(body.ToJsonString());
            }));
            var client = CreateQrHttpClient(http, keys, now);
            try
            {
                await client.CreateSessionAsync(
                    CreateQrRequest(keys.GetOrCreatePublicIdentity()), BindingIdempotencyKey);
                return null;
            }
            catch (InvalidDataException exception)
            {
                return exception;
            }
            finally
            {
                AssertEqual(1, calls);
            }
        }
    }
}
