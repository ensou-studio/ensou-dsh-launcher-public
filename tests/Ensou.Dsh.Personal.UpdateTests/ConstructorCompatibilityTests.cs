using System.Diagnostics;
using System.Net.Http;
using System.Reflection;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.Host;
using Ensou.Dsh.UpdateEngine;

namespace Ensou.Dsh.Personal.UpdateTests;

internal static class ConstructorCompatibilityTests
{
    internal static IReadOnlyList<(string Name, Func<Task> Run)> Cases { get; } =
    [
        ("Host retains its original public constructor ABI", HostConstructorAsync),
        ("health gate retains its original public constructor ABI", HealthGateConstructorAsync),
    ];

    private static Task HostConstructorAsync()
    {
        var legacy = RequirePublicConstructor(
            typeof(DshHostService),
            typeof(DshRuntimeOptions),
            typeof(Action),
            typeof(HttpClient),
            typeof(TimeSpan?),
            typeof(TimeSpan?),
            typeof(Action<Process>),
            typeof(Func<IDshHomeWriterSession>));
        Require(!legacy.GetParameters()[0].IsOptional);
        Require(!legacy.GetParameters()[1].IsOptional);
        Require(legacy.GetParameters().Skip(2).All(parameter => parameter.IsOptional));

        var diagnostic = RequirePublicConstructor(
            typeof(DshHostService),
            typeof(DshRuntimeOptions),
            typeof(Action),
            typeof(HttpClient),
            typeof(TimeSpan?),
            typeof(TimeSpan?),
            typeof(Action<Process>),
            typeof(Func<IDshHomeWriterSession>),
            typeof(Action<string, Exception?>));
        Require(diagnostic.GetParameters().All(parameter => !parameter.IsOptional));
        return Task.CompletedTask;
    }

    private static Task HealthGateConstructorAsync()
    {
        var legacy = RequirePublicConstructor(
            typeof(PersonalBootstrapHealthGate),
            typeof(PersonalInstallationLayout),
            typeof(TimeSpan?));
        Require(!legacy.GetParameters()[0].IsOptional);
        Require(legacy.GetParameters()[1].IsOptional);

        var diagnostic = RequirePublicConstructor(
            typeof(PersonalBootstrapHealthGate),
            typeof(PersonalInstallationLayout),
            typeof(TimeSpan?),
            typeof(Action<string, Exception?>));
        Require(diagnostic.GetParameters().All(parameter => !parameter.IsOptional));
        return Task.CompletedTask;
    }

    private static ConstructorInfo RequirePublicConstructor(
        Type declaringType,
        params Type[] parameterTypes) =>
        declaringType.GetConstructor(
            BindingFlags.Public | BindingFlags.Instance,
            binder: null,
            types: parameterTypes,
            modifiers: null)
        ?? throw new InvalidOperationException(
            $"Missing public constructor {declaringType.FullName}({string.Join(", ", parameterTypes.Select(type => type.FullName))}).");

    private static void Require(bool condition)
    {
        if (!condition)
        {
            throw new InvalidOperationException(
                "Constructor compatibility assertion failed.");
        }
    }
}
