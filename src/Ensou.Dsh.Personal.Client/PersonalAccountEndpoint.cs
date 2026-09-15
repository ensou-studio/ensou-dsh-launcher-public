using System.Collections.Generic;

namespace Ensou.Dsh.Personal.Client;

/// <summary>
/// Reads the Personal account service endpoint only from the signed Launcher
/// assembly metadata. Runtime configuration is intentionally not an input.
/// </summary>
public static class PersonalAccountEndpoint
{
    private const string MetadataKey = "PersonalAccountOrigin";

    public static Uri RequireCompiledOrigin(
        IEnumerable<KeyValuePair<string, string?>> metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        string? raw = null;
        var matches = 0;
        foreach (var entry in metadata)
        {
            if (!string.Equals(entry.Key, MetadataKey, StringComparison.Ordinal))
            {
                continue;
            }

            matches++;
            raw = entry.Value;
        }

        if (matches != 1 || string.IsNullOrEmpty(raw)
            || !Uri.TryCreate(raw, UriKind.Absolute, out var parsed))
        {
            throw InvalidArgument();
        }

        Uri canonical;
        try
        {
            canonical = PersonalAccountFormat.RequireOrigin(parsed);
        }
        catch (ArgumentException)
        {
            throw InvalidArgument();
        }

        // RequireOrigin deliberately canonicalizes DNS casing and URI syntax.
        // A compiled value must already be in that exact representation.
        if (!string.Equals(canonical.AbsoluteUri, raw, StringComparison.Ordinal))
        {
            throw InvalidArgument();
        }

        return canonical;
    }

    private static ArgumentException InvalidArgument() =>
        new("The compiled Personal account origin is invalid.");
}
