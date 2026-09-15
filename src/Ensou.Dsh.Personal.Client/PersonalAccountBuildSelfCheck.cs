using System.Reflection;
using System.Text;

namespace Ensou.Dsh.Personal.Client;

/// <summary>
/// Emits a deterministic observation of the account origin compiled into a
/// Launcher binary. This is metadata inspection, not a signature assertion.
/// </summary>
public static class PersonalAccountBuildSelfCheck
{
    public static byte[] Build(IEnumerable<AssemblyMetadataAttribute> metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        var entries = new List<KeyValuePair<string, string?>>();
        foreach (var item in metadata)
        {
            if (item is null) throw new ArgumentException("Compiled metadata is invalid.", nameof(metadata));
            entries.Add(new KeyValuePair<string, string?>(item.Key, item.Value));
        }

        var origin = PersonalAccountEndpoint.RequireCompiledOrigin(entries).AbsoluteUri;
        return Encoding.UTF8.GetBytes(
            "{\"schemaVersion\":1,\"product\":\"ensou-dsh-personal\",\"component\":\"launcher\",\"personalAccountOrigin\":\""
            + origin
            + "\"}");
    }

    public static void Write(Stream output, IEnumerable<AssemblyMetadataAttribute> metadata)
    {
        ArgumentNullException.ThrowIfNull(output);
        var document = Build(metadata);
        output.Write(document, 0, document.Length);
    }
}
