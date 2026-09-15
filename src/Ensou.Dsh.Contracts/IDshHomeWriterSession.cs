namespace Ensou.Dsh.Contracts;

/// <summary>Retains cooperative home admission through the exact owned runtime job.</summary>
public interface IDshHomeWriterSession : IDisposable
{
    string JobName { get; }
    void RecordAssignedProcess(int processId, long creationFileTimeUtc);
    /// <summary>Requires the exact job to be empty and closed to further assignments.</summary>
    void RecordJobEmpty();
    /// <summary>Requires proof that CreateProcess was never called for this generation.</summary>
    void RecordNeverStarted();
}

/// <summary>Requires every child of this generation to be created atomically in its exact Job.</summary>
public interface IDshAtomicHomeWriterSession : IDshHomeWriterSession
{
}
