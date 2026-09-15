namespace Ensou.Dsh.Host;

internal sealed class LauncherRestartOperationGate
{
    private int _active;

    internal bool TryEnter(out IDisposable? operation)
    {
        if (Interlocked.CompareExchange(ref _active, 1, 0) != 0)
        {
            operation = null;
            return false;
        }

        operation = new Operation(this);
        return true;
    }

    private sealed class Operation : IDisposable
    {
        private LauncherRestartOperationGate? _owner;

        internal Operation(LauncherRestartOperationGate owner)
        {
            _owner = owner;
        }

        public void Dispose()
        {
            var owner = Interlocked.Exchange(ref _owner, null);
            if (owner is not null)
            {
                Volatile.Write(ref owner._active, 0);
            }
        }
    }
}
