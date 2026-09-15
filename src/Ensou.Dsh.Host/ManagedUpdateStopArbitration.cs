namespace Ensou.Dsh.Host;

/// <summary>Orders security/manual process stops ahead of managed-update waits.</summary>
internal sealed class ManagedUpdateStopArbitration
{
    private readonly object _gate = new();
    private ActiveWait? _active;
    private int _priorityStops;

    internal ManagedWaitLease BeginManagedWait()
    {
        lock (_gate)
        {
            if (_priorityStops != 0)
            {
                throw new OperationCanceledException(
                    "A priority process stop superseded the managed-update wait.");
            }
            if (_active is not null)
            {
                throw new InvalidOperationException("A managed-update wait is already active.");
            }
            var active = new ActiveWait();
            _active = active;
            return new ManagedWaitLease(this, active);
        }
    }

    internal PriorityStopLease BeginPriorityStop()
    {
        ActiveWait? active;
        lock (_gate)
        {
            _priorityStops++;
            active = _active;
            if (active is not null) active.Cancelers++;
        }
        if (active is not null)
        {
            try { active.Cancellation.Cancel(); }
            finally { CompleteCancellation(active); }
        }
        return new PriorityStopLease(this);
    }

    private void CompleteManagedWait(ActiveWait active)
    {
        CancellationTokenSource? dispose = null;
        lock (_gate)
        {
            if (!ReferenceEquals(_active, active)) return;
            _active = null;
            active.Retired = true;
            if (active.Cancelers == 0) dispose = active.Cancellation;
        }
        dispose?.Dispose();
    }

    private void CompleteCancellation(ActiveWait active)
    {
        CancellationTokenSource? dispose = null;
        lock (_gate)
        {
            active.Cancelers--;
            if (active.Retired && active.Cancelers == 0) dispose = active.Cancellation;
        }
        dispose?.Dispose();
    }

    private void CompletePriorityStop()
    {
        lock (_gate)
        {
            if (_priorityStops <= 0) throw new InvalidOperationException("No priority process stop is active.");
            _priorityStops--;
        }
    }

    internal sealed class ActiveWait
    {
        internal CancellationTokenSource Cancellation { get; } = new();
        internal int Cancelers { get; set; }
        internal bool Retired { get; set; }
    }

    internal sealed class ManagedWaitLease : IDisposable
    {
        private ManagedUpdateStopArbitration? _owner;
        private readonly ActiveWait _active;

        internal ManagedWaitLease(ManagedUpdateStopArbitration owner, ActiveWait active)
        {
            _owner = owner;
            _active = active;
        }

        internal CancellationToken Token => _active.Cancellation.Token;
        internal bool IsPriorityCancellationRequested => _active.Cancellation.IsCancellationRequested;

        public void Dispose() => Interlocked.Exchange(ref _owner, null)?.CompleteManagedWait(_active);
    }

    internal sealed class PriorityStopLease : IDisposable
    {
        private ManagedUpdateStopArbitration? _owner;

        internal PriorityStopLease(ManagedUpdateStopArbitration owner) => _owner = owner;

        public void Dispose() => Interlocked.Exchange(ref _owner, null)?.CompletePriorityStop();
    }
}
