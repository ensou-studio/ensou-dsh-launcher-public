namespace Ensou.Dsh.WindowsPilotObserver;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        try
        {
            if (args.Length == 1 && string.Equals(args[0], "--self-check", StringComparison.Ordinal))
            {
                var identity = ExecutionIdentityPolicy.CaptureCurrent();
                var platform = PlatformEvidence.CaptureCurrent();
                return ExecutionIdentityPolicy.IsAccepted(identity.ElevationType, identity.IntegrityRid)
                    && platform.IsAccepted
                    ? 0
                    : 2;
            }
            if (args.Length != 2 || !string.Equals(args[0], "--plan", StringComparison.Ordinal))
            {
                throw new ArgumentException("Usage: Ensou.Dsh.WindowsPilotObserver.exe --plan <absolute-plan.json>");
            }
            if (!Path.IsPathFullyQualified(args[1]))
            {
                throw new ArgumentException("Observation plan path must be absolute.");
            }
            var rawPlan = File.ReadAllBytes(args[1]);
            var plan = ObservationContract.ParsePlan(rawPlan);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            using var engine = new ObservationEngine(plan, rawPlan);
            Application.Run(new ObserverForm(engine, plan));
            return engine.IsFinalized ? 0 : 3;
        }
        catch (Exception exception) when (
            exception is IOException
            or UnauthorizedAccessException
            or InvalidDataException
            or ArgumentException
            or PlatformNotSupportedException
            or System.ComponentModel.Win32Exception)
        {
            MessageBox.Show(
                exception.Message,
                "Ensou DSH Windows Pilot Observer",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            return 1;
        }
    }
}
