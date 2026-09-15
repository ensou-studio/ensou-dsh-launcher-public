using Microsoft.Win32;

namespace Ensou.Dsh.WindowsPilotObserver;

public sealed class ObserverForm : Form
{
    private readonly ObservationEngine engine;
    private readonly Label verdictLabel = new();
    private readonly Label elapsedLabel = new();
    private readonly Label actionLabel = new();
    private readonly TextBox challengeText = new();
    private readonly Label instructionLabel = new();
    private readonly Button startButton = new();
    private readonly Button completeActionButton = new();
    private readonly Button endButton = new();
    private readonly Button finalizeButton = new();
    private readonly System.Windows.Forms.Timer uiTimer = new() { Interval = 250 };
    private bool systemEventsSubscribed;

    public ObserverForm(ObservationEngine engine, ObservationPlan plan)
    {
        this.engine = engine;
        Text = "Ensou DSH Windows Pilot Observer";
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(760, 520);
        Size = new Size(840, 580);
        MaximizeBox = false;
        FormBorderStyle = FormBorderStyle.FixedDialog;

        var title = new Label
        {
            AutoSize = true,
            Font = new Font(Font.FontFamily, 16, FontStyle.Bold),
            Text = "Windows Pilot — passive evidence capture",
            Margin = new Padding(0, 0, 0, 8),
        };
        var contract = new Label
        {
            AutoSize = true,
            Text = $"Run: {plan.TestRunId}   Edition: {plan.Edition}   Minimum: {plan.MinimumObservationSeconds / 60} min",
            Margin = new Padding(0, 0, 0, 12),
        };
        instructionLabel.AutoSize = true;
        instructionLabel.MaximumSize = new Size(760, 0);
        instructionLabel.Text =
            "Start the approved external screen recorder first. Keep this entire window and the challenge "
            + "visible in the recording, then select Begin observation. The observer never clicks or closes other windows.";
        instructionLabel.Margin = new Padding(0, 0, 0, 12);

        challengeText.ReadOnly = true;
        challengeText.Text = engine.StartChallenge;
        challengeText.Font = new Font(FontFamily.GenericMonospace, 12, FontStyle.Bold);
        challengeText.Width = 720;
        challengeText.Margin = new Padding(0, 0, 0, 12);

        verdictLabel.AutoSize = true;
        elapsedLabel.AutoSize = true;
        actionLabel.AutoSize = true;
        verdictLabel.Margin = new Padding(0, 0, 0, 4);
        elapsedLabel.Margin = new Padding(0, 0, 0, 4);
        actionLabel.Margin = new Padding(0, 0, 0, 12);

        startButton.Text = "Begin observation";
        startButton.AutoSize = true;
        startButton.Click += StartClicked;
        completeActionButton.Text = "Mark current action complete";
        completeActionButton.AutoSize = true;
        completeActionButton.Enabled = false;
        completeActionButton.Click += CompleteActionClicked;
        endButton.Text = "End observation";
        endButton.AutoSize = true;
        endButton.Enabled = false;
        endButton.Click += EndClicked;
        finalizeButton.Text = "Finalize evidence after stopping recorder";
        finalizeButton.AutoSize = true;
        finalizeButton.Enabled = false;
        finalizeButton.Click += FinalizeClicked;

        var buttonRow = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = true,
            Margin = new Padding(0, 8, 0, 0),
        };
        buttonRow.Controls.AddRange([startButton, completeActionButton, endButton, finalizeButton]);

        var warning = new Label
        {
            AutoSize = true,
            MaximumSize = new Size(760, 0),
            ForeColor = Color.DarkRed,
            Text =
                "This tool produces review evidence only. standaloneAdmissionEvidence is always false; "
                + "it cannot admit a Personal or Enterprise release by itself.",
            Margin = new Padding(0, 18, 0, 0),
        };

        var layout = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            AutoScroll = true,
            Padding = new Padding(24),
        };
        layout.Controls.AddRange([
            title,
            contract,
            instructionLabel,
            challengeText,
            verdictLabel,
            elapsedLabel,
            actionLabel,
            buttonRow,
            warning,
        ]);
        Controls.Add(layout);

        engine.StatusChanged += EngineStatusChanged;
        uiTimer.Tick += (_, _) => UpdateStatus();
        uiTimer.Start();
        SubscribeSystemEvents();
        FormClosing += OnFormClosing;
        UpdateStatus();
    }

    private void StartClicked(object? sender, EventArgs args)
    {
        _ = sender;
        _ = args;
        try
        {
            engine.Start();
            startButton.Enabled = false;
            completeActionButton.Enabled = true;
            endButton.Enabled = true;
        }
        catch (Exception exception)
        {
            MessageBox.Show(
                this,
                $"Observation preflight failed: {exception.Message}",
                "Pilot Observer",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            endButton.Enabled = engine.IsStarted;
        }
        UpdateStatus();
    }

    private void CompleteActionClicked(object? sender, EventArgs args)
    {
        _ = sender;
        _ = args;
        try
        {
            engine.CompleteCurrentAction();
            completeActionButton.Enabled = engine.CurrentAction is not null;
        }
        catch (InvalidOperationException exception)
        {
            MessageBox.Show(this, exception.Message, "Pilot Observer");
        }
        UpdateStatus();
    }

    private void EndClicked(object? sender, EventArgs args)
    {
        _ = sender;
        _ = args;
        try
        {
            var endChallenge = engine.EndObservation();
            challengeText.Text = endChallenge;
            instructionLabel.Text =
                "Keep this END challenge visible for several seconds, stop the external recorder, wait for it to flush, "
                + "then select Finalize evidence.";
            completeActionButton.Enabled = false;
            endButton.Enabled = false;
            finalizeButton.Enabled = true;
        }
        catch (InvalidOperationException exception)
        {
            MessageBox.Show(this, exception.Message, "Pilot Observer");
        }
        UpdateStatus();
    }

    private void FinalizeClicked(object? sender, EventArgs args)
    {
        _ = sender;
        _ = args;
        try
        {
            var completion = engine.FinalizeEvidence();
            finalizeButton.Enabled = false;
            instructionLabel.Text =
                $"Evidence finalized as {completion.Verdict}. Directory: {completion.EvidenceDirectory}";
            MessageBox.Show(
                this,
                $"Evidence finalized as {completion.Verdict}.\n\n{completion.EvidenceDirectory}",
                "Pilot Observer",
                MessageBoxButtons.OK,
                completion.Verdict == "ELIGIBLE_FOR_REVIEW"
                    ? MessageBoxIcon.Information
                    : MessageBoxIcon.Warning);
        }
        catch (Exception exception) when (
            exception is IOException
            or UnauthorizedAccessException
            or InvalidDataException
            or InvalidOperationException)
        {
            MessageBox.Show(
                this,
                $"Evidence finalization failed: {exception.Message}",
                "Pilot Observer",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
        UpdateStatus();
    }

    private void UpdateStatus()
    {
        verdictLabel.Text = $"Current verdict: {engine.Verdict}"
            + (engine.ReasonCodes.Length == 0
                ? string.Empty
                : $" ({string.Join(", ", engine.ReasonCodes)})");
        elapsedLabel.Text = $"Monotonic duration: {TimeSpan.FromMilliseconds(engine.ElapsedMilliseconds):hh\\:mm\\:ss}";
        actionLabel.Text = engine.CurrentAction is null
            ? "Required actions: all marked complete"
            : $"Current required action: {engine.CurrentAction}";
    }

    private void EngineStatusChanged(object? sender, EventArgs args)
    {
        _ = sender;
        _ = args;
        if (IsDisposed || !IsHandleCreated)
        {
            return;
        }
        _ = BeginInvoke(UpdateStatus);
    }

    private void SubscribeSystemEvents()
    {
        SystemEvents.PowerModeChanged += PowerModeChanged;
        SystemEvents.SessionSwitch += SessionSwitch;
        systemEventsSubscribed = true;
    }

    private void PowerModeChanged(object sender, PowerModeChangedEventArgs args)
    {
        _ = sender;
        if (args.Mode == PowerModes.Suspend)
        {
            engine.NotifySystemInterruption("SYSTEM_SUSPEND");
        }
    }

    private void SessionSwitch(object sender, SessionSwitchEventArgs args)
    {
        _ = sender;
        if (args.Reason is SessionSwitchReason.SessionLock
            or SessionSwitchReason.ConsoleDisconnect
            or SessionSwitchReason.RemoteDisconnect)
        {
            engine.NotifySystemInterruption("DESKTOP_SESSION_INTERRUPTED");
        }
    }

    private void OnFormClosing(object? sender, FormClosingEventArgs args)
    {
        _ = sender;
        if (engine.IsStarted && !engine.IsFinalized)
        {
            engine.NotifySystemInterruption("OBSERVER_CLOSED_EARLY");
            args.Cancel = true;
            MessageBox.Show(
                this,
                "End and finalize the observation before closing. The run is now BLOCKED.",
                "Pilot Observer",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }
        uiTimer.Stop();
        if (systemEventsSubscribed)
        {
            SystemEvents.PowerModeChanged -= PowerModeChanged;
            SystemEvents.SessionSwitch -= SessionSwitch;
            systemEventsSubscribed = false;
        }
        engine.Dispose();
    }
}
