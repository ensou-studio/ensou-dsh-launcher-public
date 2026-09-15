using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Ensou.Dsh.WindowsPilotObserver;

public sealed class WindowsEventHookCollector : IDisposable
{
    public const uint EventSystemForeground = 0x0003;
    public const uint EventSystemDialogStart = 0x0010;
    public const uint EventObjectCreate = 0x8000;
    public const uint EventObjectShow = 0x8002;
    private const int ObjectIdWindow = 0;
    private const uint WinEventOutOfContext = 0x0000;
    private const uint WinEventSkipOwnProcess = 0x0002;

    private readonly Action<string, WindowObservation> onWindowEvent;
    private readonly Action<string> onHookFailure;
    private readonly NativeWinEvent.WinEventCallback callback;
    private readonly List<IntPtr> hooks = [];
    private bool disposed;

    public WindowsEventHookCollector(
        Action<string, WindowObservation> onWindowEvent,
        Action<string> onHookFailure)
    {
        this.onWindowEvent = onWindowEvent;
        this.onHookFailure = onHookFailure;
        callback = OnWinEvent;
    }

    public void Start()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (hooks.Count != 0)
        {
            throw new InvalidOperationException("Windows event hooks are already active.");
        }
        try
        {
            AddHook(EventSystemForeground);
            AddHook(EventSystemDialogStart);
            AddHook(EventObjectCreate);
            AddHook(EventObjectShow);
        }
        catch
        {
            DisposeHooks();
            throw;
        }
    }

    private void AddHook(uint eventId)
    {
        var hook = NativeWinEvent.SetWinEventHook(
            eventId,
            eventId,
            IntPtr.Zero,
            callback,
            0,
            0,
            WinEventOutOfContext | WinEventSkipOwnProcess);
        if (hook == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"SetWinEventHook failed for {eventId:x}.");
        }
        hooks.Add(hook);
    }

    private void OnWinEvent(
        IntPtr hook,
        uint eventType,
        IntPtr window,
        int objectId,
        int childId,
        uint eventThread,
        uint eventTime)
    {
        _ = hook;
        _ = eventThread;
        _ = eventTime;
        if (objectId != ObjectIdWindow || childId != 0 || window == IntPtr.Zero)
        {
            return;
        }
        try
        {
            var root = NativeDesktop.GetAncestor(window, NativeDesktop.GaRoot);
            if (root != IntPtr.Zero && root != window)
            {
                return;
            }
            var observation = WindowsDesktopProbe.CaptureWindow(window);
            if (observation is not null)
            {
                onWindowEvent(EventName(eventType), observation);
            }
            else
            {
                onHookFailure("WindowExpiredBeforeCapture");
            }
        }
        catch (Exception exception)
        {
            onHookFailure(exception.GetType().Name);
        }
    }

    private static string EventName(uint eventType) => eventType switch
    {
        EventSystemForeground => "FOREGROUND",
        EventSystemDialogStart => "DIALOG",
        EventObjectCreate => "CREATE",
        EventObjectShow => "SHOW",
        _ => "UNKNOWN",
    };

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }
        disposed = true;
        DisposeHooks();
        GC.KeepAlive(callback);
    }

    private void DisposeHooks()
    {
        foreach (var hook in hooks)
        {
            if (!NativeWinEvent.UnhookWinEvent(hook))
            {
                onHookFailure("UnhookWinEvent");
            }
        }
        hooks.Clear();
    }
}

internal static class NativeWinEvent
{
    internal delegate void WinEventCallback(
        IntPtr hook,
        uint eventType,
        IntPtr window,
        int objectId,
        int childId,
        uint eventThread,
        uint eventTime);

    [DllImport("user32.dll", SetLastError = true)]
    internal static extern IntPtr SetWinEventHook(
        uint eventMinimum,
        uint eventMaximum,
        IntPtr eventHookModule,
        WinEventCallback callback,
        uint processId,
        uint threadId,
        uint flags);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool UnhookWinEvent(IntPtr hook);
}
