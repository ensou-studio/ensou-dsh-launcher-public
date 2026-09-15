using System.ComponentModel;
using System.Diagnostics;
using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Ensou.Dsh.Host;

/// <summary>
/// Resolves the Windows owner of an exact IPv4 loopback listening socket.
/// The caller must check this immediately before and after every local health
/// or authentication request so an unrelated process cannot answer for the
/// owned DSH process.
/// </summary>
internal static class DshLoopbackListenerOwnership
{
    private const uint ErrorSuccess = 0;
    private const uint ErrorInsufficientBuffer = 122;
    private const int AddressFamilyInternet = 2;
    private const int TcpTableOwnerPidListener = 3;
    private const uint TcpStateListen = 2;
    private const int TableHeaderBytes = sizeof(uint);
    private const int OwnerPidRowBytes = 6 * sizeof(uint);
    private const int MaximumTableBytes = 16 * 1024 * 1024;
    private const int MaximumQueryAttempts = 3;

    // MIB_TCPROW_OWNER_PID stores IPv4 addresses in network byte order. On
    // supported Windows hosts, reading 127.0.0.1 as a native DWORD yields this.
    private const uint Ipv4LoopbackMibValue = 0x0100007f;

    internal static bool IsExactProcessListeningOnIpv4Loopback(
        Process process,
        int port)
    {
        ArgumentNullException.ThrowIfNull(process);
        if (!OperatingSystem.IsWindows() || port is < 1 or > ushort.MaxValue)
        {
            return false;
        }

        if (!TryGetActiveProcessId(process, out var processId)
            || !TryFindListener(processId, checked((ushort)port)))
        {
            return false;
        }

        // A retained Process handle identifies the original process even after
        // its numeric PID becomes reusable. Rechecking it after the table query
        // prevents a row owned by a recycled PID from passing admission.
        return TryGetActiveProcessId(process, out var confirmedProcessId)
            && confirmedProcessId == processId;
    }

    private static bool TryGetActiveProcessId(Process process, out uint processId)
    {
        processId = 0;
        try
        {
            if (process.HasExited || process.Id <= 0)
            {
                return false;
            }
            processId = checked((uint)process.Id);
            return !process.HasExited;
        }
        catch (Exception exception) when (exception is
            InvalidOperationException
            or NotSupportedException
            or Win32Exception)
        {
            processId = 0;
            return false;
        }
    }

    private static bool TryFindListener(uint processId, ushort port)
    {
        try
        {
            return TryFindListenerCore(processId, port);
        }
        catch (Exception exception) when (exception is
            ArgumentException
            or ArithmeticException
            or BadImageFormatException
            or DllNotFoundException
            or EntryPointNotFoundException
            or ExternalException)
        {
            return false;
        }
    }

    private static bool TryFindListenerCore(uint processId, ushort port)
    {
        uint tableBytes = 0;
        var probeResult = GetExtendedTcpTable(
            IntPtr.Zero,
            ref tableBytes,
            order: false,
            AddressFamilyInternet,
            TcpTableOwnerPidListener,
            reserved: 0);
        if ((probeResult != ErrorInsufficientBuffer
                && probeResult != ErrorSuccess)
            || !IsBoundedTableSize(tableBytes))
        {
            return false;
        }

        for (var attempt = 0; attempt < MaximumQueryAttempts; attempt++)
        {
            var buffer = IntPtr.Zero;
            try
            {
                buffer = Marshal.AllocHGlobal(checked((int)tableBytes));
                var returnedBytes = tableBytes;
                var result = GetExtendedTcpTable(
                    buffer,
                    ref returnedBytes,
                    order: false,
                    AddressFamilyInternet,
                    TcpTableOwnerPidListener,
                    reserved: 0);
                if (result == ErrorInsufficientBuffer)
                {
                    if (!IsBoundedTableSize(returnedBytes))
                    {
                        return false;
                    }
                    tableBytes = returnedBytes;
                    continue;
                }
                if (result != ErrorSuccess
                    || returnedBytes > tableBytes
                    || returnedBytes < TableHeaderBytes)
                {
                    return false;
                }
                return ContainsExactListener(
                    buffer,
                    returnedBytes,
                    processId,
                    port);
            }
            catch (Exception exception) when (exception is
                ArgumentException
                or ArithmeticException
                or ExternalException)
            {
                return false;
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }

        return false;
    }

    private static bool ContainsExactListener(
        IntPtr table,
        uint tableBytes,
        uint processId,
        ushort port)
    {
        var rowCount = unchecked((uint)Marshal.ReadInt32(table));
        var maximumRows = (tableBytes - TableHeaderBytes) / OwnerPidRowBytes;
        if (rowCount > maximumRows)
        {
            return false;
        }

        for (uint index = 0; index < rowCount; index++)
        {
            var rowOffset = checked(
                TableHeaderBytes + checked((int)index * OwnerPidRowBytes));
            var state = ReadUInt32(table, rowOffset);
            var localAddress = ReadUInt32(table, rowOffset + sizeof(uint));
            var localPort = ReadUInt32(table, rowOffset + (2 * sizeof(uint)));
            var owningProcessId = ReadUInt32(
                table,
                rowOffset + (5 * sizeof(uint)));
            if (state == TcpStateListen
                && localAddress == Ipv4LoopbackMibValue
                && NetworkToHostPort(localPort) == port
                && owningProcessId == processId)
            {
                return true;
            }
        }

        return false;
    }

    private static uint ReadUInt32(IntPtr buffer, int offset) =>
        unchecked((uint)Marshal.ReadInt32(buffer, offset));

    private static ushort NetworkToHostPort(uint value) =>
        BinaryPrimitives.ReverseEndianness(
            unchecked((ushort)(value & ushort.MaxValue)));

    private static bool IsBoundedTableSize(uint tableBytes) =>
        tableBytes >= TableHeaderBytes && tableBytes <= MaximumTableBytes;

    [DllImport("iphlpapi.dll")]
    private static extern uint GetExtendedTcpTable(
        IntPtr tcpTable,
        ref uint tableBytes,
        [MarshalAs(UnmanagedType.Bool)] bool order,
        int addressFamily,
        int tableClass,
        uint reserved);
}
