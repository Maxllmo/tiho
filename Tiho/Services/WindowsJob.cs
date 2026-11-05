using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Tiho.Services;

// Windows kills both VPN cores if the UI crashes or is terminated in Task Manager.
internal sealed class WindowsJob : IDisposable
{
    private IntPtr _handle;
    public WindowsJob()
    {
        if (!OperatingSystem.IsWindows()) return;
        _handle = CreateJobObject(IntPtr.Zero, null);
        if (_handle == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        var info = new ExtendedLimit { Basic = new BasicLimit { LimitFlags = 0x2000 } };
        if (!SetInformationJobObject(_handle, 9, ref info, (uint)Marshal.SizeOf<ExtendedLimit>()))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    public void Add(Process process)
    {
        if (_handle != IntPtr.Zero && !AssignProcessToJobObject(_handle, process.Handle))
        { process.Kill(entireProcessTree: true); throw new Win32Exception(Marshal.GetLastWin32Error()); }
    }
    public void Dispose() { if (_handle != IntPtr.Zero) { CloseHandle(_handle); _handle = IntPtr.Zero; } }
    [StructLayout(LayoutKind.Sequential)] private struct BasicLimit
    { public long PerProcessUserTimeLimit, PerJobUserTimeLimit; public uint LimitFlags; public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint PriorityClass, SchedulingClass; }
    [StructLayout(LayoutKind.Sequential)] private struct IoCounters { public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount; }
    [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimit
    { public BasicLimit Basic; public IoCounters Io; public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CreateJobObject(IntPtr attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetInformationJobObject(IntPtr job, int kind, ref ExtendedLimit info, uint size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
}
