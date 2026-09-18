using System.Runtime.InteropServices;

namespace HermesBridge.ServiceHost;

internal static class ScmNative
{
    internal const uint ServiceWin32OwnProcess = 0x00000010;
    internal const uint ServiceStartPending = 0x00000002;
    internal const uint ServiceStopPending = 0x00000003;
    internal const uint ServiceRunning = 0x00000004;
    internal const uint ServiceStopped = 0x00000001;
    internal const uint ServiceAcceptStop = 0x00000001;
    internal const uint ServiceAcceptShutdown = 0x00000004;
    internal const uint ServiceControlStop = 0x00000001;
    internal const uint ServiceControlShutdown = 0x00000005;
    internal const uint ErrorServiceSpecificError = 1066;

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    internal delegate void ServiceMain(uint argumentCount, IntPtr arguments);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    internal delegate uint HandlerEx(uint control, uint eventType, IntPtr eventData, IntPtr context);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct ServiceTableEntry
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string? ServiceName;
        public ServiceMain? ServiceProc;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ServiceStatus
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
    }

    [DllImport("advapi32.dll", EntryPoint = "StartServiceCtrlDispatcherW", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool StartServiceCtrlDispatcher([In, Out] ServiceTableEntry[] serviceTable);

    [DllImport("advapi32.dll", EntryPoint = "RegisterServiceCtrlHandlerExW", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern IntPtr RegisterServiceCtrlHandlerEx(string serviceName, HandlerEx handler, IntPtr context);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetServiceStatus(IntPtr statusHandle, ref ServiceStatus status);
}
