Set-StrictMode -Version Latest

if ($null -eq ('HermesBridge.BoundedProcess' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace HermesBridge {
  public sealed class BoundedProcessResult {
    public int ExitCode { get; set; }
    public string Stdout { get; set; }
    public string Stderr { get; set; }
  }

  public static class BoundedProcess {
    private const uint CreateSuspended = 0x00000004;
    private const uint CreateNoWindow = 0x08000000;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint StartfUseStdHandles = 0x00000100;
    private const uint HandleFlagInherit = 0x00000001;
    private const uint Infinite = 0xffffffff;
    private const uint WaitObject0 = 0;
    private const int MaximumOutputBytes = 1048576;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo {
      public uint cb; public string reserved; public string desktop; public string title;
      public uint x, y, xSize, ySize, xChars, yChars, fill, flags;
      public ushort showWindow, reserved2; public IntPtr reservedBytes;
      public IntPtr stdin, stdout, stderr;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation { public IntPtr process, thread; public uint processId, threadId; }
    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes { public uint length; public IntPtr descriptor; public bool inherit; }
    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimit { public long perProcess, perJob; public uint flags; public UIntPtr min, max; public uint active; public UIntPtr affinity; public uint priority, scheduling; }
    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters { public ulong readOps, writeOps, otherOps, readBytes, writeBytes, otherBytes; }
    [StructLayout(LayoutKind.Sequential)]
    private struct ExtendedLimit { public BasicLimit basic; public IoCounters io; public UIntPtr processMemory, jobMemory, peakProcess, peakJob; }

    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool CreateProcess(string application, StringBuilder commandLine, IntPtr processAttributes,
      IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string directory,
      ref StartupInfo startup, out ProcessInformation process);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool CreatePipe(out IntPtr read, out IntPtr write, ref SecurityAttributes attributes, uint size);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool SetInformationJobObject(IntPtr job, int type, ref ExtendedLimit info, uint length);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool PeekNamedPipe(IntPtr pipe, IntPtr buffer, uint size, IntPtr read, out uint available, IntPtr remaining);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool ReadFile(IntPtr file, byte[] buffer, uint size, out uint read, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool TerminateJobObject(IntPtr job, uint exitCode);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);

    private static void Check(bool value) { if (!value) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    private static string Quote(string value) {
      if (value.Length > 0 && value.IndexOfAny(new [] {' ', '\t', '\n', '\v', '"'}) < 0) return value;
      var result = new StringBuilder("\""); int slashes = 0;
      foreach (char character in value) {
        if (character == '\\') { slashes++; continue; }
        if (character == '"') { result.Append('\\', slashes * 2 + 1); result.Append(character); slashes = 0; continue; }
        result.Append('\\', slashes); slashes = 0; result.Append(character);
      }
      result.Append('\\', slashes * 2); result.Append('"'); return result.ToString();
    }
    private static string CommandLine(string application, string[] arguments) {
      var values = new List<string> { Quote(application) };
      foreach (string argument in arguments) values.Add(Quote(argument));
      return string.Join(" ", values.ToArray());
    }
    private static IntPtr EnvironmentBlock(IDictionary environment) {
      var entries = new List<string>();
      foreach (DictionaryEntry entry in environment) entries.Add(Convert.ToString(entry.Key) + "=" + Convert.ToString(entry.Value));
      entries.Sort(StringComparer.OrdinalIgnoreCase);
      string block = string.Join("\0", entries.ToArray()) + "\0\0";
      return Marshal.StringToHGlobalUni(block);
    }
    private static bool Drain(IntPtr pipe, MemoryStream output) {
      uint available; if (!PeekNamedPipe(pipe, IntPtr.Zero, 0, IntPtr.Zero, out available, IntPtr.Zero)) return true;
      if (available == 0) return false;
      byte[] buffer = new byte[Math.Min(4096, available)]; uint read;
      Check(ReadFile(pipe, buffer, (uint)buffer.Length, out read, IntPtr.Zero));
      if (output.Length + read > MaximumOutputBytes) throw new InvalidDataException("BridgeRuntimeChildOutputTooLarge");
      output.Write(buffer, 0, (int)read); return false;
    }

    public static BoundedProcessResult Run(string application, string[] arguments, string directory, IDictionary environment, int timeoutSeconds) {
      IntPtr stdinRead = IntPtr.Zero, stdinWrite = IntPtr.Zero, stdoutRead = IntPtr.Zero, stdoutWrite = IntPtr.Zero;
      IntPtr stderrRead = IntPtr.Zero, stderrWrite = IntPtr.Zero;
      IntPtr job = IntPtr.Zero, environmentBlock = IntPtr.Zero; ProcessInformation process = new ProcessInformation();
      var stdout = new MemoryStream(); var stderr = new MemoryStream(); bool started = false, assigned = false;
      try {
        var security = new SecurityAttributes { length = (uint)Marshal.SizeOf(typeof(SecurityAttributes)), inherit = true };
        Check(CreatePipe(out stdinRead, out stdinWrite, ref security, 0)); Check(SetHandleInformation(stdinWrite, HandleFlagInherit, 0));
        Check(CreatePipe(out stdoutRead, out stdoutWrite, ref security, 0)); Check(SetHandleInformation(stdoutRead, HandleFlagInherit, 0));
        Check(CreatePipe(out stderrRead, out stderrWrite, ref security, 0)); Check(SetHandleInformation(stderrRead, HandleFlagInherit, 0));
        job = CreateJobObject(IntPtr.Zero, null); Check(job != IntPtr.Zero);
        var limits = new ExtendedLimit(); limits.basic.flags = 0x2000;
        Check(SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(typeof(ExtendedLimit))));
        var startup = new StartupInfo { cb = (uint)Marshal.SizeOf(typeof(StartupInfo)), flags = StartfUseStdHandles,
          stdin = stdinRead, stdout = stdoutWrite, stderr = stderrWrite };
        environmentBlock = EnvironmentBlock(environment);
        var commandLine = new StringBuilder(CommandLine(application, arguments));
        Check(CreateProcess(application, commandLine, IntPtr.Zero, IntPtr.Zero, true,
          CreateSuspended | CreateNoWindow | CreateUnicodeEnvironment, environmentBlock, directory, ref startup, out process));
        started = true; Check(AssignProcessToJobObject(job, process.process)); assigned = true;
        CloseHandle(stdinRead); stdinRead = IntPtr.Zero; CloseHandle(stdinWrite); stdinWrite = IntPtr.Zero;
        if (ResumeThread(process.thread) == Infinite) throw new Win32Exception(Marshal.GetLastWin32Error());
        CloseHandle(stdoutWrite); stdoutWrite = IntPtr.Zero; CloseHandle(stderrWrite); stderrWrite = IntPtr.Zero;
        var deadline = DateTime.UtcNow.AddSeconds(timeoutSeconds); bool stdoutDone = false, stderrDone = false;
        while (true) {
          stdoutDone = Drain(stdoutRead, stdout) || stdoutDone; stderrDone = Drain(stderrRead, stderr) || stderrDone;
          bool exited = WaitForSingleObject(process.process, 0) == WaitObject0;
          if (exited && stdoutDone && stderrDone) break;
          if (DateTime.UtcNow >= deadline) throw new TimeoutException("BridgeRuntimeChildTimeout");
          System.Threading.Thread.Sleep(10);
        }
        uint exitCode; Check(GetExitCodeProcess(process.process, out exitCode));
        return new BoundedProcessResult { ExitCode = unchecked((int)exitCode), Stdout = Encoding.UTF8.GetString(stdout.ToArray()), Stderr = Encoding.UTF8.GetString(stderr.ToArray()) };
      } catch {
        if (assigned && job != IntPtr.Zero) { TerminateJobObject(job, 1); WaitForSingleObject(process.process, 5000); }
        // Job 할당 전 실패한 suspended process도 직접 종료하여 고아 프로세스를 남기지 않습니다.
        if (started && !assigned && WaitForSingleObject(process.process, 0) != WaitObject0) {
          Process.GetProcessById((int)process.processId).Kill(); WaitForSingleObject(process.process, 5000);
        }
        throw;
      } finally {
        stdout.Dispose(); stderr.Dispose(); if (environmentBlock != IntPtr.Zero) Marshal.FreeHGlobal(environmentBlock);
        foreach (IntPtr handle in new [] { stdinRead, stdinWrite, stdoutRead, stdoutWrite, stderrRead, stderrWrite, process.thread, process.process, job }) if (handle != IntPtr.Zero) CloseHandle(handle);
      }
    }
  }
}
'@
}
