using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost.Tests
{
    // Hermetic checks for the overlapped I/O lifetime repair. They read the
    // production source for the ownership order and exercise the channel close
    // race with fake pipes. They open no pipe and call no Win32 function.
    internal static class ServiceHostOverlappedLifetimeRepairChecks
    {
        private const string ServiceImage =
            "C:\\Program Files\\HotspotShade\\HotspotShadeEngineSvc.exe";

        public static void Run(ServiceHostCheckRunner runner)
        {
            runner.Check("overlapped repair: each operation marks kernel ownership and completion", delegate
            {
                string io = ReadSource("WindowsNamedPipeIo.cs");

                string connect = Between(
                    io,
                    "public static bool TryConnect",
                    "public static bool TryReadFrame");
                ServiceHostAssert.True(
                    connect.IndexOf("context.BeginOperation()", StringComparison.Ordinal)
                        < connect.IndexOf("ConnectNamedPipe", StringComparison.Ordinal),
                    "connect marks ownership before the kernel call");
                ServiceHostAssert.True(
                    connect.IndexOf("context.ProveCompletion()", StringComparison.Ordinal)
                        > connect.IndexOf("ConnectNamedPipe", StringComparison.Ordinal),
                    "connect proves completion after the kernel call");

                string read = Between(
                    io,
                    "internal static int TryReadSome",
                    "internal static int TryWriteSome");
                ServiceHostAssert.True(
                    read.IndexOf("context.PrepareBuffer(buffer, offset, count)", StringComparison.Ordinal)
                        < read.IndexOf("context.BeginOperation()", StringComparison.Ordinal),
                    "read prepares the buffer before kernel ownership");
                ServiceHostAssert.True(
                    read.IndexOf("context.BeginOperation()", StringComparison.Ordinal)
                        < read.IndexOf("ReadFile", StringComparison.Ordinal),
                    "read marks ownership before ReadFile");
                ServiceHostAssert.True(
                    read.IndexOf("context.ProveCompletion()", StringComparison.Ordinal)
                        > read.IndexOf("ReadFile", StringComparison.Ordinal),
                    "read proves completion after ReadFile");

                string write = Between(
                    io,
                    "internal static int TryWriteSome",
                    "private static bool TryWait");
                ServiceHostAssert.True(
                    write.IndexOf("context.PrepareBuffer(buffer, offset, count)", StringComparison.Ordinal)
                        < write.IndexOf("context.BeginOperation()", StringComparison.Ordinal),
                    "write prepares the buffer before kernel ownership");
                ServiceHostAssert.True(
                    write.IndexOf("context.BeginOperation()", StringComparison.Ordinal)
                        < write.IndexOf("WriteFile", StringComparison.Ordinal),
                    "write marks ownership before WriteFile");
                ServiceHostAssert.True(
                    write.IndexOf("context.ProveCompletion()", StringComparison.Ordinal)
                        > write.IndexOf("WriteFile", StringComparison.Ordinal),
                    "write proves completion after WriteFile");
            });

            runner.Check("overlapped repair: the native surface takes an unmanaged address", delegate
            {
                string methods = ReadSource("WindowsPipeNativeMethods.cs");
                ServiceHostAssert.Contains(
                    methods,
                    "ConnectNamedPipe(\n            IntPtr pipe,\n            IntPtr overlapped)",
                    "connect takes an address");
                ServiceHostAssert.Contains(
                    methods,
                    "GetOverlappedResult(\n            IntPtr file,\n            IntPtr overlapped,",
                    "result takes an address");
                ServiceHostAssert.DoesNotContain(
                    methods,
                    "ref NativeOverlapped",
                    "no managed OVERLAPPED by ref");
            });

            runner.Check("overlapped repair: cancellation waits for the event and collects the result", delegate
            {
                string io = ReadSource("WindowsNamedPipeIo.cs");
                string cancel = From(io, "private static bool TryCancelAndProve");
                int requested = cancel.IndexOf("CancelIoEx", StringComparison.Ordinal);
                int waited = cancel.IndexOf("WaitForSingleObject", StringComparison.Ordinal);
                int collected = cancel.IndexOf("TryCollectCompletion", StringComparison.Ordinal);
                int proven = cancel.IndexOf("context.ProveCompletion()", StringComparison.Ordinal);
                ServiceHostAssert.True(requested >= 0, "cancel request present");
                ServiceHostAssert.True(requested < waited, "cancel request before the wait");
                ServiceHostAssert.True(waited < collected, "wait before the result collection");
                ServiceHostAssert.True(collected < proven, "result before completion proof");
                ServiceHostAssert.Contains(io, "CompletionProofWaitMilliseconds", "bounded proof wait");
                ServiceHostAssert.Contains(
                    io,
                    "TryCancelAndProve(handle, context, environment, out completion)",
                    "abort uses the proven cancel");
            });

            runner.Check("overlapped repair: begin and dispose use atomic state transitions", delegate
            {
                string io = ReadSource("WindowsNamedPipeIo.cs");
                string context = Between(
                    io,
                    "internal sealed class WindowsOverlappedContext",
                    "internal sealed class WindowsOverlappedQuarantine");
                string dispose = Between(
                    context,
                    "public void Dispose()",
                    "private void ReleaseResources()");
                ServiceHostAssert.Contains(
                    dispose,
                    "Interlocked.CompareExchange(",
                    "atomic held claim");
                ServiceHostAssert.Contains(dispose, "StateReleased", "atomic release claim");
                ServiceHostAssert.DoesNotContain(
                    dispose,
                    "Volatile.Write(ref state, StateReleased)",
                    "no racy release write");
                string begin = Between(
                    context,
                    "public void BeginOperation()",
                    "public void ProveCompletion()");
                ServiceHostAssert.Contains(
                    begin,
                    "Interlocked.CompareExchange(ref state, StateOperating, StateNew)",
                    "atomic begin claim");
            });

            runner.Check("overlapped repair: deadlines are monotonic and pre-cancel starts no I/O", delegate
            {
                string io = ReadSource("WindowsNamedPipeIo.cs");
                ServiceHostAssert.Contains(io, "Stopwatch.GetTimestamp()", "monotonic clock");
                ServiceHostAssert.Contains(io, "CreateMonotonicDeadline(timeout)", "operation cap");
                ServiceHostAssert.Contains(io, "MonotonicDeadlineReached(monotonicDeadline)", "legacy monotonic cap");
                ServiceHostAssert.Contains(io, "? deadline - environment.Now() : readDeadline.Remaining", "server read selects monotonic remaining");
                ServiceHostAssert.Contains(io, "readDeadline.TryExpire()", "server expiry uses its absolute deadline");

                string connect = Between(
                    io,
                    "internal static bool TryConnect",
                    "public static bool TryReadFrame");
                ServiceHostAssert.True(
                    connect.IndexOf("cancellationToken.IsCancellationRequested", StringComparison.Ordinal)
                        < connect.IndexOf("ConnectNamedPipe", StringComparison.Ordinal),
                    "connect checks cancellation before the kernel call");

                string read = Between(
                    io,
                    "internal static int TryReadSome",
                    "internal static int TryWriteSome");
                ServiceHostAssert.True(
                    read.IndexOf("cancellationToken.IsCancellationRequested", StringComparison.Ordinal)
                        < read.IndexOf("ReadFile", StringComparison.Ordinal),
                    "read checks cancellation before the kernel call");

                string write = Between(
                    io,
                    "internal static int TryWriteSome",
                    "private static bool TryWait");
                ServiceHostAssert.True(
                    write.IndexOf("cancellationToken.IsCancellationRequested", StringComparison.Ordinal)
                        < write.IndexOf("WriteFile", StringComparison.Ordinal),
                    "write checks cancellation before the kernel call");
            });

            runner.Check("overlapped repair: an unproven completion keeps the event and buffer alive", delegate
            {
                string io = ReadSource("WindowsNamedPipeIo.cs");
                string context = Between(
                    io,
                    "internal sealed class WindowsOverlappedContext",
                    "internal sealed class WindowsOverlappedQuarantine");
                ServiceHostAssert.Contains(context, "Marshal.AllocHGlobal", "unmanaged storage");
                ServiceHostAssert.DoesNotContain(context, "GCHandle", "no movable managed pin");
                ServiceHostAssert.Contains(
                    context,
                    "quarantine.Hold(this);",
                    "unproven context is held");
                ServiceHostAssert.True(
                    context.IndexOf("quarantine.Hold(this)", StringComparison.Ordinal)
                        < context.IndexOf("ReleaseResources();", StringComparison.Ordinal),
                    "quarantine runs before a release");
                ServiceHostAssert.Contains(context, "StateOperating", "completion state");
                ServiceHostAssert.True(
                    context.IndexOf("quarantine.TryReserve()", StringComparison.Ordinal)
                        < context.IndexOf("native.CreateEventW(", StringComparison.Ordinal),
                    "capacity is reserved before the first kernel call");
                ServiceHostAssert.True(
                    context.IndexOf("native.CreateEventW(", StringComparison.Ordinal)
                        < context.IndexOf("Marshal.AllocHGlobal", StringComparison.Ordinal),
                    "the event is created before the unmanaged records");

                string quarantine = Between(
                    io,
                    "internal sealed class WindowsOverlappedQuarantine",
                    "internal sealed class WindowsPipeFrameSource");
                ServiceHostAssert.DoesNotContain(quarantine, "Free(", "quarantine frees no memory");
                ServiceHostAssert.DoesNotContain(quarantine, "CloseHandle", "quarantine closes no event");

                string pipeIo = From(io, "internal static class WindowsNamedPipeIo");
                ServiceHostAssert.DoesNotContain(pipeIo, "GCHandle", "only the context owns storage");
                ServiceHostAssert.DoesNotContain(pipeIo, "Marshal.FreeHGlobal", "the pipe path frees nothing");
            });

            runner.Check("overlapped repair: the client pipe close waits for the active frame call", delegate
            {
                string client = ReadSource("WindowsNamedPipeClient.cs");
                string connection = Between(
                    client,
                    "internal sealed class WindowsClientPipeConnection",
                    "// Opens the fixed pipe name");
                ServiceHostAssert.Contains(connection, "private readonly object ioLock", "io gate");
                string read = Between(
                    connection,
                    "public bool TryReadFrame",
                    "public bool TryWriteFrame");
                ServiceHostAssert.True(
                    read.IndexOf("lock (ioLock)", StringComparison.Ordinal)
                        < read.IndexOf("WindowsNamedPipeIo.TryReadFrame", StringComparison.Ordinal),
                    "read holds the gate");
                string write = Between(
                    connection,
                    "public bool TryWriteFrame",
                    "public bool TryGetServerProcessId");
                ServiceHostAssert.True(
                    write.IndexOf("lock (ioLock)", StringComparison.Ordinal)
                        < write.IndexOf("WindowsNamedPipeIo.TryWriteFrame", StringComparison.Ordinal),
                    "write holds the gate");
                string dispose = From(connection, "public void Dispose()");
                ServiceHostAssert.True(
                    dispose.IndexOf("lock (ioLock)", StringComparison.Ordinal)
                        < dispose.IndexOf("CloseHandle", StringComparison.Ordinal),
                    "close holds the gate");
                ServiceHostAssert.True(
                    dispose.IndexOf("disposed = true", StringComparison.Ordinal)
                        < dispose.IndexOf("CloseHandle", StringComparison.Ordinal),
                    "close refuses new calls before the handle close");
            });

            runner.Check("overlapped repair: the channel close waits for the active exchange", delegate
            {
                string channel = ReadSource("WindowsEngineServiceChannel.cs");
                string close = Between(
                    channel,
                    "public async Task CloseAsync()",
                    "public void Dispose()");
                ServiceHostAssert.True(
                    close.IndexOf("RequestClose();", StringComparison.Ordinal)
                        < close.IndexOf("requestGate.WaitAsync()", StringComparison.Ordinal),
                    "close refuses new requests before the gate wait");
                ServiceHostAssert.True(
                    close.IndexOf("requestGate.WaitAsync()", StringComparison.Ordinal)
                        < close.IndexOf("ClosePipeLocked();", StringComparison.Ordinal),
                    "close waits for the exchange before the pipe close");

                string dispose = Between(
                    channel,
                    "public void Dispose()",
                    "private void RequestClose()");
                ServiceHostAssert.True(
                    dispose.IndexOf("RequestClose();", StringComparison.Ordinal)
                        < dispose.IndexOf("requestGate.Wait();", StringComparison.Ordinal),
                    "dispose refuses new requests before the gate wait");
                ServiceHostAssert.True(
                    dispose.IndexOf("requestGate.Wait();", StringComparison.Ordinal)
                        < dispose.IndexOf("ClosePipeLocked();", StringComparison.Ordinal),
                    "dispose waits for the exchange before the pipe close");
            });

            runner.Check("overlapped repair: CloseAsync waits for the active exchange", delegate
            {
                RepairBlockingClientPipe pipe = new RepairBlockingClientPipe();
                WindowsEngineServiceChannel channel = NewChannel(pipe);
                Task<byte[]> exchange = Task.Run(delegate
                {
                    return channel.ExchangeAsync(
                        new byte[] { 1, 2, 3 },
                        CancellationToken.None);
                });
                try
                {
                    ServiceHostAssert.True(
                        pipe.ReadStarted.Wait(5000),
                        "the exchange reached the read");
                    Task close = channel.CloseAsync();
                    ServiceHostAssert.False(
                        close.Wait(250),
                        "close completed while the exchange was active");
                    ServiceHostAssert.Equal(0, pipe.DisposeCount, "pipe close during the exchange");

                    pipe.AllowRead.Set();
                    ServiceHostAssert.Wait(exchange, 5000, "exchange");
                    ServiceHostAssert.Wait(close, 5000, "close");
                    ServiceHostAssert.Equal(1, pipe.DisposeCount, "pipe close count");
                    ServiceHostAssert.False(
                        pipe.DisposedBeforeReadReleased,
                        "the pipe closed before the read returned");
                }
                finally
                {
                    pipe.AllowRead.Set();
                    try
                    {
                        exchange.Wait(5000);
                    }
                    catch (Exception)
                    {
                        // The assertions above already report the failure.
                    }
                    channel.Dispose();
                }
            });

            runner.Check("overlapped repair: Dispose waits for the active exchange", delegate
            {
                RepairBlockingClientPipe pipe = new RepairBlockingClientPipe();
                WindowsEngineServiceChannel channel = NewChannel(pipe);
                Task<byte[]> exchange = Task.Run(delegate
                {
                    return channel.ExchangeAsync(
                        new byte[] { 4, 5, 6 },
                        CancellationToken.None);
                });
                ManualResetEventSlim disposeStarted = new ManualResetEventSlim(false);
                Task dispose = null;
                try
                {
                    ServiceHostAssert.True(
                        pipe.ReadStarted.Wait(5000),
                        "the exchange reached the read");
                    dispose = Task.Run(delegate
                    {
                        disposeStarted.Set();
                        channel.Dispose();
                    });
                    ServiceHostAssert.True(
                        disposeStarted.Wait(5000),
                        "dispose started");
                    ServiceHostAssert.False(
                        dispose.Wait(250),
                        "dispose completed while the exchange was active");
                    ServiceHostAssert.Equal(0, pipe.DisposeCount, "pipe close during the exchange");

                    pipe.AllowRead.Set();
                    ServiceHostAssert.Wait(exchange, 5000, "exchange");
                    ServiceHostAssert.Wait(dispose, 5000, "dispose");
                    ServiceHostAssert.Equal(1, pipe.DisposeCount, "pipe close count");
                    ServiceHostAssert.False(
                        pipe.DisposedBeforeReadReleased,
                        "the pipe closed before the read returned");
                }
                finally
                {
                    pipe.AllowRead.Set();
                    try
                    {
                        exchange.Wait(5000);
                    }
                    catch (Exception)
                    {
                        // The assertions above already report the failure.
                    }
                    if (dispose != null)
                    {
                        try
                        {
                            dispose.Wait(5000);
                        }
                        catch (Exception)
                        {
                            // The assertions above already report the failure.
                        }
                    }
                    channel.Dispose();
                    disposeStarted.Dispose();
                }
            });
        }

        private static WindowsEngineServiceChannel NewChannel(RepairBlockingClientPipe pipe)
        {
            RepairEventSink events = new RepairEventSink();
            RepairScmInspector scm = new RepairScmInspector();
            EngineServiceServerProof proof = new EngineServiceServerProof(
                scm,
                events,
                ServiceImage);
            RepairClientPipeFactory factory = new RepairClientPipeFactory(pipe);
            return new WindowsEngineServiceChannel(factory, proof);
        }

        private static string ReadSource(string name)
        {
            string root = RepoRoot();
            ServiceHostAssert.True(root != null, "repo root");
            return File.ReadAllText(Path.Combine(
                root,
                "windows",
                "src",
                "HotspotShade.WinUI2.ServiceHost",
                name));
        }

        private static string Between(string text, string start, string end)
        {
            int first = text.IndexOf(start, StringComparison.Ordinal);
            ServiceHostAssert.True(first >= 0, "missing <" + start + ">");
            int last = text.IndexOf(end, first + start.Length, StringComparison.Ordinal);
            ServiceHostAssert.True(last > first, "missing <" + end + "> after <" + start + ">");
            return text.Substring(first, last - first);
        }

        private static string From(string text, string start)
        {
            int first = text.IndexOf(start, StringComparison.Ordinal);
            ServiceHostAssert.True(first >= 0, "missing <" + start + ">");
            return text.Substring(first);
        }

        private static string RepoRoot()
        {
            string configured = Environment.GetEnvironmentVariable("HOTSPOTSHADE_REPO_ROOT");
            if (!string.IsNullOrEmpty(configured)
                && Directory.Exists(Path.Combine(configured, "windows")))
            {
                return configured;
            }
            string directory = Directory.GetCurrentDirectory();
            while (!string.IsNullOrEmpty(directory))
            {
                if (Directory.Exists(Path.Combine(directory, "rust"))
                    && Directory.Exists(Path.Combine(directory, "windows")))
                {
                    return directory;
                }
                DirectoryInfo parent = Directory.GetParent(directory);
                directory = parent == null ? null : parent.FullName;
            }
            return null;
        }

        private sealed class RepairBlockingClientPipe : IEngineServiceClientPipe
        {
            public readonly ManualResetEventSlim ReadStarted =
                new ManualResetEventSlim(false);
            public readonly ManualResetEventSlim AllowRead =
                new ManualResetEventSlim(false);
            private int disposeCount;
            public bool DisposedBeforeReadReleased;

            public int DisposeCount
            {
                get { return Volatile.Read(ref disposeCount); }
            }

            public bool TryReadFrame(
                TimeSpan budget,
                CancellationToken cancellationToken,
                out byte[] frame,
                out EngineServiceFrameReadOutcome outcome,
                out string code)
            {
                ReadStarted.Set();
                AllowRead.Wait(5000);
                if (Volatile.Read(ref disposeCount) != 0)
                {
                    DisposedBeforeReadReleased = true;
                }
                frame = new byte[] { 9 };
                outcome = EngineServiceFrameReadOutcome.Frame;
                code = "";
                return true;
            }

            public bool TryWriteFrame(
                byte[] frame,
                TimeSpan budget,
                CancellationToken cancellationToken,
                out string code)
            {
                code = "";
                return true;
            }

            public bool TryGetServerProcessId(out int processId)
            {
                processId = 700;
                return true;
            }

            public bool TryGetOwnerSid(out string sid)
            {
                sid = EngineServiceBoundary.SystemSid;
                return true;
            }

            public void Dispose()
            {
                Interlocked.Increment(ref disposeCount);
            }
        }

        private sealed class RepairClientPipeFactory : IEngineServiceClientPipeFactory
        {
            private readonly IEngineServiceClientPipe pipe;

            public RepairClientPipeFactory(IEngineServiceClientPipe pipe)
            {
                this.pipe = pipe;
            }

            public bool TryOpen(out IEngineServiceClientPipe opened, out string code)
            {
                opened = pipe;
                code = "";
                return opened != null;
            }
        }

        private sealed class RepairScmInspector : IEngineServiceScmInspector
        {
            public bool TryQuery(out EngineServiceScmState state, out string code)
            {
                state = new EngineServiceScmState(
                    EngineServiceBoundary.ServiceName,
                    700,
                    4,
                    "\"" + ServiceImage + "\" --instance sample");
                code = "";
                return true;
            }
        }

        private sealed class RepairEventSink : IEngineServiceEventSink
        {
            public void Record(string eventCode)
            {
            }
        }
    }
}
