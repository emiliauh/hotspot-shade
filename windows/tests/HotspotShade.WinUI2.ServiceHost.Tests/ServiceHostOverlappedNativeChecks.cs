using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost.Tests
{
    // Hermetic checks for the overlapped I/O state machine. They use the
    // native seam fakery, so they open no pipe, call no Win32 function, and
    // run on a non-Windows host.
    internal static class ServiceHostOverlappedNativeChecks
    {
        public static void Run(ServiceHostCheckRunner runner)
        {
            runner.Check("overlapped native: a pending read completes through unmanaged storage", delegate
            {
                SeamNative native = new SeamNative();
                native.ReadResult = false;
                native.ReadError = WindowsPipeNativeMethods.ErrorIoPending;
                native.GetResult = true;
                native.AsyncTransferred = 4;
                native.AsyncPayload = new byte[] { 9, 8, 7, 6 };
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                SeamClock clock = new SeamClock();
                WindowsPipeIoEnvironment environment = NewEnvironment(native, quarantine, clock);
                byte[] buffer = new byte[8];
                string code;

                int read = WindowsNamedPipeIo.TryReadSome(
                    new IntPtr(1),
                    buffer,
                    2,
                    4,
                    clock.Now + TimeSpan.FromSeconds(1),
                    CancellationToken.None,
                    out code,
                    environment);

                ServiceHostAssert.Equal(4, read, "bytes");
                ServiceHostAssert.Equal("", code, "code");
                ServiceHostAssert.Equal((byte)9, buffer[2], "first byte");
                ServiceHostAssert.Equal((byte)6, buffer[5], "last byte");
                ServiceHostAssert.Equal(1, native.ReadCalls, "one read");
                ServiceHostAssert.Equal(1, native.GetOverlappedCalls, "one result");
                ServiceHostAssert.Equal(1, native.CloseCalls, "event closed after proof");
                ServiceHostAssert.Equal(0, quarantine.HeldCount, "nothing quarantined");
                ServiceHostAssert.Equal(0, quarantine.ReservedCount, "reservation released");
                ServiceHostAssert.True(
                    native.LastOverlapped != IntPtr.Zero,
                    "kernel call received an overlapped address");
            });

            runner.Check("overlapped native: a pending connect completes through the event", delegate
            {
                SeamNative native = new SeamNative();
                native.ConnectResult = false;
                native.ConnectError = WindowsPipeNativeMethods.ErrorIoPending;
                native.GetResult = true;
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                SeamClock clock = new SeamClock();
                WindowsPipeIoEnvironment environment = NewEnvironment(native, quarantine, clock);
                string code;

                bool connected = WindowsNamedPipeIo.TryConnect(
                    new IntPtr(1),
                    TimeSpan.FromSeconds(1),
                    CancellationToken.None,
                    out code,
                    environment);

                ServiceHostAssert.True(connected, "connected");
                ServiceHostAssert.Equal("", code, "code");
                ServiceHostAssert.Equal(1, native.ConnectCalls, "one connect");
                ServiceHostAssert.Equal(1, native.WaitCalls, "one event wait");
                ServiceHostAssert.Equal(1, native.CloseCalls, "event closed after proof");
                ServiceHostAssert.Equal(0, quarantine.ReservedCount, "reservation released");
            });

            runner.Check("overlapped native: a synchronous read completes and copies its bytes", delegate
            {
                SeamNative native = new SeamNative();
                native.ReadResult = true;
                native.ReadPayload = new byte[] { 1, 2, 3 };
                native.Transferred = 3;
                native.GetResult = true;
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                SeamClock clock = new SeamClock();
                WindowsPipeIoEnvironment environment = NewEnvironment(native, quarantine, clock);
                byte[] buffer = new byte[4];
                string code;

                int read = WindowsNamedPipeIo.TryReadSome(
                    new IntPtr(1),
                    buffer,
                    0,
                    3,
                    clock.Now + TimeSpan.FromSeconds(1),
                    CancellationToken.None,
                    out code,
                    environment);

                ServiceHostAssert.Equal(3, read, "bytes");
                ServiceHostAssert.Equal((byte)2, buffer[1], "copied byte");
                ServiceHostAssert.Equal(1, native.CloseCalls, "event closed");
                ServiceHostAssert.Equal(0, quarantine.ReservedCount, "reservation released");
            });

            runner.Check("overlapped native: a synchronous broken-pipe read is a clean end of stream", delegate
            {
                SeamNative native = new SeamNative();
                native.ReadResult = false;
                native.ReadError = WindowsPipeNativeMethods.ErrorBrokenPipe;
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                SeamClock clock = new SeamClock();
                WindowsPipeIoEnvironment environment = NewEnvironment(native, quarantine, clock);
                string code;
                bool zeroTransferProven;

                int read = WindowsNamedPipeIo.TryReadSome(
                    new IntPtr(1),
                    new byte[4],
                    0,
                    4,
                    clock.Now + TimeSpan.FromSeconds(1),
                    CancellationToken.None,
                    out code,
                    out zeroTransferProven,
                    environment);

                ServiceHostAssert.Equal(-2, read, "failed read");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.BadResponse, code, "code");
                ServiceHostAssert.False(zeroTransferProven, "a synchronous failure does not prove a count");
                ServiceHostAssert.Equal(1, native.ReadCalls, "one read");
                ServiceHostAssert.Equal(1, native.CloseCalls, "event closed after proof");
                ServiceHostAssert.Equal(0, quarantine.HeldCount, "no quarantine");
                ServiceHostAssert.Equal(0, quarantine.ReservedCount, "reservation released");
            });

            runner.Check("overlapped native: a synchronous aborted read has an unknown count", delegate
            {
                SeamNative native = new SeamNative();
                native.ReadResult = false;
                native.ReadError = WindowsPipeNativeMethods.ErrorOperationAborted;
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                SeamClock clock = new SeamClock();
                WindowsPipeIoEnvironment environment = NewEnvironment(native, quarantine, clock);
                string code;
                bool zeroTransferProven;

                int read = WindowsNamedPipeIo.TryReadSome(
                    new IntPtr(1),
                    new byte[4],
                    0,
                    4,
                    clock.Now + TimeSpan.FromSeconds(1),
                    CancellationToken.None,
                    out code,
                    out zeroTransferProven,
                    environment);

                ServiceHostAssert.Equal(-1, read, "timeout result");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Timeout, code, "code");
                ServiceHostAssert.False(zeroTransferProven, "transfer count unknown");
                ServiceHostAssert.Equal(1, native.CloseCalls, "event closed after proof");
                ServiceHostAssert.Equal(0, quarantine.HeldCount, "no quarantine");
                ServiceHostAssert.Equal(0, quarantine.ReservedCount, "reservation released");
            });

            runner.Check("overlapped native: a synchronous unknown read failure has an unknown count", delegate
            {
                SeamNative native = new SeamNative();
                native.ReadResult = false;
                native.ReadError = 1234;
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                SeamClock clock = new SeamClock();
                WindowsPipeIoEnvironment environment = NewEnvironment(native, quarantine, clock);
                string code;
                bool zeroTransferProven;

                int read = WindowsNamedPipeIo.TryReadSome(
                    new IntPtr(1),
                    new byte[4],
                    0,
                    4,
                    clock.Now + TimeSpan.FromSeconds(1),
                    CancellationToken.None,
                    out code,
                    out zeroTransferProven,
                    environment);

                ServiceHostAssert.Equal(-2, read, "read refused");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.EngineUnavailable, code, "code");
                ServiceHostAssert.False(zeroTransferProven, "transfer count unknown");
                ServiceHostAssert.Equal(1, native.CloseCalls, "event closed after proof");
                ServiceHostAssert.Equal(0, quarantine.HeldCount, "no quarantine");
                ServiceHostAssert.Equal(0, quarantine.ReservedCount, "reservation released");
            });

            runner.Check("overlapped native: a pending write copies its frame and completes", delegate
            {
                SeamNative native = new SeamNative();
                native.WriteResult = false;
                native.WriteError = WindowsPipeNativeMethods.ErrorIoPending;
                native.GetResult = true;
                native.AsyncTransferred = 3;
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                SeamClock clock = new SeamClock();
                WindowsPipeIoEnvironment environment = NewEnvironment(native, quarantine, clock);
                string code;

                int written = WindowsNamedPipeIo.TryWriteSome(
                    new IntPtr(1),
                    new byte[] { 4, 5, 6 },
                    0,
                    3,
                    clock.Now + TimeSpan.FromSeconds(1),
                    CancellationToken.None,
                    environment,
                    out code);

                ServiceHostAssert.Equal(3, written, "bytes");
                ServiceHostAssert.Equal("", code, "code");
                ServiceHostAssert.Equal(1, native.WriteCalls, "one write");
                ServiceHostAssert.True(native.LastWritePayload != null, "frame copied to unmanaged storage");
                ServiceHostAssert.Equal((byte)4, native.LastWritePayload[0], "first frame byte");
                ServiceHostAssert.Equal((byte)6, native.LastWritePayload[2], "last frame byte");
                ServiceHostAssert.Equal(1, native.CloseCalls, "event closed after proof");
                ServiceHostAssert.Equal(0, quarantine.ReservedCount, "reservation released");
            });

            runner.Check("overlapped native: ERROR_IO_INCOMPLETE never proves completion", delegate
            {
                SeamNative native = new SeamNative();
                native.ReadResult = false;
                native.ReadError = WindowsPipeNativeMethods.ErrorIoPending;
                native.GetResult = false;
                native.GetError = WindowsPipeNativeMethods.ErrorIoIncomplete;
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                SeamClock clock = new SeamClock();
                WindowsPipeIoEnvironment environment = NewEnvironment(native, quarantine, clock);
                string code;

                int read = WindowsNamedPipeIo.TryReadSome(
                    new IntPtr(1),
                    new byte[4],
                    0,
                    4,
                    clock.Now + TimeSpan.FromSeconds(1),
                    CancellationToken.None,
                    out code,
                    environment);

                ServiceHostAssert.Equal(-2, read, "read refused");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.EngineUnavailable, code, "code");
                ServiceHostAssert.Equal(1, quarantine.HeldCount, "context held");
                ServiceHostAssert.Equal(0, quarantine.ReservedCount, "reservation became held");
                ServiceHostAssert.Equal(
                    WindowsOverlappedQuarantine.DiagnosticCompletionUnproven,
                    quarantine.LastDiagnostic,
                    "fixed diagnostic");
                ServiceHostAssert.Equal(0, native.CloseCalls, "unproven event is never closed");
                ServiceHostAssert.Equal(1, native.CancelCalls, "cancel requested once");
                ServiceHostAssert.True(native.GetOverlappedCalls >= 1, "result collected");
            });

            runner.Check("overlapped native: a direct ERROR_IO_INCOMPLETE result is not completion", delegate
            {
                SeamNative native = new SeamNative();
                native.ReadResult = false;
                native.ReadError = WindowsPipeNativeMethods.ErrorIoIncomplete;
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                SeamClock clock = new SeamClock();
                WindowsPipeIoEnvironment environment = NewEnvironment(native, quarantine, clock);
                string code;

                int read = WindowsNamedPipeIo.TryReadSome(
                    new IntPtr(1),
                    new byte[4],
                    0,
                    4,
                    clock.Now + TimeSpan.FromSeconds(1),
                    CancellationToken.None,
                    out code,
                    environment);

                ServiceHostAssert.Equal(-2, read, "read refused");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.EngineUnavailable, code, "code");
                ServiceHostAssert.Equal(1, quarantine.HeldCount, "context held");
                ServiceHostAssert.Equal(0, native.CloseCalls, "incomplete event is never closed");
            });

            runner.Check("overlapped native: an unknown completion result fails closed", delegate
            {
                SeamNative native = new SeamNative();
                native.ReadResult = false;
                native.ReadError = WindowsPipeNativeMethods.ErrorIoPending;
                native.GetResult = false;
                native.GetError = 1234;
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                SeamClock clock = new SeamClock();
                WindowsPipeIoEnvironment environment = NewEnvironment(native, quarantine, clock);
                string code;

                int read = WindowsNamedPipeIo.TryReadSome(
                    new IntPtr(1),
                    new byte[4],
                    0,
                    4,
                    clock.Now + TimeSpan.FromSeconds(1),
                    CancellationToken.None,
                    out code,
                    environment);

                ServiceHostAssert.Equal(-2, read, "read refused");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.EngineUnavailable, code, "code");
                ServiceHostAssert.Equal(1, quarantine.HeldCount, "unknown result held");
                ServiceHostAssert.Equal(0, native.CloseCalls, "unknown result is not released");
            });

            runner.Check("overlapped native: a canceled pending read proves completion before release", delegate
            {
                SeamNative native = new SeamNative();
                native.ReadResult = false;
                native.ReadError = WindowsPipeNativeMethods.ErrorIoPending;
                native.GetResult = false;
                native.GetError = WindowsPipeNativeMethods.ErrorOperationAborted;
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                SeamClock clock = new SeamClock();
                WindowsPipeIoEnvironment environment = NewEnvironment(native, quarantine, clock);
                CancellationTokenSource source = new CancellationTokenSource();
                native.WaitResults.Enqueue(WindowsPipeNativeMethods.WaitTimeout);
                native.OnWait = delegate { source.Cancel(); };
                string code;

                int read = WindowsNamedPipeIo.TryReadSome(
                    new IntPtr(1),
                    new byte[4],
                    0,
                    4,
                    clock.Now + TimeSpan.FromSeconds(1),
                    source.Token,
                    out code,
                    environment);

                ServiceHostAssert.Equal(-1, read, "canceled");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Timeout, code, "timeout code");
                ServiceHostAssert.Equal(1, native.CancelCalls, "cancel requested");
                ServiceHostAssert.Equal(1, native.CloseCalls, "completion proof allows release");
                ServiceHostAssert.Equal(0, quarantine.HeldCount, "nothing held");
                ServiceHostAssert.Equal(0, quarantine.ReservedCount, "reservation released");
                source.Dispose();
            });

            runner.Check("overlapped native: a pre-canceled operation starts no kernel call", delegate
            {
                SeamNative native = new SeamNative();
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                SeamClock clock = new SeamClock();
                WindowsPipeIoEnvironment environment = NewEnvironment(native, quarantine, clock);
                CancellationTokenSource source = new CancellationTokenSource();
                source.Cancel();
                string code;

                bool connected = WindowsNamedPipeIo.TryConnect(
                    new IntPtr(1),
                    TimeSpan.FromSeconds(1),
                    source.Token,
                    out code,
                    environment);
                ServiceHostAssert.False(connected, "connect canceled");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Timeout, code, "connect code");

                int read = WindowsNamedPipeIo.TryReadSome(
                    new IntPtr(1),
                    new byte[4],
                    0,
                    4,
                    clock.Now + TimeSpan.FromSeconds(1),
                    source.Token,
                    out code,
                    environment);
                ServiceHostAssert.Equal(-1, read, "read canceled");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Timeout, code, "read code");

                int write = WindowsNamedPipeIo.TryWriteSome(
                    new IntPtr(1),
                    new byte[] { 1, 2, 3 },
                    0,
                    3,
                    clock.Now + TimeSpan.FromSeconds(1),
                    source.Token,
                    environment,
                    out code);
                ServiceHostAssert.Equal(-1, write, "write canceled");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Timeout, code, "write code");

                int expiredRead = WindowsNamedPipeIo.TryReadSome(
                    new IntPtr(1),
                    new byte[4],
                    0,
                    4,
                    clock.Now - TimeSpan.FromSeconds(1),
                    CancellationToken.None,
                    out code,
                    environment);
                ServiceHostAssert.Equal(-1, expiredRead, "read expired");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Timeout, code, "expired read code");

                int expiredWrite = WindowsNamedPipeIo.TryWriteSome(
                    new IntPtr(1),
                    new byte[] { 1 },
                    0,
                    1,
                    clock.Now - TimeSpan.FromSeconds(1),
                    CancellationToken.None,
                    environment,
                    out code);
                ServiceHostAssert.Equal(-1, expiredWrite, "write expired");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Timeout, code, "expired write code");

                ServiceHostAssert.Equal(0, native.ConnectCalls, "no connect call");
                ServiceHostAssert.Equal(0, native.ReadCalls, "no read call");
                ServiceHostAssert.Equal(0, native.WriteCalls, "no write call");
                ServiceHostAssert.Equal(0, native.CreateEventCalls, "no event created");
                ServiceHostAssert.Equal(0, native.CancelCalls, "no cancel needed");
                ServiceHostAssert.Equal(0, quarantine.ReservedCount, "nothing reserved");
                ServiceHostAssert.Equal(0, quarantine.HeldCount, "nothing held");
                source.Dispose();
            });

            runner.Check("overlapped native: an expired deadline cancels and waits for proof", delegate
            {
                SeamNative native = new SeamNative();
                native.ReadResult = false;
                native.ReadError = WindowsPipeNativeMethods.ErrorIoPending;
                native.GetResult = false;
                native.GetError = WindowsPipeNativeMethods.ErrorOperationAborted;
                native.WaitResults.Enqueue(WindowsPipeNativeMethods.WaitTimeout);
                native.WaitResults.Enqueue(WindowsPipeNativeMethods.WaitObject0);
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                SeamClock clock = new SeamClock();
                native.OnWait = delegate { clock.Advance(TimeSpan.FromSeconds(2)); };
                WindowsPipeIoEnvironment environment = NewEnvironment(native, quarantine, clock);
                string code;

                int read = WindowsNamedPipeIo.TryReadSome(
                    new IntPtr(1),
                    new byte[4],
                    0,
                    4,
                    clock.Now + TimeSpan.FromSeconds(1),
                    CancellationToken.None,
                    out code,
                    environment);

                ServiceHostAssert.Equal(-1, read, "timed out");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Timeout, code, "timeout code");
                ServiceHostAssert.Equal(1, native.CancelCalls, "cancel requested");
                ServiceHostAssert.True(native.WaitCalls >= 2, "deadline wait and proof wait");
                ServiceHostAssert.Equal(1, native.CloseCalls, "proof allows release");
                ServiceHostAssert.Equal(0, quarantine.HeldCount, "nothing held");
            });

            runner.Check("overlapped native: an aborted read does not prove an idle transfer", delegate
            {
                SeamNative native = new SeamNative();
                native.ReadResult = false;
                native.ReadError = WindowsPipeNativeMethods.ErrorIoPending;
                native.GetResult = false;
                native.GetError = WindowsPipeNativeMethods.ErrorOperationAborted;
                native.WaitResults.Enqueue(WindowsPipeNativeMethods.WaitTimeout);
                native.WaitResults.Enqueue(WindowsPipeNativeMethods.WaitObject0);
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                SeamClock clock = new SeamClock();
                native.OnWait = delegate { clock.Advance(TimeSpan.FromSeconds(2)); };
                WindowsPipeIoEnvironment environment = NewEnvironment(native, quarantine, clock);
                string code;
                bool zeroTransferProven;

                int read = WindowsNamedPipeIo.TryReadSome(
                    new IntPtr(1),
                    new byte[4],
                    0,
                    4,
                    clock.Now + TimeSpan.FromSeconds(1),
                    CancellationToken.None,
                    out code,
                    out zeroTransferProven,
                    environment);

                ServiceHostAssert.Equal(-1, read, "timed out");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Timeout, code, "timeout code");
                ServiceHostAssert.False(zeroTransferProven, "failed count is unknown");
                ServiceHostAssert.Equal(0, quarantine.HeldCount, "nothing held");
                ServiceHostAssert.Equal(1, native.CloseCalls, "proof allows release");

                // The frame layer can report Idle when an expired
                // budget starts no kernel operation and consumes no byte.
                WindowsPipeFrameSource source = new WindowsPipeFrameSource(
                    new IntPtr(1),
                    clock.Now - TimeSpan.FromMilliseconds(1),
                    WindowsNamedPipeIo.CreateMonotonicDeadline(TimeSpan.FromSeconds(30)),
                    CancellationToken.None,
                    environment);
                byte[] frame;
                EngineServiceFrameReadOutcome outcome;
                ServiceHostAssert.False(
                    EngineServiceBoundedFrameReader.TryReadFrame(
                        source,
                        out frame,
                        out outcome,
                        out code),
                    "idle read");
                ServiceHostAssert.Equal(
                    EngineServiceFrameReadOutcome.Idle,
                    outcome,
                    "idle outcome");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Timeout, code, "idle code");
            });

            runner.Check("overlapped native: a cancel race that completed with bytes is not idle", delegate
            {
                SeamNative native = new SeamNative();
                native.ReadResult = false;
                native.ReadError = WindowsPipeNativeMethods.ErrorIoPending;
                native.GetResult = true;
                native.AsyncTransferred = 4;
                native.AsyncPayload = new byte[] { 1, 2, 3, 4 };
                native.WaitResults.Enqueue(WindowsPipeNativeMethods.WaitTimeout);
                native.WaitResults.Enqueue(WindowsPipeNativeMethods.WaitObject0);
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                SeamClock clock = new SeamClock();
                native.OnWait = delegate { clock.Advance(TimeSpan.FromSeconds(2)); };
                WindowsPipeIoEnvironment environment = NewEnvironment(native, quarantine, clock);
                string code;
                bool zeroTransferProven;

                int read = WindowsNamedPipeIo.TryReadSome(
                    new IntPtr(1),
                    new byte[4],
                    0,
                    4,
                    clock.Now + TimeSpan.FromSeconds(1),
                    CancellationToken.None,
                    out code,
                    out zeroTransferProven,
                    environment);

                ServiceHostAssert.Equal(-1, read, "timed out");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Timeout, code, "timeout code");
                ServiceHostAssert.False(
                    zeroTransferProven,
                    "a completed transfer is not a zero-byte proof");
                ServiceHostAssert.Equal(0, quarantine.HeldCount, "proven completion is released");
                ServiceHostAssert.Equal(1, native.CloseCalls, "event closed after the proof");

                // Re-arm the seam for the frame-layer read. The first wait
                // times out and advances the clock past the wall deadline, so
                // the abort completes with four bytes.
                native.WaitResults.Enqueue(WindowsPipeNativeMethods.WaitTimeout);
                WindowsPipeFrameSource source = new WindowsPipeFrameSource(
                    new IntPtr(1),
                    clock.Now + TimeSpan.FromSeconds(1),
                    WindowsNamedPipeIo.CreateMonotonicDeadline(TimeSpan.FromSeconds(30)),
                    CancellationToken.None,
                    environment);
                byte[] frame;
                EngineServiceFrameReadOutcome outcome;
                ServiceHostAssert.False(
                    EngineServiceBoundedFrameReader.TryReadFrame(
                        source,
                        out frame,
                        out outcome,
                        out code),
                    "race read");
                ServiceHostAssert.Equal(
                    EngineServiceFrameReadOutcome.Unknown,
                    outcome,
                    "a consumed transfer with no frame is unknown");
            });

            runner.Check("overlapped native: a failed completion cannot prove an idle read", delegate
            {
                SeamNative native = new SeamNative();
                native.ReadResult = false;
                native.ReadError = WindowsPipeNativeMethods.ErrorIoPending;
                native.GetResult = false;
                native.GetError = WindowsPipeNativeMethods.ErrorOperationAborted;
                native.GetCountKnown = true;
                native.AsyncTransferred = 3;
                native.WaitResults.Enqueue(WindowsPipeNativeMethods.WaitTimeout);
                native.WaitResults.Enqueue(WindowsPipeNativeMethods.WaitObject0);
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                SeamClock clock = new SeamClock();
                native.OnWait = delegate { clock.Advance(TimeSpan.FromSeconds(2)); };
                WindowsPipeIoEnvironment environment = NewEnvironment(native, quarantine, clock);
                string code;
                bool zeroTransferProven;

                int read = WindowsNamedPipeIo.TryReadSome(
                    new IntPtr(1),
                    new byte[4],
                    0,
                    4,
                    clock.Now + TimeSpan.FromSeconds(1),
                    CancellationToken.None,
                    out code,
                    out zeroTransferProven,
                    environment);

                // The fake offers a positive count for a failed completion.
                // That count is not proven, so zero transfer is not proven.
                ServiceHostAssert.Equal(-1, read, "timeout result");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Timeout, code, "code");
                ServiceHostAssert.False(zeroTransferProven, "zero transfer is unproven");
                ServiceHostAssert.Equal(1, native.CloseCalls, "proven completion is released");
                ServiceHostAssert.Equal(0, quarantine.HeldCount, "nothing held");

                // The frame layer must not turn that read into Idle.
                native.WaitResults.Enqueue(WindowsPipeNativeMethods.WaitTimeout);
                native.WaitResults.Enqueue(WindowsPipeNativeMethods.WaitObject0);
                WindowsPipeFrameSource source = new WindowsPipeFrameSource(
                    new IntPtr(1),
                    clock.Now + TimeSpan.FromSeconds(1),
                    WindowsNamedPipeIo.CreateMonotonicDeadline(TimeSpan.FromSeconds(30)),
                    CancellationToken.None,
                    environment);
                byte[] frame;
                EngineServiceFrameReadOutcome outcome;
                ServiceHostAssert.False(
                    EngineServiceBoundedFrameReader.TryReadFrame(
                        source,
                        out frame,
                        out outcome,
                        out code),
                    "partial read");
                ServiceHostAssert.Equal(
                    EngineServiceFrameReadOutcome.Unknown,
                    outcome,
                    "an unproven transfer is not an idle read");
            });

            runner.Check("overlapped native: an unknown read count is never idle", delegate
            {
                SeamNative native = new SeamNative();
                native.ReadResult = false;
                native.ReadError = WindowsPipeNativeMethods.ErrorIoPending;
                native.GetResult = false;
                native.GetError = WindowsPipeNativeMethods.ErrorOperationAborted;
                native.GetCountKnown = false;
                native.AsyncTransferred = 0;
                native.WaitResults.Enqueue(WindowsPipeNativeMethods.WaitTimeout);
                native.WaitResults.Enqueue(WindowsPipeNativeMethods.WaitObject0);
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                SeamClock clock = new SeamClock();
                native.OnWait = delegate { clock.Advance(TimeSpan.FromSeconds(2)); };
                WindowsPipeIoEnvironment environment = NewEnvironment(native, quarantine, clock);
                string code;
                bool zeroTransferProven;

                int read = WindowsNamedPipeIo.TryReadSome(
                    new IntPtr(1),
                    new byte[4],
                    0,
                    4,
                    clock.Now + TimeSpan.FromSeconds(1),
                    CancellationToken.None,
                    out code,
                    out zeroTransferProven,
                    environment);

                ServiceHostAssert.Equal(-1, read, "timeout result");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Timeout, code, "code");
                ServiceHostAssert.False(
                    zeroTransferProven,
                    "an undefined count is not a zero transfer");
                ServiceHostAssert.Equal(1, native.CloseCalls, "proven completion is released");
                ServiceHostAssert.Equal(0, quarantine.HeldCount, "nothing held");

                native.WaitResults.Enqueue(WindowsPipeNativeMethods.WaitTimeout);
                native.WaitResults.Enqueue(WindowsPipeNativeMethods.WaitObject0);
                WindowsPipeFrameSource source = new WindowsPipeFrameSource(
                    new IntPtr(1),
                    clock.Now + TimeSpan.FromSeconds(1),
                    WindowsNamedPipeIo.CreateMonotonicDeadline(TimeSpan.FromSeconds(30)),
                    CancellationToken.None,
                    environment);
                byte[] frame;
                EngineServiceFrameReadOutcome outcome;
                ServiceHostAssert.False(
                    EngineServiceBoundedFrameReader.TryReadFrame(
                        source,
                        out frame,
                        out outcome,
                        out code),
                    "unproven transfer");
                ServiceHostAssert.Equal(
                    EngineServiceFrameReadOutcome.Unknown,
                    outcome,
                    "an unknown count is not an idle read");
            });

            runner.Check("overlapped native: a failed completion cannot prove an idle read", delegate
            {
                SeamNative native = new SeamNative();
                native.ReadResult = false;
                native.ReadError = WindowsPipeNativeMethods.ErrorIoPending;
                native.GetResult = false;
                native.GetError = WindowsPipeNativeMethods.ErrorOperationAborted;
                native.GetCountKnown = true;
                native.AsyncTransferred = 0;
                native.WaitResults.Enqueue(WindowsPipeNativeMethods.WaitTimeout);
                native.WaitResults.Enqueue(WindowsPipeNativeMethods.WaitObject0);
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                SeamClock clock = new SeamClock();
                native.OnWait = delegate { clock.Advance(TimeSpan.FromSeconds(2)); };
                WindowsPipeIoEnvironment environment = NewEnvironment(native, quarantine, clock);
                string code;
                bool zeroTransferProven;

                int read = WindowsNamedPipeIo.TryReadSome(
                    new IntPtr(1),
                    new byte[4],
                    0,
                    4,
                    clock.Now + TimeSpan.FromSeconds(1),
                    CancellationToken.None,
                    out code,
                    out zeroTransferProven,
                    environment);

                ServiceHostAssert.Equal(-1, read, "timeout result");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Timeout, code, "code");
                ServiceHostAssert.False(zeroTransferProven, "failed count is undefined");

                native.WaitResults.Enqueue(WindowsPipeNativeMethods.WaitTimeout);
                native.WaitResults.Enqueue(WindowsPipeNativeMethods.WaitObject0);
                WindowsPipeFrameSource source = new WindowsPipeFrameSource(
                    new IntPtr(1),
                    clock.Now + TimeSpan.FromSeconds(1),
                    WindowsNamedPipeIo.CreateMonotonicDeadline(TimeSpan.FromSeconds(30)),
                    CancellationToken.None,
                    environment);
                byte[] frame;
                EngineServiceFrameReadOutcome outcome;
                ServiceHostAssert.False(
                    EngineServiceBoundedFrameReader.TryReadFrame(
                        source,
                        out frame,
                        out outcome,
                        out code),
                    "idle read");
                ServiceHostAssert.Equal(
                    EngineServiceFrameReadOutcome.Unknown,
                    outcome,
                    "a failed completion leaves the stream position unknown");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.EngineUnavailable, code, "unknown read code");
            });

            runner.Check("overlapped native: an aborted partial write is unproven", delegate
            {
                SeamNative native = new SeamNative();
                native.WriteResult = false;
                native.WriteError = WindowsPipeNativeMethods.ErrorIoPending;
                native.GetResult = false;
                native.GetError = WindowsPipeNativeMethods.ErrorOperationAborted;
                native.GetCountKnown = true;
                native.AsyncTransferred = 5;
                native.WaitResults.Enqueue(WindowsPipeNativeMethods.WaitTimeout);
                native.WaitResults.Enqueue(WindowsPipeNativeMethods.WaitObject0);
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                SeamClock clock = new SeamClock();
                native.OnWait = delegate { clock.Advance(TimeSpan.FromSeconds(2)); };
                WindowsPipeIoEnvironment environment = NewEnvironment(native, quarantine, clock);
                string code;
                EngineServiceRequestWriteProof proof;

                bool written = WindowsNamedPipeIo.TryWriteFrame(
                    new IntPtr(1),
                    new byte[10],
                    TimeSpan.FromSeconds(1),
                    CancellationToken.None,
                    out code,
                    out proof,
                    environment);

                ServiceHostAssert.False(written, "the write failed");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Timeout, code, "timeout code");
                ServiceHostAssert.Equal(
                    EngineServiceRequestWriteProof.Unproven,
                    proof,
                    "five bytes may have reached the pipe");
                ServiceHostAssert.Equal(1, native.CloseCalls, "proven completion is released");
                ServiceHostAssert.Equal(0, quarantine.HeldCount, "nothing held");
            });

            runner.Check("overlapped native: an aborted write with a zero out count is unproven", delegate
            {
                SeamNative native = new SeamNative();
                native.WriteResult = false;
                native.WriteError = WindowsPipeNativeMethods.ErrorIoPending;
                native.GetResult = false;
                native.GetError = WindowsPipeNativeMethods.ErrorOperationAborted;
                native.GetCountKnown = true;
                native.AsyncTransferred = 0;
                native.WaitResults.Enqueue(WindowsPipeNativeMethods.WaitTimeout);
                native.WaitResults.Enqueue(WindowsPipeNativeMethods.WaitObject0);
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                SeamClock clock = new SeamClock();
                native.OnWait = delegate { clock.Advance(TimeSpan.FromSeconds(2)); };
                WindowsPipeIoEnvironment environment = NewEnvironment(native, quarantine, clock);
                string code;
                EngineServiceRequestWriteProof proof;

                bool written = WindowsNamedPipeIo.TryWriteFrame(
                    new IntPtr(1),
                    new byte[10],
                    TimeSpan.FromSeconds(1),
                    CancellationToken.None,
                    out code,
                    out proof,
                    environment);

                ServiceHostAssert.False(written, "the write failed");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Timeout, code, "timeout code");
                ServiceHostAssert.Equal(
                    EngineServiceRequestWriteProof.Unproven,
                    proof,
                    "failed count cannot prove no delivery");
                ServiceHostAssert.Equal(0, quarantine.HeldCount, "nothing held");
            });

            runner.Check("overlapped native: an immediate failed write has unknown delivery", delegate
            {
                SeamNative native = new SeamNative();
                native.WriteResult = false;
                native.WriteError = WindowsPipeNativeMethods.ErrorBrokenPipe;
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                SeamClock clock = new SeamClock();
                string code;
                EngineServiceRequestWriteProof proof;
                bool written = WindowsNamedPipeIo.TryWriteFrame(
                    new IntPtr(1), new byte[4], TimeSpan.FromSeconds(1),
                    CancellationToken.None, out code, out proof,
                    NewEnvironment(native, quarantine, clock));
                ServiceHostAssert.False(written, "write failed");
                ServiceHostAssert.Equal(EngineServiceRequestWriteProof.Unproven, proof, "delivery unknown");
                ServiceHostAssert.Equal(1, native.CloseCalls, "completed operation released");
                ServiceHostAssert.Equal(0, quarantine.HeldCount, "nothing held");
            });

            runner.Check("overlapped native: a pre-canceled write starts nothing", delegate
            {
                SeamNative native = new SeamNative();
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                SeamClock clock = new SeamClock();
                WindowsPipeIoEnvironment environment = NewEnvironment(native, quarantine, clock);
                CancellationTokenSource source = new CancellationTokenSource();
                source.Cancel();
                string code;
                EngineServiceRequestWriteProof proof;

                bool written = WindowsNamedPipeIo.TryWriteFrame(
                    new IntPtr(1),
                    new byte[4],
                    TimeSpan.FromSeconds(1),
                    source.Token,
                    out code,
                    out proof,
                    environment);

                ServiceHostAssert.False(written, "the write was refused");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Timeout, code, "timeout code");
                ServiceHostAssert.Equal(
                    EngineServiceRequestWriteProof.NotStarted,
                    proof,
                    "no kernel write ran");
                ServiceHostAssert.Equal(0, native.WriteCalls, "no write call");
                ServiceHostAssert.Equal(0, native.CreateEventCalls, "no event created");
                ServiceHostAssert.Equal(0, quarantine.ReservedCount, "nothing reserved");
                source.Dispose();
            });

            runner.Check("overlapped native: an unproven completion is quarantined and never idle", delegate
            {
                SeamNative native = new SeamNative();
                native.ReadResult = false;
                native.ReadError = WindowsPipeNativeMethods.ErrorIoPending;
                native.GetResult = false;
                native.GetError = WindowsPipeNativeMethods.ErrorIoIncomplete;
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                SeamClock clock = new SeamClock();
                WindowsPipeIoEnvironment environment = NewEnvironment(native, quarantine, clock);
                string code;
                bool zeroTransferProven;

                int read = WindowsNamedPipeIo.TryReadSome(
                    new IntPtr(1),
                    new byte[4],
                    0,
                    4,
                    clock.Now + TimeSpan.FromSeconds(1),
                    CancellationToken.None,
                    out code,
                    out zeroTransferProven,
                    environment);

                ServiceHostAssert.Equal(-2, read, "read refused");
                ServiceHostAssert.False(zeroTransferProven, "no zero-byte proof");
                ServiceHostAssert.Equal(1, quarantine.HeldCount, "context held");
                ServiceHostAssert.Equal(0, native.CloseCalls, "unproven event is never closed");

                WindowsPipeFrameSource source = new WindowsPipeFrameSource(
                    new IntPtr(1),
                    clock.Now + TimeSpan.FromSeconds(1),
                    WindowsNamedPipeIo.CreateMonotonicDeadline(TimeSpan.FromSeconds(30)),
                    CancellationToken.None,
                    environment);
                byte[] frame;
                EngineServiceFrameReadOutcome outcome;
                ServiceHostAssert.False(
                    EngineServiceBoundedFrameReader.TryReadFrame(
                        source,
                        out frame,
                        out outcome,
                        out code),
                    "quarantined read");
                ServiceHostAssert.Equal(
                    EngineServiceFrameReadOutcome.Unknown,
                    outcome,
                    "an unproven read is not idle and not a proven clean refusal");
                ServiceHostAssert.Equal(2, quarantine.HeldCount, "second context held");
                ServiceHostAssert.Equal(0, native.CloseCalls, "still no close");
            });

            runner.Check("overlapped native: a full quarantine refuses before any kernel call", delegate
            {
                SeamNative native = new SeamNative();
                native.ReadResult = false;
                native.ReadError = WindowsPipeNativeMethods.ErrorIoPending;
                native.GetResult = false;
                native.GetError = WindowsPipeNativeMethods.ErrorIoIncomplete;
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(1);
                SeamClock clock = new SeamClock();
                WindowsPipeIoEnvironment environment = NewEnvironment(native, quarantine, clock);
                string code;

                int first = WindowsNamedPipeIo.TryReadSome(
                    new IntPtr(1),
                    new byte[4],
                    0,
                    4,
                    clock.Now + TimeSpan.FromSeconds(1),
                    CancellationToken.None,
                    out code,
                    environment);
                ServiceHostAssert.Equal(-2, first, "first refused");
                ServiceHostAssert.Equal(1, quarantine.HeldCount, "one held");
                ServiceHostAssert.Equal(1, native.CreateEventCalls, "one event created");

                int second = WindowsNamedPipeIo.TryReadSome(
                    new IntPtr(1),
                    new byte[4],
                    0,
                    4,
                    clock.Now + TimeSpan.FromSeconds(1),
                    CancellationToken.None,
                    out code,
                    environment);

                ServiceHostAssert.Equal(-2, second, "second refused");
                ServiceHostAssert.Equal(1, native.ReadCalls, "no second kernel read");
                ServiceHostAssert.Equal(1, native.CreateEventCalls, "no second kernel event");
                ServiceHostAssert.Equal(1, quarantine.HeldCount, "still one held");
                ServiceHostAssert.Equal(1, quarantine.RefusedCount, "one refusal");
                ServiceHostAssert.Equal(
                    WindowsOverlappedQuarantine.DiagnosticCapacityFull,
                    quarantine.LastDiagnostic,
                    "fixed capacity diagnostic");
            });

            runner.Check("overlapped native: concurrent operations cannot exceed the cap", delegate
            {
                SeamNative native = new SeamNative();
                native.ReadResult = false;
                native.ReadError = WindowsPipeNativeMethods.ErrorIoPending;
                native.GetResult = true;
                native.AsyncTransferred = 1;
                native.AsyncPayload = new byte[] { 7 };
                native.WaitGate = new ManualResetEventSlim(false);
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(1);
                SeamClock clock = new SeamClock();
                WindowsPipeIoEnvironment environment = NewEnvironment(native, quarantine, clock);
                Task<int> first = Task.Run(delegate
                {
                    string taskCode;
                    return WindowsNamedPipeIo.TryReadSome(
                        new IntPtr(1),
                        new byte[1],
                        0,
                        1,
                        clock.Now + TimeSpan.FromSeconds(1),
                        CancellationToken.None,
                        out taskCode,
                        environment);
                });
                int firstResult = 0;
                string code;
                try
                {
                    ServiceHostAssert.True(
                        native.ReadStarted.Wait(5000),
                        "the first read reached the kernel call");
                    int second = WindowsNamedPipeIo.TryReadSome(
                        new IntPtr(1),
                        new byte[1],
                        0,
                        1,
                        clock.Now + TimeSpan.FromSeconds(1),
                        CancellationToken.None,
                        out code,
                        environment);

                    ServiceHostAssert.Equal(-2, second, "second refused");
                    ServiceHostAssert.Equal(1, native.ReadCalls, "one kernel read");
                    ServiceHostAssert.Equal(1, quarantine.RefusedCount, "one refusal");

                    native.WaitGate.Set();
                    ServiceHostAssert.True(first.Wait(5000), "first completed");
                    firstResult = first.Result;
                }
                finally
                {
                    native.WaitGate.Set();
                }

                ServiceHostAssert.Equal(1, firstResult, "first bytes");
                ServiceHostAssert.Equal(0, quarantine.HeldCount, "nothing held");
                ServiceHostAssert.Equal(0, quarantine.ReservedCount, "reservation released");
            });

            runner.Check("overlapped native: the OVERLAPPED layout is stable and unmanaged", delegate
            {
                Type type = typeof(WindowsPipeNativeMethods.NativeOverlapped);
                int pointerSize = IntPtr.Size;
                ServiceHostAssert.Equal(3 * pointerSize + 8, Marshal.SizeOf(type), "record size");
                ServiceHostAssert.Equal(0, Marshal.OffsetOf(type, "Internal").ToInt32(), "internal offset");
                ServiceHostAssert.Equal(pointerSize, Marshal.OffsetOf(type, "InternalHigh").ToInt32(), "internal high offset");
                ServiceHostAssert.Equal(2 * pointerSize, Marshal.OffsetOf(type, "Offset").ToInt32(), "offset");
                ServiceHostAssert.Equal(
                    2 * pointerSize + 4,
                    Marshal.OffsetOf(type, "OffsetHigh").ToInt32(),
                    "offset high");
                int eventOffset = Marshal.OffsetOf(type, "Event").ToInt32();
                ServiceHostAssert.Equal(
                    2 * pointerSize + 8,
                    eventOffset,
                    "event offset");

                SeamNative native = new SeamNative();
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                SeamClock clock = new SeamClock();
                WindowsOverlappedContext context = new WindowsOverlappedContext(
                    NewEnvironment(native, quarantine, clock));
                try
                {
                    IntPtr overlapped = context.OverlappedPointer;
                    ServiceHostAssert.True(overlapped != IntPtr.Zero, "unmanaged overlapped");
                    ServiceHostAssert.Equal(
                        IntPtr.Zero,
                        Marshal.ReadIntPtr(overlapped, 0),
                        "internal starts zero");
                    ServiceHostAssert.Equal(
                        native.EventHandle,
                        Marshal.ReadIntPtr(overlapped, eventOffset),
                        "event handle written in native layout");

                    IntPtr buffer = context.PrepareBuffer(new byte[4], 0, 4);
                    ServiceHostAssert.True(buffer != IntPtr.Zero, "unmanaged buffer");
                    Marshal.WriteByte(buffer, 0, 0x5A);
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                    GC.Collect();

                    ServiceHostAssert.Equal(
                        overlapped,
                        context.OverlappedPointer,
                        "overlapped address survived a collection");
                    ServiceHostAssert.Equal(
                        native.EventHandle,
                        Marshal.ReadIntPtr(overlapped, eventOffset),
                        "event survived a collection");
                    ServiceHostAssert.Equal((byte)0x5A, Marshal.ReadByte(buffer, 0), "buffer stayed valid");
                }
                finally
                {
                    context.Dispose();
                }
                ServiceHostAssert.True(context.IsReleased, "released after dispose");
                ServiceHostAssert.Equal(1, native.CloseCalls, "event closed");
                ServiceHostAssert.Equal(0, quarantine.ReservedCount, "reservation released");
            });

            runner.Check("overlapped native: one context performs one operation only", delegate
            {
                SeamNative native = new SeamNative();
                WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                SeamClock clock = new SeamClock();
                using (WindowsOverlappedContext context = new WindowsOverlappedContext(
                    NewEnvironment(native, quarantine, clock)))
                {
                    context.PrepareBuffer(new byte[4], 0, 4);
                    context.BeginOperation();
                    ServiceHostAssert.Throws<InvalidOperationException>(
                        delegate { context.BeginOperation(); },
                        "second begin refused");
                    context.ProveCompletion();
                    ServiceHostAssert.Throws<InvalidOperationException>(
                        delegate { context.BeginOperation(); },
                        "begin after completion refused");
                    ServiceHostAssert.Throws<InvalidOperationException>(
                        delegate { context.ProveCompletion(); },
                        "second proof refused");
                }
                ServiceHostAssert.Equal(1, native.CloseCalls, "one release");
                ServiceHostAssert.Equal(0, quarantine.ReservedCount, "reservation released");
            });

            runner.Check("overlapped native: a Begin and Dispose race never releases a started operation", delegate
            {
                for (int iteration = 0; iteration < 200; iteration++)
                {
                    SeamNative native = new SeamNative();
                    WindowsOverlappedQuarantine quarantine = new WindowsOverlappedQuarantine(4);
                    SeamClock clock = new SeamClock();
                    WindowsOverlappedContext context = new WindowsOverlappedContext(
                        NewEnvironment(native, quarantine, clock));
                    ManualResetEventSlim start = new ManualResetEventSlim(false);
                    bool began = false;
                    Task begin = Task.Run(delegate
                    {
                        start.Wait(5000);
                        try
                        {
                            context.BeginOperation();
                            began = true;
                        }
                        catch (InvalidOperationException)
                        {
                            began = false;
                        }
                    });
                    Task dispose = Task.Run(delegate
                    {
                        start.Wait(5000);
                        context.Dispose();
                    });
                    try
                    {
                        start.Set();
                        ServiceHostAssert.Wait(begin, 5000, "begin");
                        ServiceHostAssert.Wait(dispose, 5000, "dispose");
                        if (began)
                        {
                            ServiceHostAssert.True(
                                context.IsQuarantined,
                                "a begun operation is quarantined, not released");
                        }
                        else
                        {
                            ServiceHostAssert.True(
                                context.IsReleased || context.IsQuarantined,
                                "a refused begin leaves no owned operation");
                        }
                    }
                    finally
                    {
                        start.Dispose();
                    }
                }
            });

            runner.Check("channel: a busy exchange does not poison the channel", delegate
            {
                ServiceHostFakeScmInspector scm = RunningScm();
                EngineServiceServerProof proof = new EngineServiceServerProof(
                    scm,
                    new ServiceHostFakeEvents(),
                    ServiceHostTestData.ServiceImage);
                BusyClientPipe pipe = new BusyClientPipe();
                ServiceHostFakeClientPipeFactory factory = new ServiceHostFakeClientPipeFactory();
                factory.Pipe = pipe;
                WindowsEngineServiceChannel channel = new WindowsEngineServiceChannel(factory, proof);
                byte[] request = ServiceHostTestData.Encode(ServiceHostTestData.HelloFields());
                Task<byte[]> first = Task.Run(delegate
                {
                    return channel.ExchangeAsync(request, CancellationToken.None);
                });
                try
                {
                    ServiceHostAssert.True(pipe.ReadStarted.Wait(5000), "first exchange reached the read");
                    byte[] busy = ServiceHostAssert.Wait(
                        channel.ExchangeAsync(request, CancellationToken.None),
                        5000,
                        "busy exchange");
                    ServiceHostAssert.True(busy == null, "busy exchange refused");
                    ServiceHostAssert.Equal(
                        EngineProtocol.ErrorCodes.Busy,
                        channel.LastFailureCode,
                        "busy code");
                    ServiceHostAssert.False(pipe.DisposeCalled, "busy did not close the pipe");

                    pipe.AllowRead.Set();
                    byte[] firstAnswer = ServiceHostAssert.Wait(first, 5000, "first exchange");
                    ServiceHostAssert.True(firstAnswer != null, "first exchange succeeded");

                    byte[] third = ServiceHostAssert.Wait(
                        channel.ExchangeAsync(request, CancellationToken.None),
                        5000,
                        "third exchange");
                    ServiceHostAssert.True(third != null, "a later exchange still works");
                    ServiceHostAssert.Equal(1, factory.Calls, "one pipe open");
                    ServiceHostAssert.False(pipe.DisposeCalled, "channel stayed usable");
                }
                finally
                {
                    pipe.AllowRead.Set();
                    try
                    {
                        first.Wait(5000);
                    }
                    catch (Exception)
                    {
                        // The assertions above report the failure.
                    }
                    channel.Dispose();
                }
            });

            runner.Check("channel: a proof exception disposes the locally opened pipe", delegate
            {
                ServiceHostFakeScmInspector scm = RunningScm();
                ServiceHostFakeClientPipe pipe = new ServiceHostFakeClientPipe();
                pipe.ServerProcessId = 701;
                ServiceHostFakeClientPipeFactory factory = new ServiceHostFakeClientPipeFactory();
                factory.Pipe = pipe;
                EngineServiceServerProof proof = new EngineServiceServerProof(
                    scm,
                    new ThrowingEventSink(),
                    ServiceHostTestData.ServiceImage);
                WindowsEngineServiceChannel channel = new WindowsEngineServiceChannel(factory, proof);
                try
                {
                    byte[] answer = ServiceHostAssert.Wait(
                        channel.ExchangeAsync(
                            ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()),
                            CancellationToken.None),
                        5000,
                        "exchange");

                    ServiceHostAssert.True(answer == null, "no answer");
                    ServiceHostAssert.True(pipe.DisposeCalled, "opened pipe disposed");
                    ServiceHostAssert.Equal(0, pipe.Writes.Count, "no frame written");
                    ServiceHostAssert.Equal(
                        EngineProtocol.ErrorCodes.EngineUnavailable,
                        channel.LastFailureCode,
                        "fixed failure code");
                }
                finally
                {
                    channel.Dispose();
                }
            });
        }

        private static WindowsPipeIoEnvironment NewEnvironment(
            SeamNative native,
            WindowsOverlappedQuarantine quarantine,
            SeamClock clock)
        {
            return new WindowsPipeIoEnvironment(
                native,
                quarantine,
                delegate { return clock.Now; });
        }

        private static ServiceHostFakeScmInspector RunningScm()
        {
            ServiceHostFakeScmInspector scm = new ServiceHostFakeScmInspector();
            scm.State = new EngineServiceScmState(
                EngineServiceBoundary.ServiceName,
                700,
                4,
                ServiceHostTestData.ServiceCommand);
            return scm;
        }

        private sealed class SeamClock
        {
            public DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1762344000);

            public void Advance(TimeSpan amount)
            {
                Now = Now + amount;
            }
        }

        private sealed class SeamNative : IWindowsPipeNative
        {
            public readonly IntPtr EventHandle = new IntPtr(0x1111);
            public readonly ManualResetEventSlim ReadStarted = new ManualResetEventSlim(false);
            public readonly Queue<uint> WaitResults = new Queue<uint>();
            public ManualResetEventSlim WaitGate;
            public Action OnWait;

            public bool ConnectResult = true;
            public int ConnectError;
            public bool ReadResult = true;
            public int ReadError;
            public bool WriteResult = true;
            public int WriteError;
            public bool GetResult = true;
            public int GetError;
            public bool GetCountKnown = true;
            public uint Transferred;
            public uint AsyncTransferred;
            public byte[] ReadPayload;
            public byte[] AsyncPayload;

            public int CreateEventCalls;
            public int ConnectCalls;
            public int ReadCalls;
            public int WriteCalls;
            public int GetOverlappedCalls;
            public int CancelCalls;
            public int WaitCalls;
            public int CloseCalls;
            public IntPtr LastOverlapped;
            public IntPtr LastReadBuffer;
            public IntPtr LastWriteBuffer;
            public byte[] LastWritePayload;
            public int LastError;

            public IntPtr CreateEventW(IntPtr eventAttributes, int manualReset, int initialState, string name)
            {
                CreateEventCalls++;
                return EventHandle;
            }

            public bool ConnectNamedPipe(IntPtr pipe, IntPtr overlapped)
            {
                ConnectCalls++;
                LastOverlapped = overlapped;
                if (!ConnectResult)
                {
                    LastError = ConnectError;
                }
                return ConnectResult;
            }

            public bool ReadFile(IntPtr file, IntPtr buffer, uint bytesToRead, IntPtr overlapped)
            {
                ReadCalls++;
                LastOverlapped = overlapped;
                LastReadBuffer = buffer;
                ReadStarted.Set();
                if (!ReadResult)
                {
                    LastError = ReadError;
                    return false;
                }
                if (ReadPayload != null)
                {
                    Marshal.Copy(ReadPayload, 0, buffer, ReadPayload.Length);
                    Transferred = (uint)ReadPayload.Length;
                }
                return true;
            }

            public bool WriteFile(IntPtr file, IntPtr buffer, uint bytesToWrite, IntPtr overlapped)
            {
                WriteCalls++;
                LastOverlapped = overlapped;
                LastWriteBuffer = buffer;
                LastWritePayload = new byte[(int)bytesToWrite];
                if (bytesToWrite > 0)
                {
                    Marshal.Copy(buffer, LastWritePayload, 0, (int)bytesToWrite);
                }
                if (!WriteResult)
                {
                    LastError = WriteError;
                    return false;
                }
                Transferred = bytesToWrite;
                return true;
            }

            public WindowsPipeNativeResult GetOverlappedResult(
                IntPtr file,
                IntPtr overlapped,
                bool wait)
            {
                GetOverlappedCalls++;
                LastOverlapped = overlapped;
                if (!GetResult)
                {
                    LastError = GetError;
                    WindowsPipeNativeResult failed = new WindowsPipeNativeResult();
                    failed.Ok = false;
                    failed.Error = GetError;
                    failed.CountKnown = GetCountKnown;
                    failed.Transferred = GetCountKnown ? AsyncTransferred : 0;
                    return failed;
                }
                uint completed = AsyncTransferred != 0 ? AsyncTransferred : Transferred;
                if (AsyncPayload != null && completed > 0 && LastReadBuffer != IntPtr.Zero)
                {
                    Marshal.Copy(AsyncPayload, 0, LastReadBuffer, AsyncPayload.Length);
                }
                WindowsPipeNativeResult result = new WindowsPipeNativeResult();
                result.Ok = true;
                result.Error = 0;
                result.CountKnown = true;
                result.Transferred = completed;
                return result;
            }

            public bool CancelIoEx(IntPtr file, IntPtr overlapped)
            {
                CancelCalls++;
                LastOverlapped = overlapped;
                return true;
            }

            public uint WaitForSingleObject(IntPtr handle, uint milliseconds)
            {
                WaitCalls++;
                if (OnWait != null)
                {
                    OnWait();
                }
                if (WaitGate != null)
                {
                    WaitGate.Wait(5000);
                    return WindowsPipeNativeMethods.WaitObject0;
                }
                if (WaitResults.Count > 0)
                {
                    return WaitResults.Dequeue();
                }
                return WindowsPipeNativeMethods.WaitObject0;
            }

            public bool CloseHandle(IntPtr handle)
            {
                CloseCalls++;
                return true;
            }

            public int GetLastError()
            {
                return LastError;
            }
        }

        private sealed class BusyClientPipe : IEngineServiceClientPipe
        {
            public readonly ManualResetEventSlim ReadStarted = new ManualResetEventSlim(false);
            public readonly ManualResetEventSlim AllowRead = new ManualResetEventSlim(false);
            public bool DisposeCalled;

            public bool TryReadFrame(
                TimeSpan budget,
                CancellationToken cancellationToken,
                out byte[] frame,
                out EngineServiceFrameReadOutcome outcome,
                out string code)
            {
                ReadStarted.Set();
                AllowRead.Wait(5000);
                frame = new byte[] { 1 };
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
                DisposeCalled = true;
            }
        }

        private sealed class ThrowingEventSink : IEngineServiceEventSink
        {
            public void Record(string eventCode)
            {
                throw new InvalidOperationException("event sink failed");
            }
        }
    }
}
