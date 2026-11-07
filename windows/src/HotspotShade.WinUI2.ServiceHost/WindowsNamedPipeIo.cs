using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost
{
    // The Win32 calls used by overlapped pipe I/O. Production uses the real
    // declarations. Hermetic checks use a fake seam and call no Win32
    // function.
    //
    // A failed completion does not establish a transfer count.
    internal interface IWindowsPipeNative
    {
        IntPtr CreateEventW(IntPtr eventAttributes, int manualReset, int initialState, string name);

        bool ConnectNamedPipe(IntPtr pipe, IntPtr overlapped);

        bool ReadFile(IntPtr file, IntPtr buffer, uint bytesToRead, IntPtr overlapped);

        bool WriteFile(IntPtr file, IntPtr buffer, uint bytesToWrite, IntPtr overlapped);

        WindowsPipeNativeResult GetOverlappedResult(IntPtr file, IntPtr overlapped, bool wait);

        bool CancelIoEx(IntPtr file, IntPtr overlapped);

        uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        bool CloseHandle(IntPtr handle);

        int GetLastError();
    }

    // One GetOverlappedResult answer.
    //
    // Ok is the documented success flag. Error is the Win32 error when Ok is
    // false. Transferred is the byte count the completed operation reported.
    // CountKnown is true only when the count is documented. A caller must
    // treat an unknown count as unproven, not as zero.
    internal struct WindowsPipeNativeResult
    {
        public bool Ok;
        public bool CountKnown;
        public uint Transferred;
        public int Error;
    }

    internal sealed class WindowsPipeNativeSeam : IWindowsPipeNative
    {
        public static readonly WindowsPipeNativeSeam Instance = new WindowsPipeNativeSeam();

        private WindowsPipeNativeSeam()
        {
        }

        public IntPtr CreateEventW(IntPtr eventAttributes, int manualReset, int initialState, string name)
        {
            return WindowsPipeNativeMethods.CreateEventW(eventAttributes, manualReset, initialState, name);
        }

        public bool ConnectNamedPipe(IntPtr pipe, IntPtr overlapped)
        {
            return WindowsPipeNativeMethods.ConnectNamedPipe(pipe, overlapped);
        }

        public bool ReadFile(IntPtr file, IntPtr buffer, uint bytesToRead, IntPtr overlapped)
        {
            return WindowsPipeNativeMethods.ReadFile(file, buffer, bytesToRead, IntPtr.Zero, overlapped);
        }

        public bool WriteFile(IntPtr file, IntPtr buffer, uint bytesToWrite, IntPtr overlapped)
        {
            return WindowsPipeNativeMethods.WriteFile(file, buffer, bytesToWrite, IntPtr.Zero, overlapped);
        }

        public WindowsPipeNativeResult GetOverlappedResult(
            IntPtr file,
            IntPtr overlapped,
            bool wait)
        {
            uint transferred;
            WindowsPipeNativeResult result = new WindowsPipeNativeResult();
            if (WindowsPipeNativeMethods.GetOverlappedResult(
                file,
                overlapped,
                out transferred,
                wait))
            {
                // A success always defines the count.
                result.Ok = true;
                result.Error = WindowsPipeNativeMethods.ErrorSuccess;
                result.CountKnown = true;
                result.Transferred = transferred;
                return result;
            }

            result.Ok = false;
            result.Error = Marshal.GetLastWin32Error();
            result.Transferred = 0;
            result.CountKnown = false;
            return result;
        }

        public bool CancelIoEx(IntPtr file, IntPtr overlapped)
        {
            return WindowsPipeNativeMethods.CancelIoEx(file, overlapped);
        }

        public uint WaitForSingleObject(IntPtr handle, uint milliseconds)
        {
            return WindowsPipeNativeMethods.WaitForSingleObject(handle, milliseconds);
        }

        public bool CloseHandle(IntPtr handle)
        {
            return WindowsPipeNativeMethods.CloseHandle(handle);
        }

        public int GetLastError()
        {
            return Marshal.GetLastWin32Error();
        }
    }

    // One native seam, one quarantine, and one clock for a pipe I/O path.
    // Production uses the shared instance. A hermetic check supplies its own
    // so one check cannot consume another check's quarantine capacity.
    internal sealed class WindowsPipeIoEnvironment
    {
        private static readonly WindowsPipeIoEnvironment shared =
            new WindowsPipeIoEnvironment(
                WindowsPipeNativeSeam.Instance,
                new WindowsOverlappedQuarantine(WindowsOverlappedQuarantine.DefaultCapacity),
                delegate { return DateTimeOffset.UtcNow; });

        private readonly IWindowsPipeNative native;
        private readonly WindowsOverlappedQuarantine quarantine;
        private readonly Func<DateTimeOffset> utcNow;

        internal WindowsPipeIoEnvironment(
            IWindowsPipeNative native,
            WindowsOverlappedQuarantine quarantine,
            Func<DateTimeOffset> utcNow)
        {
            if (native == null)
            {
                throw new ArgumentNullException("native");
            }
            if (quarantine == null)
            {
                throw new ArgumentNullException("quarantine");
            }
            if (utcNow == null)
            {
                throw new ArgumentNullException("utcNow");
            }
            this.native = native;
            this.quarantine = quarantine;
            this.utcNow = utcNow;
        }

        internal static WindowsPipeIoEnvironment Shared
        {
            get { return shared; }
        }

        internal IWindowsPipeNative Native
        {
            get { return native; }
        }

        internal WindowsOverlappedQuarantine Quarantine
        {
            get { return quarantine; }
        }

        internal DateTimeOffset Now()
        {
            return utcNow();
        }
    }

    // Owns the event, one unmanaged OVERLAPPED record, and one unmanaged data
    // buffer for exactly one kernel operation. The kernel must never hold a
    // managed heap address. The context reserves quarantine capacity before it
    // creates the event, so a full quarantine refuses the operation before any
    // kernel call. A context is one-shot: after BeginOperation and one
    // completion proof it cannot start another operation.
    //
    // Dispose releases the memory only after completion is proven. If proof is
    // impossible, the instance moves to the quarantine and keeps every address
    // valid. A leaked operation is safer than a use-after-free in the kernel.
    internal sealed class WindowsOverlappedContext : IDisposable
    {
        private const int StateNew = 0;
        private const int StateOperating = 1;
        private const int StateCompleted = 2;
        private const int StateHeld = 3;
        private const int StateReleased = 4;

        private readonly IWindowsPipeNative native;
        private readonly WindowsOverlappedQuarantine quarantine;
        private IntPtr eventHandle;
        private IntPtr overlappedPointer;
        private IntPtr bufferPointer;
        private int bufferLength;
        private int reservation;
        private int state;
        private int disposed;

        public WindowsOverlappedContext(WindowsPipeIoEnvironment environment)
        {
            if (environment == null)
            {
                throw new ArgumentNullException("environment");
            }
            native = environment.Native;
            quarantine = environment.Quarantine;

            // Reserve before CreateEventW or any other kernel call. A full
            // quarantine leaves the context invalid and the caller fails
            // closed without starting I/O.
            if (!quarantine.TryReserve())
            {
                return;
            }
            reservation = 1;

            try
            {
                eventHandle = native.CreateEventW(
                    IntPtr.Zero,
                    1,
                    0,
                    null);
                if (eventHandle == IntPtr.Zero)
                {
                    return;
                }

                int size = Marshal.SizeOf(typeof(WindowsPipeNativeMethods.NativeOverlapped));
                overlappedPointer = Marshal.AllocHGlobal(size);
                WindowsPipeNativeMethods.NativeOverlapped record =
                    new WindowsPipeNativeMethods.NativeOverlapped();
                record.Event = eventHandle;
                Marshal.StructureToPtr(record, overlappedPointer, false);
            }
            catch (Exception)
            {
                ReleaseReservation();
                if (overlappedPointer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(overlappedPointer);
                    overlappedPointer = IntPtr.Zero;
                }
                IntPtr failedEvent = eventHandle;
                eventHandle = IntPtr.Zero;
                if (failedEvent != IntPtr.Zero)
                {
                    native.CloseHandle(failedEvent);
                }
                throw;
            }
        }

        public bool Valid
        {
            get { return eventHandle != IntPtr.Zero && overlappedPointer != IntPtr.Zero; }
        }

        public IntPtr EventHandle
        {
            get { return eventHandle; }
        }

        public IntPtr OverlappedPointer
        {
            get { return overlappedPointer; }
        }

        public bool IsReleased
        {
            get { return Volatile.Read(ref state) == StateReleased; }
        }

        public bool IsQuarantined
        {
            get { return Volatile.Read(ref state) == StateHeld; }
        }

        public IntPtr PrepareBuffer(byte[] buffer, int offset, int count)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException("buffer");
            }
            if (offset < 0 || count <= 0 || offset > buffer.Length || count > buffer.Length - offset)
            {
                throw new ArgumentOutOfRangeException("count");
            }
            if (Volatile.Read(ref disposed) != 0)
            {
                throw new InvalidOperationException("the overlapped context is disposed");
            }
            if (Volatile.Read(ref state) != StateNew)
            {
                throw new InvalidOperationException("the overlapped context is one-shot");
            }
            if (bufferPointer != IntPtr.Zero)
            {
                throw new InvalidOperationException("the operation buffer is already prepared");
            }
            bufferPointer = Marshal.AllocHGlobal(count);
            bufferLength = count;
            return bufferPointer;
        }

        public void CopyToNative(byte[] buffer, int offset, int count)
        {
            if (buffer == null || bufferPointer == IntPtr.Zero)
            {
                throw new InvalidOperationException("the operation buffer is not prepared");
            }
            if (offset < 0 || count < 0 || offset > buffer.Length || count > buffer.Length - offset
                || count > bufferLength)
            {
                throw new ArgumentOutOfRangeException("count");
            }
            if (count > 0)
            {
                Marshal.Copy(buffer, offset, bufferPointer, count);
            }
        }

        public void CopyFromNative(byte[] buffer, int offset, int count)
        {
            if (buffer == null || bufferPointer == IntPtr.Zero)
            {
                throw new InvalidOperationException("the operation buffer is not prepared");
            }
            if (offset < 0 || count < 0 || offset > buffer.Length || count > buffer.Length - offset
                || count > bufferLength)
            {
                throw new ArgumentOutOfRangeException("count");
            }
            if (count > 0)
            {
                Marshal.Copy(bufferPointer, buffer, offset, count);
            }
        }

        // Marks the start of the one kernel operation this context allows.
        // Until ProveCompletion is called, the kernel may still own the
        // OVERLAPPED and the buffer.
        public void BeginOperation()
        {
            if (Volatile.Read(ref disposed) != 0)
            {
                throw new InvalidOperationException("the overlapped context is disposed");
            }
            if (Interlocked.CompareExchange(ref state, StateOperating, StateNew) != StateNew)
            {
                throw new InvalidOperationException("the overlapped context is one-shot");
            }
        }

        public void ProveCompletion()
        {
            if (Interlocked.CompareExchange(ref state, StateCompleted, StateOperating) != StateOperating)
            {
                throw new InvalidOperationException("the overlapped context has no pending operation");
            }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
            {
                return;
            }

            // The held transition must be one atomic compare-exchange. A
            // separate read and write can overwrite a concurrent
            // BeginOperation and release the buffer under the kernel.
            int current = Interlocked.CompareExchange(
                ref state,
                StateHeld,
                StateOperating);
            if (current == StateOperating)
            {
                // The kernel may still own the OVERLAPPED and the buffer.
                // Keep the context, the event, and every address alive.
                quarantine.Hold(this);
                return;
            }

            while (true)
            {
                if (current == StateHeld || current == StateReleased)
                {
                    return;
                }
                if (current == StateOperating)
                {
                    // BeginOperation won the race after the first exchange.
                    // Move the context to the quarantine instead of freeing
                    // memory the kernel may still use.
                    current = Interlocked.CompareExchange(
                        ref state,
                        StateHeld,
                        StateOperating);
                    if (current == StateOperating)
                    {
                        quarantine.Hold(this);
                        return;
                    }
                    continue;
                }

                // StateNew or StateCompleted. Claim the release atomically.
                // If BeginOperation wins, the next iteration sees
                // StateOperating and holds the context instead.
                int prior = Interlocked.CompareExchange(
                    ref state,
                    StateReleased,
                    current);
                if (prior == current)
                {
                    break;
                }
                current = prior;
            }

            ReleaseResources();
        }

        private void ReleaseResources()
        {
            IntPtr currentBuffer = bufferPointer;
            bufferPointer = IntPtr.Zero;
            bufferLength = 0;
            IntPtr currentOverlapped = overlappedPointer;
            overlappedPointer = IntPtr.Zero;
            IntPtr currentEvent = eventHandle;
            eventHandle = IntPtr.Zero;

            try
            {
                if (currentBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(currentBuffer);
                }
                if (currentOverlapped != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(currentOverlapped);
                }
            }
            finally
            {
                try
                {
                    if (currentEvent != IntPtr.Zero)
                    {
                        native.CloseHandle(currentEvent);
                    }
                }
                finally
                {
                    ReleaseReservation();
                }
            }
        }

        private void ReleaseReservation()
        {
            if (Interlocked.Exchange(ref reservation, 0) != 0)
            {
                quarantine.ReleaseReservation();
            }
        }
    }

    // A completion that cannot be proven leaves the kernel in charge of the
    // OVERLAPPED and the buffer. The entries are never reused or released.
    // Capacity is reserved before any kernel call, so held entries plus live
    // reservations can never exceed the configured bound.
    internal sealed class WindowsOverlappedQuarantine
    {
        public const int DefaultCapacity = 16;
        public const string DiagnosticCompletionUnproven = "overlapped_completion_unproven";
        public const string DiagnosticCapacityFull = "overlapped_quarantine_full";
        public const string DiagnosticHoldRejected = "overlapped_quarantine_hold_rejected";

        private readonly object sync = new object();
        private readonly WindowsOverlappedContext[] held;
        private int heldCount;
        private int reservedCount;
        private int refusedCount;
        private string lastDiagnostic = "";

        public WindowsOverlappedQuarantine(int capacity)
        {
            if (capacity <= 0 || capacity > 1024)
            {
                throw new ArgumentOutOfRangeException("capacity");
            }
            held = new WindowsOverlappedContext[capacity];
        }

        public int Capacity
        {
            get { return held.Length; }
        }

        public int HeldCount
        {
            get
            {
                lock (sync)
                {
                    return heldCount;
                }
            }
        }

        public int ReservedCount
        {
            get
            {
                lock (sync)
                {
                    return reservedCount;
                }
            }
        }

        public int RefusedCount
        {
            get
            {
                lock (sync)
                {
                    return refusedCount;
                }
            }
        }

        // A fixed, nonsecret diagnostic. It never holds a handle, address,
        // path, process id, token, or key.
        public string LastDiagnostic
        {
            get
            {
                lock (sync)
                {
                    return lastDiagnostic;
                }
            }
        }

        internal bool TryReserve()
        {
            lock (sync)
            {
                if (heldCount + reservedCount >= held.Length)
                {
                    refusedCount++;
                    lastDiagnostic = DiagnosticCapacityFull;
                    return false;
                }
                reservedCount++;
                return true;
            }
        }

        internal void ReleaseReservation()
        {
            lock (sync)
            {
                if (reservedCount > 0)
                {
                    reservedCount--;
                }
            }
        }

        internal void Hold(WindowsOverlappedContext context)
        {
            if (context == null)
            {
                return;
            }
            lock (sync)
            {
                if (heldCount >= held.Length)
                {
                    lastDiagnostic = DiagnosticHoldRejected;
                    return;
                }
                held[heldCount] = context;
                heldCount++;
                if (reservedCount > 0)
                {
                    reservedCount--;
                }
                lastDiagnostic = DiagnosticCompletionUnproven;
            }
        }
    }

    internal sealed class WindowsPipeFrameSource : IEngineServiceFrameSource
    {
        private readonly IntPtr handle;
        private readonly DateTimeOffset deadline;
        private readonly long monotonicDeadline;
        private readonly EngineServiceReadDeadline readDeadline;
        private readonly CancellationToken cancellationToken;
        private readonly WindowsPipeIoEnvironment environment;

        public WindowsPipeFrameSource(
            IntPtr handle,
            DateTimeOffset deadline,
            CancellationToken cancellationToken)
            : this(
                handle,
                deadline,
                WindowsNamedPipeIo.CreateMonotonicDeadline(deadline - DateTimeOffset.UtcNow),
                cancellationToken,
                WindowsPipeIoEnvironment.Shared)
        {
        }

        internal WindowsPipeFrameSource(
            IntPtr handle,
            DateTimeOffset deadline,
            long monotonicDeadline,
            CancellationToken cancellationToken,
            WindowsPipeIoEnvironment environment)
        {
            if (environment == null)
            {
                throw new ArgumentNullException("environment");
            }
            this.handle = handle;
            this.deadline = deadline;
            this.monotonicDeadline = monotonicDeadline;
            this.cancellationToken = cancellationToken;
            this.environment = environment;
        }

        internal WindowsPipeFrameSource(
            IntPtr handle, EngineServiceReadDeadline deadline,
            CancellationToken cancellationToken, WindowsPipeIoEnvironment environment)
        {
            this.handle = handle;
            this.readDeadline = deadline;
            this.cancellationToken = cancellationToken;
            this.environment = environment;
        }

        public EngineServiceFrameSourceRead Read(
            byte[] buffer,
            int offset,
            int count,
            out string code)
        {
            bool zeroTransferProven;
            // Consume exactly one byte at the boundary so the frame budget
            // begins as soon as that byte is observed, even for a split prefix.
            int requested = readDeadline != null && !readDeadline.HasFirstByte ? 1 : count;
            int read = WindowsNamedPipeIo.TryReadSome(
                handle,
                buffer,
                offset,
                requested,
                deadline,
                monotonicDeadline,
                cancellationToken,
                out code,
                out zeroTransferProven,
                environment,
                readDeadline);
            if (read > 0)
            {
                if (readDeadline != null)
                {
                    readDeadline.ConsumedFirstByte();
                }
                return EngineServiceFrameSourceRead.Data(read);
            }
            if (read == 0)
            {
                // A clean end is only reported for a completed zero-byte
                // transfer, which is also a proven zero transfer.
                return EngineServiceFrameSourceRead.EndOfStream();
            }
            if (read == -1)
            {
                // A stop request is never an idle proof. A cancel that
                // completed with a positive transfer, or whose transfer count
                // is unknown, is not an idle proof either. The caller closes
                // the pipe for both.
                if (cancellationToken.IsCancellationRequested || !zeroTransferProven)
                {
                    return EngineServiceFrameSourceRead.Interrupted();
                }
                return EngineServiceFrameSourceRead.Idle();
            }
            if (!zeroTransferProven)
            {
                // A refused read whose transfer count is unproven may still
                // have consumed a byte. The stream position is unknown, so the
                // caller closes the pipe instead of treating this as a plain
                // refusal that consumed nothing.
                return EngineServiceFrameSourceRead.Interrupted();
            }
            return EngineServiceFrameSourceRead.Failed();
        }
    }

    internal static class WindowsNamedPipeIo
    {
        // CancelIoEx only asks for cancellation. The operation event is the
        // proof that the kernel has stopped touching the OVERLAPPED and the
        // data buffer. A driver that never signals leaves the operation in
        // quarantine instead of releasing live memory.
        private const uint CompletionProofWaitMilliseconds = 5000;

        // Legacy connect, client reads, and writes use these caps. Server
        // reads use EngineServiceReadDeadline without consulting UTC.
        // The wall clock can move backward. A legacy operation keeps the
        // earlier of its wall deadline and this monotonic cap, so a clock
        // change cannot extend a kernel wait. The wall deadline still makes a
        // forward clock change end the operation early.
        internal static long CreateMonotonicDeadline(TimeSpan budget)
        {
            long now = Stopwatch.GetTimestamp();
            if (budget <= TimeSpan.Zero)
            {
                return now;
            }
            double ticks = budget.TotalSeconds * Stopwatch.Frequency;
            if (ticks >= (double)(long.MaxValue - now))
            {
                return long.MaxValue;
            }
            return now + (long)ticks;
        }

        internal static bool MonotonicDeadlineReached(long monotonicDeadline)
        {
            return Stopwatch.GetTimestamp() >= monotonicDeadline;
        }

        public static string LastOverlappedDiagnostic
        {
            get { return WindowsPipeIoEnvironment.Shared.Quarantine.LastDiagnostic; }
        }

        public static bool TryConnect(
            IntPtr handle,
            TimeSpan timeout,
            CancellationToken cancellationToken,
            out string code)
        {
            return TryConnect(
                handle,
                timeout,
                cancellationToken,
                out code,
                WindowsPipeIoEnvironment.Shared);
        }

        internal static bool TryConnect(
            IntPtr handle,
            TimeSpan timeout,
            CancellationToken cancellationToken,
            out string code,
            WindowsPipeIoEnvironment environment)
        {
            if (handle == IntPtr.Zero || timeout <= TimeSpan.Zero || environment == null)
            {
                code = EngineProtocol.ErrorCodes.EngineUnavailable;
                return false;
            }
            if (cancellationToken.IsCancellationRequested)
            {
                // A canceled caller starts no kernel operation. There is no
                // overlapped record to cancel or prove.
                code = EngineProtocol.ErrorCodes.Timeout;
                return false;
            }
            DateTimeOffset deadline = environment.Now() + timeout;
            long monotonicDeadline = CreateMonotonicDeadline(timeout);
            using (WindowsOverlappedContext context = new WindowsOverlappedContext(environment))
            {
                if (!context.Valid)
                {
                    code = EngineProtocol.ErrorCodes.EngineUnavailable;
                    return false;
                }
                context.BeginOperation();
                bool connected = environment.Native.ConnectNamedPipe(
                    handle,
                    context.OverlappedPointer);
                if (connected)
                {
                    context.ProveCompletion();
                    code = "";
                    return true;
                }
                int error = environment.Native.GetLastError();
                if (error == WindowsPipeNativeMethods.ErrorPipeConnected)
                {
                    context.ProveCompletion();
                    code = "";
                    return true;
                }
                if (error == WindowsPipeNativeMethods.ErrorIoIncomplete)
                {
                    // An incomplete result never proves completion. Leave the
                    // context in the operating state so Dispose quarantines
                    // the event and the unmanaged records.
                    code = EngineProtocol.ErrorCodes.EngineUnavailable;
                    return false;
                }
                if (error != WindowsPipeNativeMethods.ErrorIoPending)
                {
                    // No operation is pending. The kernel holds no reference.
                    context.ProveCompletion();
                    code = EngineProtocol.ErrorCodes.EngineUnavailable;
                    return false;
                }
                uint transferred;
                bool ignoredZeroTransfer;
                return TryWait(
                    handle,
                    context,
                    deadline,
                    monotonicDeadline,
                    cancellationToken,
                    environment,
                    out transferred,
                    out ignoredZeroTransfer,
                    out code);
            }
        }

        public static bool TryReadFrame(
            IntPtr handle,
            TimeSpan timeout,
            CancellationToken cancellationToken,
            out byte[] frame,
            out string code)
        {
            return TryReadFrame(
                handle,
                timeout,
                cancellationToken,
                out frame,
                out code,
                WindowsPipeIoEnvironment.Shared);
        }

        public static bool TryReadFrame(
            IntPtr handle,
            TimeSpan timeout,
            CancellationToken cancellationToken,
            out byte[] frame,
            out EngineServiceFrameReadOutcome outcome,
            out string code)
        {
            return TryReadFrame(
                handle,
                timeout,
                cancellationToken,
                out frame,
                out outcome,
                out code,
                WindowsPipeIoEnvironment.Shared);
        }

        internal static bool TryReadFrame(
            IntPtr handle,
            TimeSpan timeout,
            CancellationToken cancellationToken,
            out byte[] frame,
            out string code,
            WindowsPipeIoEnvironment environment)
        {
            EngineServiceFrameReadOutcome outcome;
            return TryReadFrame(
                handle,
                timeout,
                cancellationToken,
                out frame,
                out outcome,
                out code,
                environment);
        }

        internal static bool TryReadFrame(
            IntPtr handle,
            TimeSpan timeout,
            CancellationToken cancellationToken,
            out byte[] frame,
            out EngineServiceFrameReadOutcome outcome,
            out string code,
            WindowsPipeIoEnvironment environment)
        {
            frame = null;
            outcome = EngineServiceFrameReadOutcome.Failed;
            if (handle == IntPtr.Zero || timeout <= TimeSpan.Zero || environment == null)
            {
                code = EngineProtocol.ErrorCodes.EngineUnavailable;
                return false;
            }
            if (cancellationToken.IsCancellationRequested)
            {
                // A canceled frame read starts no kernel operation and
                // allocates no buffer.
                code = EngineProtocol.ErrorCodes.Timeout;
                return false;
            }
            DateTimeOffset deadline = environment.Now() + timeout;
            long monotonicDeadline = CreateMonotonicDeadline(timeout);
            WindowsPipeFrameSource source = new WindowsPipeFrameSource(
                handle,
                deadline,
                monotonicDeadline,
                cancellationToken,
                environment);
            return EngineServiceBoundedFrameReader.TryReadFrame(
                source,
                out frame,
                out outcome,
                out code);
        }

        // Server reads carry an absolute monotonic boundary deadline. They
        // never consult UTC, including before allocation or between fragments.
        internal static bool TryReadFrame(
            IntPtr handle, EngineServiceReadDeadline deadline,
            CancellationToken cancellationToken, out byte[] frame,
            out EngineServiceFrameReadOutcome outcome, out string code,
            WindowsPipeIoEnvironment environment)
        {
            frame = null;
            outcome = EngineServiceFrameReadOutcome.Failed;
            if (handle == IntPtr.Zero || deadline == null || environment == null)
            {
                code = EngineProtocol.ErrorCodes.EngineUnavailable;
                return false;
            }
            if (cancellationToken.IsCancellationRequested)
            {
                code = EngineProtocol.ErrorCodes.Timeout;
                return false;
            }
            WindowsPipeFrameSource source = new WindowsPipeFrameSource(
                handle, deadline, cancellationToken, environment);
            return EngineServiceBoundedFrameReader.TryReadFrame(
                source, out frame, out outcome, out code);
        }

        public static bool TryWriteFrame(
            IntPtr handle,
            byte[] frame,
            TimeSpan timeout,
            CancellationToken cancellationToken,
            out string code)
        {
            EngineServiceRequestWriteProof ignoredProof;
            return TryWriteFrame(
                handle,
                frame,
                timeout,
                cancellationToken,
                out code,
                out ignoredProof,
                WindowsPipeIoEnvironment.Shared);
        }

        // proof says what a failed frame write can prove about delivery. A
        // write that started a kernel operation may have delivered part or all
        // of the frame. Only a write that never started, or whose every
        // completed operation reported an unknown-free zero transfer, is a
        // clean no-delivery result.
        internal static bool TryWriteFrame(
            IntPtr handle,
            byte[] frame,
            TimeSpan timeout,
            CancellationToken cancellationToken,
            out string code,
            out EngineServiceRequestWriteProof proof,
            WindowsPipeIoEnvironment environment)
        {
            proof = EngineServiceRequestWriteProof.NotStarted;
            if (handle == IntPtr.Zero || frame == null || frame.Length == 0 || timeout <= TimeSpan.Zero
                || environment == null)
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }
            if (cancellationToken.IsCancellationRequested)
            {
                // A canceled frame write starts no kernel operation.
                code = EngineProtocol.ErrorCodes.Timeout;
                return false;
            }
            DateTimeOffset deadline = environment.Now() + timeout;
            long monotonicDeadline = CreateMonotonicDeadline(timeout);
            int offset = 0;
            bool anyBytes = false;
            while (offset < frame.Length)
            {
                WriteStep step = TryWriteStep(
                    handle,
                    frame,
                    offset,
                    frame.Length - offset,
                    deadline,
                    monotonicDeadline,
                    cancellationToken,
                    environment);
                if (step.Bytes > 0)
                {
                    offset += step.Bytes;
                    anyBytes = true;
                    continue;
                }
                code = step.Code;
                if (anyBytes)
                {
                    // Part of the frame already left this process. The
                    // service may have read a complete frame even though this
                    // call failed, so the delivery is unproven.
                    proof = EngineServiceRequestWriteProof.Unproven;
                }
                else if (step.Started && step.ZeroDeliveryProven)
                {
                    proof = EngineServiceRequestWriteProof.NotDelivered;
                }
                else if (step.Started)
                {
                    proof = EngineServiceRequestWriteProof.Unproven;
                }
                else
                {
                    proof = EngineServiceRequestWriteProof.NotStarted;
                }
                return false;
            }
            code = "";
            proof = EngineServiceRequestWriteProof.Delivered;
            return true;
        }

        public static bool TryImpersonateClient(IntPtr handle, out string code)
        {
            if (handle == IntPtr.Zero
                || !WindowsPipeNativeMethods.ImpersonateNamedPipeClient(handle))
            {
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }
            code = "";
            return true;
        }

        public static bool TryOpenThreadToken(
            out IEngineServiceCallerToken token,
            out string code)
        {
            token = null;
            IntPtr handle;
            if (!WindowsPipeNativeMethods.OpenThreadToken(
                WindowsPipeNativeMethods.GetCurrentThread(),
                WindowsPipeNativeMethods.TokenQuery,
                true,
                out handle)
                || handle == IntPtr.Zero)
            {
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }
            token = new WindowsCallerToken(handle);
            code = "";
            return true;
        }

        // Calls RevertToSelf and then proves the thread no longer has a token.
        // Only ERROR_NO_TOKEN is accepted as proof. A thread token that opens
        // after the revert, or any other error, is unverified and fails closed.
        public static bool TryRevertToSelfAndVerify(out string code)
        {
            if (!WindowsPipeNativeMethods.RevertToSelf())
            {
                code = EngineProtocol.ErrorCodes.EngineUnavailable;
                return false;
            }

            IntPtr token;
            if (WindowsPipeNativeMethods.OpenThreadToken(
                WindowsPipeNativeMethods.GetCurrentThread(),
                WindowsPipeNativeMethods.TokenQuery,
                true,
                out token))
            {
                if (token != IntPtr.Zero)
                {
                    WindowsPipeNativeMethods.CloseHandle(token);
                }
                code = EngineProtocol.ErrorCodes.EngineUnavailable;
                return false;
            }
            if (Marshal.GetLastWin32Error() != WindowsPipeNativeMethods.ErrorNoToken)
            {
                code = EngineProtocol.ErrorCodes.EngineUnavailable;
                return false;
            }
            code = "";
            return true;
        }

        public static bool TryGetClientProcessId(IntPtr handle, out int processId)
        {
            processId = 0;
            uint value;
            if (handle == IntPtr.Zero
                || !WindowsPipeNativeMethods.GetNamedPipeClientProcessId(handle, out value)
                || value == 0
                || value > int.MaxValue)
            {
                return false;
            }
            processId = (int)value;
            return true;
        }

        public static bool TryGetServerProcessId(IntPtr handle, out int processId)
        {
            processId = 0;
            uint value;
            if (handle == IntPtr.Zero
                || !WindowsPipeNativeMethods.GetNamedPipeServerProcessId(handle, out value)
                || value == 0
                || value > int.MaxValue)
            {
                return false;
            }
            processId = (int)value;
            return true;
        }

        public static int TryReadSome(
            IntPtr handle,
            byte[] buffer,
            int offset,
            int count,
            DateTimeOffset deadline,
            CancellationToken cancellationToken,
            out string code)
        {
            return TryReadSome(
                handle,
                buffer,
                offset,
                count,
                deadline,
                cancellationToken,
                out code,
                WindowsPipeIoEnvironment.Shared);
        }

        internal static int TryReadSome(
            IntPtr handle,
            byte[] buffer,
            int offset,
            int count,
            DateTimeOffset deadline,
            CancellationToken cancellationToken,
            out string code,
            WindowsPipeIoEnvironment environment)
        {
            bool ignoredZeroTransfer;
            return TryReadSome(
                handle,
                buffer,
                offset,
                count,
                deadline,
                cancellationToken,
                out code,
                out ignoredZeroTransfer,
                environment);
        }

        // zeroTransferProven is true only when the read ended with a proven
        // zero-byte transfer and consumed no byte. It is true for a read that
        // starts no kernel operation, for a completed operation that
        // transferred zero bytes. Completion proof alone never proves a count.
        // It is false for an unproven completion and
        // for a cancel that completed with a positive or unknown transfer.
        internal static int TryReadSome(
            IntPtr handle,
            byte[] buffer,
            int offset,
            int count,
            DateTimeOffset deadline,
            CancellationToken cancellationToken,
            out string code,
            out bool zeroTransferProven,
            WindowsPipeIoEnvironment environment)
        {
            zeroTransferProven = false;
            if (environment == null)
            {
                code = EngineProtocol.ErrorCodes.EngineUnavailable;
                return -2;
            }
            long monotonicDeadline = CreateMonotonicDeadline(deadline - environment.Now());
            return TryReadSome(
                handle,
                buffer,
                offset,
                count,
                deadline,
                monotonicDeadline,
                cancellationToken,
                out code,
                out zeroTransferProven,
                environment);
        }

        internal static int TryReadSome(
            IntPtr handle,
            byte[] buffer,
            int offset,
            int count,
            DateTimeOffset deadline,
            long monotonicDeadline,
            CancellationToken cancellationToken,
            out string code,
            WindowsPipeIoEnvironment environment)
        {
            bool ignoredZeroTransfer;
            return TryReadSome(
                handle,
                buffer,
                offset,
                count,
                deadline,
                monotonicDeadline,
                cancellationToken,
                out code,
                out ignoredZeroTransfer,
                environment);
        }

        internal static int TryReadSome(
            IntPtr handle,
            byte[] buffer,
            int offset,
            int count,
            DateTimeOffset deadline,
            long monotonicDeadline,
            CancellationToken cancellationToken,
            out string code,
            out bool zeroTransferProven,
            WindowsPipeIoEnvironment environment,
            EngineServiceReadDeadline readDeadline = null)
        {
            code = EngineProtocol.ErrorCodes.EngineUnavailable;
            zeroTransferProven = false;
            if (buffer == null || offset < 0 || count <= 0 || offset > buffer.Length
                || count > buffer.Length - offset || environment == null)
            {
                // No kernel operation ran. Nothing was consumed.
                zeroTransferProven = true;
                return -2;
            }
            if (cancellationToken.IsCancellationRequested)
            {
                // A canceled read starts no kernel operation and allocates no
                // unmanaged buffer. Nothing was consumed.
                code = EngineProtocol.ErrorCodes.Timeout;
                zeroTransferProven = true;
                return -1;
            }
            if (readDeadline != null ? readDeadline.TryExpire() : deadline <= environment.Now())
            {
                // An already expired budget starts no kernel operation.
                code = EngineProtocol.ErrorCodes.Timeout;
                zeroTransferProven = true;
                return -1;
            }

            using (WindowsOverlappedContext context = new WindowsOverlappedContext(environment))
            {
                if (!context.Valid)
                {
                    // No kernel operation ran. Nothing was consumed.
                    zeroTransferProven = true;
                    return -2;
                }
                IntPtr pointer = context.PrepareBuffer(buffer, offset, count);
                context.BeginOperation();
                bool ok = environment.Native.ReadFile(
                    handle,
                    pointer,
                    (uint)count,
                    context.OverlappedPointer);
                int error = ok
                    ? WindowsPipeNativeMethods.ErrorSuccess
                    : environment.Native.GetLastError();
                if (ok)
                {
                    OverlappedCompletion completion = TryGetSynchronousCompletion(
                        handle,
                        context,
                        environment);
                    if (!completion.Proven)
                    {
                        // The kernel may still own the records. Dispose moves
                        // the context to the quarantine.
                        return -2;
                    }
                    if (!completion.Succeeded)
                    {
                        code = completion.Error == WindowsPipeNativeMethods.ErrorOperationAborted
                            ? EngineProtocol.ErrorCodes.Timeout
                            : EngineProtocol.ErrorCodes.EngineUnavailable;
                        return completion.Error == WindowsPipeNativeMethods.ErrorOperationAborted
                            ? -1 : -2;
                    }
                    if (!completion.CountKnown)
                    {
                        // An unknown count may have consumed a byte.
                        code = EngineProtocol.ErrorCodes.EngineUnavailable;
                        return -1;
                    }
                    if (completion.Bytes > (uint)count)
                    {
                        // A count above the buffer is not a valid completion.
                        // The stream position is unknown.
                        code = EngineProtocol.ErrorCodes.BadResponse;
                        return -1;
                    }
                    zeroTransferProven = completion.Bytes == 0;
                    if (readDeadline != null
                        && (cancellationToken.IsCancellationRequested || readDeadline.TryExpire()))
                    {
                        code = EngineProtocol.ErrorCodes.Timeout;
                        return -1;
                    }

                    if (completion.Bytes > 0)
                    {
                        context.CopyFromNative(buffer, offset, (int)completion.Bytes);
                    }
                    code = "";
                    return completion.Bytes == 0 ? 0 : (int)completion.Bytes;
                }
                if (error == WindowsPipeNativeMethods.ErrorIoIncomplete)
                {
                    // An incomplete result never proves completion. Leave the
                    // context in the operating state so Dispose quarantines
                    // the event and the unmanaged records.
                    return -2;
                }
                if (error != WindowsPipeNativeMethods.ErrorIoPending)
                {
                    // No operation is pending, but failure does not prove a
                    // transfer count.
                    context.ProveCompletion();
                    if (error == WindowsPipeNativeMethods.ErrorBrokenPipe
                        || error == WindowsPipeNativeMethods.ErrorPipeNotConnected
                        || error == WindowsPipeNativeMethods.ErrorNoData)
                    {
                        code = EngineProtocol.ErrorCodes.BadResponse;
                        return -2;
                    }
                    if (error == WindowsPipeNativeMethods.ErrorOperationAborted)
                    {
                        code = EngineProtocol.ErrorCodes.Timeout;
                        return -1;
                    }
                    return -2;
                }

                uint transferred;
                bool waitZeroTransferProven;
                if (!TryWait(
                    handle,
                    context,
                    deadline,
                    monotonicDeadline,
                    cancellationToken,
                    environment,
                    out transferred,
                    out waitZeroTransferProven,
                    out code,
                    readDeadline))
                {
                    zeroTransferProven = waitZeroTransferProven;
                    return code == EngineProtocol.ErrorCodes.Timeout ? -1 : -2;
                }
                if (transferred > (uint)count)
                {
                    code = EngineProtocol.ErrorCodes.BadResponse;
                    zeroTransferProven = false;
                    return -1;
                }
                zeroTransferProven = transferred == 0;
                if (transferred > 0)
                {
                    context.CopyFromNative(buffer, offset, (int)transferred);
                }
                return transferred == 0 ? 0 : (int)transferred;
            }
        }

        internal static int TryWriteSome(
            IntPtr handle,
            byte[] buffer,
            int offset,
            int count,
            DateTimeOffset deadline,
            CancellationToken cancellationToken,
            WindowsPipeIoEnvironment environment,
            out string code)
        {
            if (environment == null)
            {
                code = EngineProtocol.ErrorCodes.EngineUnavailable;
                return -1;
            }
            long monotonicDeadline = CreateMonotonicDeadline(deadline - environment.Now());
            return TryWriteSome(
                handle,
                buffer,
                offset,
                count,
                deadline,
                monotonicDeadline,
                cancellationToken,
                environment,
                out code);
        }

        internal static int TryWriteSome(
            IntPtr handle,
            byte[] buffer,
            int offset,
            int count,
            DateTimeOffset deadline,
            long monotonicDeadline,
            CancellationToken cancellationToken,
            WindowsPipeIoEnvironment environment,
            out string code)
        {
            WriteStep step = TryWriteStep(
                handle,
                buffer,
                offset,
                count,
                deadline,
                monotonicDeadline,
                cancellationToken,
                environment);
            code = step.Bytes > 0 ? "" : step.Code;
            return step.Bytes > 0 ? step.Bytes : -1;
        }

        // One kernel write attempt and the delivery evidence it produced.
        //
        // Bytes is the positive count of a successful write that the caller
        // may advance past. Started is true when a kernel write operation
        // began. ZeroDeliveryProven is true only when the completed operation
        // is proven to have delivered no byte. A failed completion has an
        // unknown count and never proves no delivery.
        private struct WriteStep
        {
            public int Bytes;
            public bool Started;
            public bool ZeroDeliveryProven;
            public string Code;
        }

        private static WriteStep TryWriteStep(
            IntPtr handle,
            byte[] buffer,
            int offset,
            int count,
            DateTimeOffset deadline,
            long monotonicDeadline,
            CancellationToken cancellationToken,
            WindowsPipeIoEnvironment environment)
        {
            WriteStep step = new WriteStep();
            step.Code = EngineProtocol.ErrorCodes.EngineUnavailable;
            if (buffer == null || offset < 0 || count <= 0 || offset > buffer.Length
                || count > buffer.Length - offset || environment == null)
            {
                return step;
            }
            if (cancellationToken.IsCancellationRequested)
            {
                // A canceled write starts no kernel operation and allocates
                // no unmanaged buffer.
                step.Code = EngineProtocol.ErrorCodes.Timeout;
                return step;
            }
            if (deadline <= environment.Now())
            {
                // An already expired budget starts no kernel operation.
                step.Code = EngineProtocol.ErrorCodes.Timeout;
                return step;
            }

            using (WindowsOverlappedContext context = new WindowsOverlappedContext(environment))
            {
                if (!context.Valid)
                {
                    return step;
                }
                IntPtr pointer = context.PrepareBuffer(buffer, offset, count);
                context.CopyToNative(buffer, offset, count);
                context.BeginOperation();
                step.Started = true;
                bool ok = environment.Native.WriteFile(
                    handle,
                    pointer,
                    (uint)count,
                    context.OverlappedPointer);
                int error = ok
                    ? WindowsPipeNativeMethods.ErrorSuccess
                    : environment.Native.GetLastError();
                if (ok)
                {
                    OverlappedCompletion completion = TryGetSynchronousCompletion(
                        handle,
                        context,
                        environment);
                    if (!completion.Proven)
                    {
                        // The kernel may still own the records. Dispose moves
                        // the context to the quarantine.
                        step.Code = EngineProtocol.ErrorCodes.EngineUnavailable;
                        return step;
                    }
                    if (!completion.Succeeded)
                    {
                        step.Code = completion.Error == WindowsPipeNativeMethods.ErrorOperationAborted
                            ? EngineProtocol.ErrorCodes.Timeout
                            : EngineProtocol.ErrorCodes.EngineUnavailable;
                        step.ZeroDeliveryProven = completion.CountKnown
                            && completion.Bytes == 0;
                        return step;
                    }
                    if (!completion.CountKnown || completion.Bytes > (uint)count)
                    {
                        // A successful write must report a count within the
                        // requested bytes. Without that proof the delivery is
                        // unknown.
                        step.Code = EngineProtocol.ErrorCodes.EngineUnavailable;
                        return step;
                    }
                    step.Bytes = (int)completion.Bytes;
                    step.ZeroDeliveryProven = completion.Bytes == 0;
                    return step;
                }
                if (error == WindowsPipeNativeMethods.ErrorIoIncomplete)
                {
                    // An incomplete result never proves completion. Leave the
                    // context in the operating state so Dispose quarantines
                    // the event and the unmanaged records.
                    step.Code = EngineProtocol.ErrorCodes.EngineUnavailable;
                    return step;
                }
                if (error != WindowsPipeNativeMethods.ErrorIoPending)
                {
                    // No operation is pending, but delivery remains unknown.
                    context.ProveCompletion();
                    step.Code = error == WindowsPipeNativeMethods.ErrorOperationAborted
                        ? EngineProtocol.ErrorCodes.Timeout
                        : EngineProtocol.ErrorCodes.EngineUnavailable;
                    return step;
                }

                uint transferred;
                bool waitZeroTransferProven;
                string code;
                if (!TryWait(
                    handle,
                    context,
                    deadline,
                    monotonicDeadline,
                    cancellationToken,
                    environment,
                    out transferred,
                    out waitZeroTransferProven,
                    out code))
                {
                    // An unknown count is not a no-delivery proof.
                    step.Code = code;
                    step.ZeroDeliveryProven = waitZeroTransferProven;
                    return step;
                }
                if (transferred == 0 || transferred > (uint)count)
                {
                    step.Code = EngineProtocol.ErrorCodes.EngineUnavailable;
                    return step;
                }
                step.Bytes = (int)transferred;
                return step;
            }
        }

        private static bool TryWait(
            IntPtr handle,
            WindowsOverlappedContext context,
            DateTimeOffset deadline,
            long monotonicDeadline,
            CancellationToken cancellationToken,
            WindowsPipeIoEnvironment environment,
            out uint transferred,
            out bool zeroTransferProven,
            out string code,
            EngineServiceReadDeadline readDeadline = null)
        {
            transferred = 0;
            zeroTransferProven = false;
            while (true)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    return TryAbort(
                        handle,
                        context,
                        environment,
                        true,
                        out transferred,
                        out zeroTransferProven,
                        out code);
                }
                bool expired = readDeadline == null
                    ? MonotonicDeadlineReached(monotonicDeadline) : readDeadline.TryExpire();
                // Preserve the legacy monotonic cap before consulting UTC.
                // The server path never consults UTC at all.
                TimeSpan remaining = expired ? TimeSpan.Zero : readDeadline == null
                    ? deadline - environment.Now() : readDeadline.Remaining;
                if (expired || (readDeadline == null && remaining <= TimeSpan.Zero))
                {
                    return TryAbort(
                        handle, context, environment, true,
                        out transferred, out zeroTransferProven, out code);
                }
                double milliseconds = remaining.TotalMilliseconds;
                uint slice = milliseconds < 1.0
                    ? 1
                    : (milliseconds > 250.0 ? 250 : (uint)milliseconds);
                uint wait = environment.Native.WaitForSingleObject(
                    context.EventHandle,
                    slice);
                if (wait == WindowsPipeNativeMethods.WaitObject0)
                {
                    break;
                }
                if (wait == WindowsPipeNativeMethods.WaitTimeout)
                {
                    continue;
                }
                return TryAbort(
                    handle,
                    context,
                    environment,
                    false,
                    out transferred,
                    out zeroTransferProven,
                    out code);
            }

            if (readDeadline != null
                && (cancellationToken.IsCancellationRequested || readDeadline.TryExpire()))
            {
                return TryAbort(handle, context, environment, true,
                    out transferred, out zeroTransferProven, out code);
            }

            OverlappedCompletion completion = TryCollectCompletion(
                handle,
                context,
                environment);
            if (!completion.Proven)
            {
                return TryAbort(
                    handle,
                    context,
                    environment,
                    false,
                    out transferred,
                    out zeroTransferProven,
                    out code);
            }
            context.ProveCompletion();
            transferred = completion.CountKnown ? completion.Bytes : 0;
            // A known zero count is the only idle-safe completion. A positive
            // count, and an unknown count, mean the read may have consumed a
            // byte.
            zeroTransferProven = completion.CountKnown && completion.Bytes == 0;
            if (completion.Succeeded)
            {
                if (!completion.CountKnown)
                {
                    // A successful operation must report its count. Without it
                    // the stream position is unknown, so the caller closes the
                    // pipe.
                    transferred = 0;
                    zeroTransferProven = false;
                    code = EngineProtocol.ErrorCodes.EngineUnavailable;
                    return false;
                }
                // Collection can finish after the wait observed readiness.
                // Accept only a completion observed within the server budget.
                // Its count remains transfer evidence even when it is late;
                // it cannot prove when the bytes first became available.
                if (readDeadline != null
                    && (cancellationToken.IsCancellationRequested || readDeadline.TryExpire()))
                {
                    code = EngineProtocol.ErrorCodes.Timeout;
                    return false;
                }
                code = "";
                return true;
            }
            code = completion.Error == WindowsPipeNativeMethods.ErrorOperationAborted
                ? EngineProtocol.ErrorCodes.Timeout
                : EngineProtocol.ErrorCodes.EngineUnavailable;
            return false;
        }

        // One collected overlapped completion.
        //
        // Proven is true only for a documented completed result. Succeeded is
        // the GetOverlappedResult success flag. CountKnown is false when the
        // completed operation did not report a documented byte count. A
        // failed completion never supplies transfer-count proof.
        private struct OverlappedCompletion
        {
            public bool Proven;
            public bool Succeeded;
            public bool CountKnown;
            public uint Bytes;
            public int Error;
        }

        private static OverlappedCompletion TryGetSynchronousCompletion(
            IntPtr handle,
            WindowsOverlappedContext context,
            WindowsPipeIoEnvironment environment)
        {
            OverlappedCompletion completion = TryCollectCompletion(
                handle,
                context,
                environment);
            if (completion.Proven)
            {
                context.ProveCompletion();
            }
            return completion;
        }

        private static OverlappedCompletion TryCollectCompletion(
            IntPtr handle,
            WindowsOverlappedContext context,
            WindowsPipeIoEnvironment environment)
        {
            WindowsPipeNativeResult result = environment.Native.GetOverlappedResult(
                handle,
                context.OverlappedPointer,
                false);
            OverlappedCompletion completion = new OverlappedCompletion();
            completion.Error = result.Ok
                ? WindowsPipeNativeMethods.ErrorSuccess
                : result.Error;
            if (result.Ok)
            {
                completion.Proven = true;
                completion.Succeeded = true;
                completion.CountKnown = result.CountKnown;
                completion.Bytes = result.CountKnown ? result.Transferred : 0;
                return completion;
            }
            if (IsCompletionProofError(result.Error))
            {
                // Completion releases the records, but does not prove a count.
                completion.Proven = true;
                completion.Succeeded = false;
                completion.CountKnown = false;
                completion.Bytes = 0;
            }
            // ERROR_IO_PENDING, ERROR_IO_INCOMPLETE, a closed handle, and every
            // unknown result are not completion proof. The kernel might still
            // hold the unmanaged OVERLAPPED and the buffer.
            return completion;
        }

        // Only documented completed-failure results prove that the kernel has
        // stopped using the OVERLAPPED and the buffer. Everything else,
        // including ERROR_IO_INCOMPLETE (996), fails closed.
        private static bool IsCompletionProofError(int error)
        {
            return WindowsPipeNativeMethods.IsOverlappedCompletionError(error);
        }

        // A cancellation request is not a completion proof. CancelIoEx can
        // fail because the operation completed first or because the caller
        // closed the handle. Only the operation event and the collected result
        // prove that the kernel no longer touches the OVERLAPPED or the buffer.
        //
        // A successful completion can prove its count. A failed completion
        // cannot prove zero and the caller must close the pipe.
        private static bool TryAbort(
            IntPtr handle,
            WindowsOverlappedContext context,
            WindowsPipeIoEnvironment environment,
            bool timeout,
            out uint transferred,
            out bool zeroTransferProven,
            out string code)
        {
            OverlappedCompletion completion;
            if (!TryCancelAndProve(handle, context, environment, out completion))
            {
                // The context remains unproven. Its Dispose moves it to the
                // quarantine instead of freeing live kernel memory.
                transferred = 0;
                zeroTransferProven = false;
                code = EngineProtocol.ErrorCodes.EngineUnavailable;
                return false;
            }
            transferred = completion.CountKnown ? completion.Bytes : 0;
            zeroTransferProven = completion.CountKnown && completion.Bytes == 0;
            code = timeout
                ? EngineProtocol.ErrorCodes.Timeout
                : EngineProtocol.ErrorCodes.EngineUnavailable;
            return false;
        }

        private static bool TryCancelAndProve(
            IntPtr handle,
            WindowsOverlappedContext context,
            WindowsPipeIoEnvironment environment,
            out OverlappedCompletion completion)
        {
            completion = new OverlappedCompletion();
            // A false return is not a failure that can be ignored, but it is
            // also not proof of completion. ERROR_NOT_FOUND means the
            // operation completed before the cancel. A closed handle also
            // settles its operations. The event wait below is the only
            // accepted proof in every case.
            environment.Native.CancelIoEx(
                handle,
                context.OverlappedPointer);

            uint wait = environment.Native.WaitForSingleObject(
                context.EventHandle,
                CompletionProofWaitMilliseconds);
            if (wait != WindowsPipeNativeMethods.WaitObject0)
            {
                return false;
            }

            OverlappedCompletion collected = TryCollectCompletion(
                handle,
                context,
                environment);
            if (!collected.Proven)
            {
                return false;
            }
            context.ProveCompletion();
            completion = collected;
            return true;
        }
    }
}
