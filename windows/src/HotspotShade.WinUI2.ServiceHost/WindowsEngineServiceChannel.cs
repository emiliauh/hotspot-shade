using System;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost
{
    // One app-side connection to the service. The channel opens the pipe once,
    // proves the server before the first frame, serializes requests, and
    // proves the SCM state again after each exchange. A transport failure
    // closes the pipe and marks the channel failed. A busy gate or a
    // cancellation before the gate is entered is transient and changes
    // neither. It never reconnects with a wider access mask and never retries
    // a request.
    //
    // The exchange budget is per call. A start reply may take the full service
    // start budget, so the channel never applies one short reply-read budget
    // to every operation.
    //
    // A failed reply read keeps its evidence. A partial or unproven reply read
    // means the request may have been applied and the reply cannot be
    // reassembled: the channel closes the pipe and reports an ambiguous
    // outcome. It never replays the request, never resumes a partial frame,
    // and never reports a proven zero-byte reply read as a successful stop or
    // a successful start.
    public sealed class WindowsEngineServiceChannel :
        IEngineServiceChannel,
        IEngineServiceChannelExchange,
        IDisposable
    {
        private readonly object sync = new object();
        private readonly SemaphoreSlim requestGate = new SemaphoreSlim(1, 1);
        private readonly IEngineServiceClientPipeFactory pipeFactory;
        private readonly EngineServiceServerProof serverProof;
        private IEngineServiceClientPipe pipe;
        private int serviceProcessId;
        private bool failed;
        private bool disposed;
        private string lastFailureCode = "";

        public WindowsEngineServiceChannel(
            IEngineServiceClientPipeFactory pipeFactory,
            EngineServiceServerProof serverProof)
        {
            if (pipeFactory == null)
            {
                throw new ArgumentNullException("pipeFactory");
            }
            if (serverProof == null)
            {
                throw new ArgumentNullException("serverProof");
            }
            this.pipeFactory = pipeFactory;
            this.serverProof = serverProof;
        }

        public string LastFailureCode
        {
            get
            {
                lock (sync)
                {
                    return lastFailureCode;
                }
            }
        }

        // A fixed, nonsecret transport diagnostic from the overlapped I/O
        // quarantine. It never holds a handle, address, path, process id,
        // token, or key.
        public string LastTransportDiagnostic
        {
            get { return WindowsNamedPipeIo.LastOverlappedDiagnostic; }
        }

        // The base channel form. It has no outcome evidence and uses the short
        // budget. A caller that needs the reply-read evidence or a long start
        // budget uses IEngineServiceChannelExchange.
        public async Task<byte[]> ExchangeAsync(
            byte[] requestFrame,
            CancellationToken cancellationToken)
        {
            EngineServiceChannelAnswer answer = await ExchangeAsync(
                requestFrame,
                TimeSpan.FromMilliseconds(EngineServiceCallBudgets.ShortMilliseconds),
                cancellationToken).ConfigureAwait(false);
            return answer == null ? null : answer.Frame;
        }

        public async Task<EngineServiceChannelAnswer> ExchangeAsync(
            byte[] requestFrame,
            TimeSpan budget,
            CancellationToken cancellationToken)
        {
            if (requestFrame == null)
            {
                SetFailure(EngineProtocol.ErrorCodes.BadRequest);
                return EngineServiceChannelAnswer.NotWritten(
                    EngineProtocol.ErrorCodes.BadRequest);
            }
            if (budget <= TimeSpan.Zero)
            {
                // An expired budget starts no pipe operation.
                RecordTransientFailure(EngineProtocol.ErrorCodes.Timeout);
                return EngineServiceChannelAnswer.Failure(
                    EngineProtocol.ErrorCodes.Timeout,
                    true);
            }

            bool entered;
            try
            {
                entered = await requestGate.WaitAsync(0, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // The gate was never entered, so no pipe operation ran. A
                // canceled caller does not poison the channel for later calls.
                RecordTransientFailure(EngineProtocol.ErrorCodes.Timeout);
                return EngineServiceChannelAnswer.Failure(
                    EngineProtocol.ErrorCodes.Timeout,
                    true);
            }
            if (!entered)
            {
                // A busy gate means another exchange owns the pipe. That is a
                // transient condition, not a transport failure. Do not close
                // the pipe or poison the channel.
                bool closed;
                lock (sync)
                {
                    closed = failed || disposed;
                }
                RecordTransientFailure(closed
                    ? EngineProtocol.ErrorCodes.EngineUnavailable
                    : EngineProtocol.ErrorCodes.Busy);
                return EngineServiceChannelAnswer.Failure(
                    closed
                        ? EngineProtocol.ErrorCodes.EngineUnavailable
                        : EngineProtocol.ErrorCodes.Busy,
                    !closed);
            }

            EngineServiceReplyReadProof replyReadProof =
                EngineServiceReplyReadProof.NoReplyRead;
            bool writeAttempted = false;
            bool requestWritten = false;
            try
            {
                string code;
                if (!EnsureConnected(out code))
                {
                    SetFailure(code);
                    return EngineServiceChannelAnswer.NotWritten(code);
                }

                IEngineServiceClientPipe current;
                int expectedProcessId;
                lock (sync)
                {
                    if (failed || disposed || pipe == null)
                    {
                        SetFailureLocked(EngineProtocol.ErrorCodes.EngineUnavailable);
                        return EngineServiceChannelAnswer.NotWritten(
                            EngineProtocol.ErrorCodes.EngineUnavailable);
                    }
                    current = pipe;
                    expectedProcessId = serviceProcessId;
                }

                if (cancellationToken.IsCancellationRequested)
                {
                    // The caller stopped before the write. No part of the
                    // request reached the pipe, so this exchange is not
                    // ambiguous and the channel stays usable.
                    RecordTransientFailure(EngineProtocol.ErrorCodes.Timeout);
                    return EngineServiceChannelAnswer.Failure(
                        EngineProtocol.ErrorCodes.Timeout,
                        true);
                }

                writeAttempted = true;
                EngineServiceRequestWriteProof writeProof =
                    EngineServiceRequestWriteProof.Unproven;
                bool written;
                IEngineServiceClientPipeWriteEvidence evidence =
                    current as IEngineServiceClientPipeWriteEvidence;
                if (evidence != null)
                {
                    written = evidence.TryWriteFrame(
                        requestFrame,
                        budget,
                        cancellationToken,
                        out writeProof,
                        out code);
                }
                else
                {
                    // A pipe without evidence cannot prove that a failed write
                    // started no kernel operation. Treat it as unproven. Only
                    // the checks before this call prove that no write started.
                    written = current.TryWriteFrame(
                        requestFrame,
                        budget,
                        cancellationToken,
                        out code);
                    writeProof = written
                        ? EngineServiceRequestWriteProof.Delivered
                        : EngineServiceRequestWriteProof.Unproven;
                }
                if (!written)
                {
                    if (writeProof == EngineServiceRequestWriteProof.NotStarted)
                    {
                        // The pipe refused before its first kernel write. No
                        // frame byte reached it and the pipe is still at a
                        // frame boundary, so a later exchange may succeed.
                        RecordTransientFailure(code);
                        return EngineServiceChannelAnswer.Failure(code, true);
                    }
                    Fail(code);
                    if (writeProof == EngineServiceRequestWriteProof.NotDelivered)
                    {
                        // Every kernel write completed with a proven zero
                        // transfer. No byte reached the pipe, so this is a
                        // clean refusal even though the pipe is closed.
                        return EngineServiceChannelAnswer.WriteFailed(code, false);
                    }
                    // A kernel write may have delivered part or all of the
                    // frame. The request may already be applied, so the answer
                    // is never a clean refusal.
                    return EngineServiceChannelAnswer.WriteFailed(code, true);
                }
                requestWritten = true;

                byte[] response;
                if (cancellationToken.IsCancellationRequested)
                {
                    // The write finished, so the request is delivered. No
                    // reply read ran and therefore no reply byte arrived.
                    Fail(EngineProtocol.ErrorCodes.Timeout);
                    return EngineServiceChannelAnswer.Ambiguous(
                        EngineProtocol.ErrorCodes.Timeout,
                        EngineServiceReplyReadProof.Missing);
                }

                EngineServiceFrameReadOutcome outcome;
                if (!current.TryReadFrame(
                    budget,
                    cancellationToken,
                    out response,
                    out outcome,
                    out code))
                {
                    // The reply read failed. The evidence decides whether a
                    // reply byte arrived. Every case closes the pipe because
                    // the stream is not at a frame boundary any more.
                    replyReadProof = MapReplyReadProof(outcome);
                    Fail(code);
                    return EngineServiceChannelAnswer.Ambiguous(code, replyReadProof);
                }

                if (!serverProof.TryVerifyAfterExchange(expectedProcessId, out code))
                {
                    // The reply arrived but the server identity could not be
                    // proved again. The request may already be applied, so the
                    // outcome is unknown, not a clean failure.
                    Fail(code);
                    return EngineServiceChannelAnswer.Ambiguous(
                        code,
                        EngineServiceReplyReadProof.Missing);
                }
                return EngineServiceChannelAnswer.Success(response);
            }
            catch (OperationCanceledException)
            {
                // A stop during the reply read is ambiguous. A stop during the
                // request write may have delivered part of the frame. Neither
                // case is a clean refusal. A failure before the write keeps
                // the pipe usable.
                if (requestWritten || writeAttempted)
                {
                    Fail(EngineProtocol.ErrorCodes.Timeout);
                }
                else
                {
                    SetFailure(EngineProtocol.ErrorCodes.Timeout);
                }
                if (requestWritten)
                {
                    return EngineServiceChannelAnswer.Ambiguous(
                        EngineProtocol.ErrorCodes.Timeout,
                        EngineServiceReplyReadProof.Unproven);
                }
                return writeAttempted
                    ? EngineServiceChannelAnswer.WriteFailed(
                        EngineProtocol.ErrorCodes.Timeout,
                        true)
                    : EngineServiceChannelAnswer.Failure(EngineProtocol.ErrorCodes.Timeout, false);
            }
            catch (Exception)
            {
                if (requestWritten || writeAttempted)
                {
                    Fail(EngineProtocol.ErrorCodes.EngineUnavailable);
                }
                else
                {
                    SetFailure(EngineProtocol.ErrorCodes.EngineUnavailable);
                }
                if (requestWritten)
                {
                    return EngineServiceChannelAnswer.Ambiguous(
                        EngineProtocol.ErrorCodes.EngineUnavailable,
                        EngineServiceReplyReadProof.Unproven);
                }
                return writeAttempted
                    ? EngineServiceChannelAnswer.WriteFailed(
                        EngineProtocol.ErrorCodes.EngineUnavailable,
                        true)
                    : EngineServiceChannelAnswer.NotWritten(
                        EngineProtocol.ErrorCodes.EngineUnavailable);
            }
            finally
            {
                requestGate.Release();
            }
        }

        public async Task CloseAsync()
        {
            // Refuse new requests first, then wait for the one exchange that
            // already owns the gate. CloseHandle must not race a pending
            // ReadFile or WriteFile: the kernel can touch the OVERLAPPED and
            // the pinned buffer until that operation completes.
            RequestClose();
            await requestGate.WaitAsync().ConfigureAwait(false);
            try
            {
                lock (sync)
                {
                    ClosePipeLocked();
                }
            }
            finally
            {
                requestGate.Release();
            }
        }

        public void Dispose()
        {
            RequestClose();
            requestGate.Wait();
            try
            {
                lock (sync)
                {
                    ClosePipeLocked();
                }
            }
            finally
            {
                requestGate.Release();
            }
        }

        // A partial or unproven read is never a clean refusal and never an
        // idle read. A proven zero-byte read is the only failure that says no
        // reply byte arrived.
        private static EngineServiceReplyReadProof MapReplyReadProof(
            EngineServiceFrameReadOutcome outcome)
        {
            if (outcome == EngineServiceFrameReadOutcome.Idle)
            {
                return EngineServiceReplyReadProof.Missing;
            }
            if (outcome == EngineServiceFrameReadOutcome.Partial)
            {
                return EngineServiceReplyReadProof.Partial;
            }
            return EngineServiceReplyReadProof.Unproven;
        }

        private void RequestClose()
        {
            lock (sync)
            {
                disposed = true;
            }
        }

        private bool EnsureConnected(out string code)
        {
            lock (sync)
            {
                if (failed || disposed)
                {
                    code = EngineProtocol.ErrorCodes.EngineUnavailable;
                    return false;
                }
                if (pipe != null)
                {
                    code = "";
                    return true;
                }
            }

            int expectedProcessId;
            if (!serverProof.TryVerifyBeforeConnect(out expectedProcessId, out code))
            {
                return false;
            }

            IEngineServiceClientPipe opened;
            if (!pipeFactory.TryOpen(out opened, out code) || opened == null)
            {
                SafeDispose(opened);
                return false;
            }

            try
            {
                if (!serverProof.TryVerifyConnectedServer(opened, expectedProcessId, out code))
                {
                    SafeDispose(opened);
                    return false;
                }
            }
            catch (Exception)
            {
                // A proof or event sink failure must not leak the locally
                // opened pipe handle.
                SafeDispose(opened);
                code = EngineProtocol.ErrorCodes.EngineUnavailable;
                return false;
            }

            lock (sync)
            {
                if (failed || disposed)
                {
                    SafeDispose(opened);
                    code = EngineProtocol.ErrorCodes.EngineUnavailable;
                    return false;
                }
                pipe = opened;
                serviceProcessId = expectedProcessId;
                code = "";
                return true;
            }
        }

        private static void SafeDispose(IEngineServiceClientPipe pipe)
        {
            if (pipe == null)
            {
                return;
            }
            try
            {
                pipe.Dispose();
            }
            catch (Exception)
            {
                // A close failure cannot make the pipe usable again.
            }
        }

        private void Fail(string code)
        {
            lock (sync)
            {
                SetFailureLocked(code);
                ClosePipeLocked();
            }
        }

        private void SetFailure(string code)
        {
            lock (sync)
            {
                SetFailureLocked(code);
            }
        }

        // Records a fixed code without marking the channel failed or closing
        // the pipe. Used for a busy gate and a pre-gate cancellation, where no
        // pipe operation ran and a later exchange can still succeed.
        private void RecordTransientFailure(string code)
        {
            lock (sync)
            {
                lastFailureCode = NormalizeFailureCode(code);
            }
        }

        private static string NormalizeFailureCode(string code)
        {
            return EngineProtocol.IsKnownErrorCode(code)
                ? code
                : EngineProtocol.ErrorCodes.Internal;
        }

        private void SetFailureLocked(string code)
        {
            lastFailureCode = NormalizeFailureCode(code);
            failed = true;
        }

        private void ClosePipeLocked()
        {
            if (pipe != null)
            {
                try
                {
                    pipe.Dispose();
                }
                catch (Exception)
                {
                    // A close failure cannot leave a usable claim.
                }
                pipe = null;
            }
        }
    }
}
