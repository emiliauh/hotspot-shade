using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost
{
    // A monotonic source for the host budgets. Production uses Stopwatch. A
    // hermetic check supplies a fake so a wall-clock step cannot change a
    // readiness or stop decision.
    internal interface IEngineServiceHostMonotonicClock
    {
        long Timestamp { get; }

        long Frequency { get; }
    }

    internal sealed class EngineServiceHostStopwatchClock : IEngineServiceHostMonotonicClock
    {
        public static readonly EngineServiceHostStopwatchClock Instance =
            new EngineServiceHostStopwatchClock();

        private EngineServiceHostStopwatchClock()
        {
        }

        public long Timestamp
        {
            get { return Stopwatch.GetTimestamp(); }
        }

        public long Frequency
        {
            get { return Stopwatch.Frequency; }
        }
    }

    // The service-host foundation, driven by an injected control seam. It
    // reports start and stop states, applies a start readiness proof and a
    // stop budget with checkpoints, and runs exactly one generation. It never
    // installs a service, never starts a service through the SCM, never
    // restarts a listener, and never launches an engine.
    public sealed class EngineServiceHost
    {
        private readonly EngineServiceHostOptions options;
        private readonly EngineServiceInstalledAccountGate installedAccountGate;
        private readonly EngineServiceDurableStateGate stateGate;
        private readonly IEngineServiceListenerFactory listenerFactory;
        private readonly IEngineServiceHostControl control;
        private readonly IEngineServiceEventSink events;
        private readonly IEngineServiceHostMonotonicClock clock;
        private int ran;
        private int disabled;

        public EngineServiceHost(
            EngineServiceHostOptions options,
            EngineServiceInstalledAccountGate installedAccountGate,
            EngineServiceDurableStateGate stateGate,
            IEngineServiceListenerFactory listenerFactory,
            IEngineServiceHostControl control,
            IEngineServiceEventSink events)
            : this(
                options,
                installedAccountGate,
                stateGate,
                listenerFactory,
                control,
                events,
                EngineServiceHostStopwatchClock.Instance)
        {
        }

        internal EngineServiceHost(
            EngineServiceHostOptions options,
            EngineServiceInstalledAccountGate installedAccountGate,
            EngineServiceDurableStateGate stateGate,
            IEngineServiceListenerFactory listenerFactory,
            IEngineServiceHostControl control,
            IEngineServiceEventSink events,
            IEngineServiceHostMonotonicClock clock)
        {
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }
            options.Validate();
            if (installedAccountGate == null)
            {
                throw new ArgumentNullException("installedAccountGate");
            }
            if (stateGate == null)
            {
                throw new ArgumentNullException("stateGate");
            }
            if (listenerFactory == null)
            {
                throw new ArgumentNullException("listenerFactory");
            }
            if (control == null)
            {
                throw new ArgumentNullException("control");
            }
            if (events == null)
            {
                throw new ArgumentNullException("events");
            }
            if (clock == null)
            {
                throw new ArgumentNullException("clock");
            }
            if (clock.Frequency <= 0)
            {
                throw new ArgumentOutOfRangeException("clock");
            }
            this.options = options;
            this.installedAccountGate = installedAccountGate;
            this.stateGate = stateGate;
            this.listenerFactory = listenerFactory;
            this.control = control;
            this.events = events;
            this.clock = clock;
        }

        public async Task<EngineServiceHostResult> RunAsync(CancellationToken cancellationToken)
        {
            if (Volatile.Read(ref disabled) != 0)
            {
                return EngineServiceHostResult.DisabledFailure(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    EngineServiceHostState.Stopped,
                    0);
            }
            if (Interlocked.CompareExchange(ref ran, 1, 0) != 0)
            {
                events.Record(EngineServiceEventCodes.SecondStartRefused);
                return EngineServiceHostResult.Failure(
                    EngineProtocol.ErrorCodes.Busy,
                    EngineServiceHostState.Stopped,
                    0);
            }
            if (cancellationToken.IsCancellationRequested)
            {
                return EngineServiceHostResult.Failure(
                    EngineProtocol.ErrorCodes.Closed,
                    EngineServiceHostState.Stopped,
                    0);
            }

            ReportCounter reports = new ReportCounter();
            Report(reports, EngineServiceHostState.StartPending, 1, options.StartWaitHint);

            // The configured account must be proven a user account before a
            // pipe exists. The core constructor is only a form check.
            EngineServiceCallerVerdict account =
                await installedAccountGate.VerifyAsync(cancellationToken).ConfigureAwait(false);
            if (account == null || !account.Allowed)
            {
                string accountCode = account == null
                    ? EngineProtocol.ErrorCodes.BoundaryAuthFailed
                    : account.Code;
                string accountEvent = account == null || string.IsNullOrEmpty(account.EventCode)
                    ? EngineServiceEventCodes.CallerAccountTypeFailed
                    : account.EventCode;
                events.Record(accountEvent);
                Report(reports, EngineServiceHostState.Stopped, 0, TimeSpan.Zero);
                return EngineServiceHostResult.Failure(
                    accountCode,
                    EngineServiceHostState.Stopped,
                    reports.Count);
            }

            EngineServiceStateRecord record;
            string code;
            if (!stateGate.TryRead(out record, out code))
            {
                events.Record(EngineServiceEventCodes.StateReadFailed);
                Report(reports, EngineServiceHostState.Stopped, 0, TimeSpan.Zero);
                return EngineServiceHostResult.Failure(
                    code,
                    EngineServiceHostState.Stopped,
                    reports.Count);
            }

            if (cancellationToken.IsCancellationRequested)
            {
                Report(reports, EngineServiceHostState.Stopped, 0, TimeSpan.Zero);
                return EngineServiceHostResult.Failure(
                    EngineProtocol.ErrorCodes.Closed,
                    EngineServiceHostState.Stopped,
                    reports.Count);
            }

            IEngineServiceListener listener;
            if (!listenerFactory.TryCreate(out listener, out code) || listener == null)
            {
                events.Record(EngineServiceEventCodes.ListenerCreateFailed);
                Report(reports, EngineServiceHostState.Stopped, 0, TimeSpan.Zero);
                return EngineServiceHostResult.Failure(
                    EngineProtocol.IsKnownErrorCode(code)
                        ? code
                        : EngineProtocol.ErrorCodes.EngineUnavailable,
                    EngineServiceHostState.Stopped,
                    reports.Count);
            }

            bool runCompleted = false;
            CancellationTokenSource stop = null;
            try
            {
                stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                Task<EngineServiceListenerResult> run;
                try
                {
                    run = listener.RunAsync(stop.Token);
                }
                catch (Exception)
                {
                    runCompleted = true;
                    Report(reports, EngineServiceHostState.Stopped, 0, TimeSpan.Zero);
                    return EngineServiceHostResult.Failure(
                        EngineProtocol.ErrorCodes.Internal,
                        EngineServiceHostState.Stopped,
                        reports.Count);
                }

                // Running is a claim that the listener can accept a client.
                // It is reported only after the listener proves its first pipe
                // instance exists and only when no start cancellation won.
                bool wasReady = await WaitForReadyAsync(
                    listener,
                    run,
                    reports,
                    cancellationToken).ConfigureAwait(false);
                bool reportedRunning = false;

                if (run.IsCompleted)
                {
                    // The listener ended before the host could claim Running.
                    // Readiness alone is not a live generation: never report
                    // Running for a run that already finished. Its own result
                    // still decides success or failure.
                    Report(reports, EngineServiceHostState.Stopped, 0, TimeSpan.Zero);
                    runCompleted = true;
                    return await FinishRunAsync(
                        run,
                        reports,
                        wasReady,
                        cancellationToken,
                        false).ConfigureAwait(false);
                }

                if (wasReady && !cancellationToken.IsCancellationRequested)
                {
                    // Recheck immediately before the state transition. The
                    // listener can finish between the wait and this point.
                    if (!run.IsCompleted)
                    {
                        Report(reports, EngineServiceHostState.Running, 0, TimeSpan.Zero);
                        reportedRunning = true;
                    }
                    while (!run.IsCompleted && !cancellationToken.IsCancellationRequested)
                    {
                        await Task.WhenAny(
                            run,
                            Task.Delay(options.CheckpointInterval)).ConfigureAwait(false);
                    }
                }

                Report(reports, EngineServiceHostState.StopPending, 1, options.StopWaitHint);
                stop.Cancel();

                runCompleted = await WaitForStopAsync(run, reports).ConfigureAwait(false);
                if (!runCompleted && run.IsCompleted)
                {
                    // Recheck once more before the host reports a timeout.
                    // The listener can finish after the wait saw the last
                    // budget slice but before the host decides.
                    runCompleted = true;
                }
                if (!runCompleted)
                {
                    // The run may still own a pipe and a session. Do not
                    // report Stopped, do not dispose its gate, and do not
                    // release its token source. A future SCM adapter sets a
                    // service-specific exit code after this failure.
                    events.Record(EngineServiceEventCodes.StopTimeout);
                    return EngineServiceHostResult.Failure(
                        EngineProtocol.ErrorCodes.EngineStopTimeout,
                        EngineServiceHostState.StopPending,
                        reports.Count);
                }

                Report(reports, EngineServiceHostState.Stopped, 0, TimeSpan.Zero);
                return await FinishRunAsync(
                    run,
                    reports,
                    wasReady,
                    cancellationToken,
                    reportedRunning).ConfigureAwait(false);
            }
            finally
            {
                if (runCompleted)
                {
                    if (stop != null)
                    {
                        stop.Dispose();
                    }
                    try
                    {
                        listener.Dispose();
                    }
                    catch (Exception)
                    {
                        // A failed dispose cannot turn a failed stop into a
                        // clean one. The host result already carries the
                        // failure.
                    }
                }
            }
        }

        private async Task<bool> WaitForReadyAsync(
            IEngineServiceListener listener,
            Task<EngineServiceListenerResult> run,
            ReportCounter reports,
            CancellationToken cancellationToken)
        {
            Task<bool> ready;
            try
            {
                ready = listener.Ready;
            }
            catch (Exception)
            {
                return false;
            }
            if (ready == null)
            {
                return false;
            }

            // The budget is monotonic. A wall-clock step must not extend or
            // shorten the readiness wait.
            long deadline = CreateMonotonicDeadline(options.StartBudget);
            int checkpoint = 1;
            while (true)
            {
                if (ready.IsCompleted)
                {
                    break;
                }
                if (run.IsCompleted || cancellationToken.IsCancellationRequested)
                {
                    return false;
                }
                TimeSpan remaining = MonotonicRemaining(deadline);
                if (remaining <= TimeSpan.Zero)
                {
                    // Final completion recheck at the budget boundary. A
                    // readiness proof that landed in the last window still
                    // counts.
                    if (ready.IsCompleted)
                    {
                        break;
                    }
                    return false;
                }
                TimeSpan slice = remaining < options.CheckpointInterval
                    ? remaining
                    : options.CheckpointInterval;
                if (slice < TimeSpan.FromMilliseconds(1))
                {
                    slice = TimeSpan.FromMilliseconds(1);
                }
                await Task.WhenAny(
                    run,
                    ready,
                    Task.Delay(slice)).ConfigureAwait(false);
                if (ready.IsCompleted)
                {
                    break;
                }
                if (run.IsCompleted || cancellationToken.IsCancellationRequested)
                {
                    return false;
                }
                checkpoint++;
                Report(
                    reports,
                    EngineServiceHostState.StartPending,
                    checkpoint,
                    options.StartWaitHint);
            }

            if (ready.Status != TaskStatus.RanToCompletion)
            {
                return false;
            }
            return ready.Result;
        }

        private async Task<EngineServiceHostResult> FinishRunAsync(
            Task<EngineServiceListenerResult> run,
            ReportCounter reports,
            bool wasReady,
            CancellationToken cancellationToken,
            bool reportedRunning)
        {
            EngineServiceListenerResult result;
            try
            {
                result = await run.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return EngineServiceHostResult.Failure(
                    EngineProtocol.ErrorCodes.Closed,
                    EngineServiceHostState.Stopped,
                    reports.Count);
            }
            catch (Exception)
            {
                return EngineServiceHostResult.Failure(
                    EngineProtocol.ErrorCodes.Internal,
                    EngineServiceHostState.Stopped,
                    reports.Count);
            }

            if (result == null)
            {
                return EngineServiceHostResult.Failure(
                    EngineProtocol.ErrorCodes.Internal,
                    EngineServiceHostState.Stopped,
                    reports.Count);
            }

            if (result.Fatal)
            {
                // A failed caller revert already requested termination or
                // disablement. This host refuses every later generation.
                Interlocked.Exchange(ref disabled, 1);
                return EngineServiceHostResult.DisabledFailure(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    EngineServiceHostState.Stopped,
                    reports.Count);
            }

            if (!wasReady && !cancellationToken.IsCancellationRequested)
            {
                events.Record(EngineServiceEventCodes.ListenerNotReady);
            }

            if (!result.Ok || result.Cleanup != EngineServiceCleanup.Ok)
            {
                return EngineServiceHostResult.Failure(
                    result.Ok
                        ? EngineProtocol.ErrorCodes.CleanupBlocked
                        : result.Code,
                    EngineServiceHostState.Stopped,
                    reports.Count);
            }

            if (!wasReady)
            {
                // A listener cannot claim a clean generation if it never
                // proved readiness. Cancellation keeps the closed result,
                // because no stop failure was reported above.
                return EngineServiceHostResult.Failure(
                    cancellationToken.IsCancellationRequested
                        ? EngineProtocol.ErrorCodes.Closed
                        : EngineProtocol.ErrorCodes.EngineUnavailable,
                    EngineServiceHostState.Stopped,
                    reports.Count);
            }

            if (cancellationToken.IsCancellationRequested && !reportedRunning)
            {
                return EngineServiceHostResult.Failure(
                    EngineProtocol.ErrorCodes.Closed,
                    EngineServiceHostState.Stopped,
                    reports.Count);
            }

            return EngineServiceHostResult.Success(
                EngineServiceHostState.Stopped,
                reports.Count);
        }

        private async Task<bool> WaitForStopAsync(
            Task<EngineServiceListenerResult> run,
            ReportCounter reports)
        {
            // The budget is monotonic. A wall-clock step must not extend or
            // shorten the stop wait.
            long deadline = CreateMonotonicDeadline(options.StopBudget);
            int checkpoint = 1;
            while (true)
            {
                if (run.IsCompleted)
                {
                    return true;
                }
                TimeSpan remaining = MonotonicRemaining(deadline);
                if (remaining <= TimeSpan.Zero)
                {
                    // Final completion recheck at the budget boundary. A run
                    // that finished in the last window is not a timeout.
                    return run.IsCompleted;
                }
                TimeSpan slice = remaining < options.CheckpointInterval
                    ? remaining
                    : options.CheckpointInterval;
                if (slice < TimeSpan.FromMilliseconds(1))
                {
                    slice = TimeSpan.FromMilliseconds(1);
                }
                await Task.WhenAny(
                    run,
                    Task.Delay(slice)).ConfigureAwait(false);
                if (run.IsCompleted)
                {
                    return true;
                }
                checkpoint++;
                Report(
                    reports,
                    EngineServiceHostState.StopPending,
                    checkpoint,
                    options.StopWaitHint);
            }
        }

        private long CreateMonotonicDeadline(TimeSpan budget)
        {
            long now = clock.Timestamp;
            if (budget <= TimeSpan.Zero)
            {
                return now;
            }
            double ticks = budget.TotalSeconds * clock.Frequency;
            if (ticks >= (double)(long.MaxValue - now))
            {
                return long.MaxValue;
            }
            return now + (long)ticks;
        }

        private TimeSpan MonotonicRemaining(long deadline)
        {
            long now = clock.Timestamp;
            if (now >= deadline)
            {
                return TimeSpan.Zero;
            }
            double seconds = (deadline - now) / (double)clock.Frequency;
            if (seconds <= 0)
            {
                return TimeSpan.Zero;
            }
            return TimeSpan.FromSeconds(seconds);
        }

        private void Report(
            ReportCounter reports,
            EngineServiceHostState state,
            int checkpoint,
            TimeSpan waitHint)
        {
            reports.Count++;
            try
            {
                control.ReportState(state, checkpoint, waitHint);
            }
            catch (Exception)
            {
                // A status report failure must not change the host decision.
                // A future SCM adapter treats a failed SetServiceStatus as a
                // fatal service condition.
            }
        }

        private sealed class ReportCounter
        {
            public int Count;
        }
    }
}
