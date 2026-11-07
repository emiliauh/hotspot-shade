using System;
using System.Threading;
using System.Threading.Tasks;

namespace HotspotShade.WinUI2.Core.Engine
{
    public enum EngineStartupState
    {
        Idle,
        Launching,
        Connecting,
        Connected,
        Failed,
        Closed
    }

    // The app-side startup and stop lifecycle for the Windows engine.
    //
    // Placement: this class belongs to the process that owns the engine, which
    // is the full-trust broker. The UWP window cannot create an inheritable
    // handle or start a full-trust process, so it talks to the broker through
    // IEngineBroker over an app service and never holds a handle or a secret.
    // The broker uses this class and EngineBoundary to keep one engine, serve
    // status, and stop the engine when the app is gone.
    //
    // It launches the engine at most once, connects the status session, and
    // turns the tunnel on only when a person asks for it. It never retries a
    // failed launch on its own and never restarts a tunnel. Every stop path is
    // bounded and runs even when the engine does not answer.
    //
    // The host owns the two inherited handles and the engine process. This
    // class owns the launch secret for exactly one launch call and clears it
    // when that call returns.
    public sealed class EngineStartup
    {
        private readonly object gate = new object();
        private readonly IEngineHost host;
        private readonly EngineBoundary boundary;
        private readonly TimeSpan launchTimeout;
        private readonly TimeSpan hostCloseGrace;

        private Task<EngineCommandResult> ensure;
        private EngineCommandResult failureResult;
        private EngineLaunchPlan activePlan;
        private int state = (int)EngineStartupState.Idle;
        private EngineLaunchFailure lastFailure = EngineLaunchFailure.None;
        private EngineHostCloseState lastClose = EngineHostCloseState.None;

        public EngineStartup(IEngineHost host, EngineBoundary boundary)
            : this(host, boundary, EngineLaunchTiming.Launch, EngineLaunchTiming.HostClose)
        {
        }

        public EngineStartup(
            IEngineHost host,
            EngineBoundary boundary,
            TimeSpan launchTimeout,
            TimeSpan hostCloseGrace)
        {
            if (host == null)
            {
                throw new ArgumentNullException("host");
            }
            if (boundary == null)
            {
                throw new ArgumentNullException("boundary");
            }
            if (launchTimeout <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException("launchTimeout");
            }
            if (hostCloseGrace <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException("hostCloseGrace");
            }
            this.host = host;
            this.boundary = boundary;
            this.launchTimeout = launchTimeout;
            this.hostCloseGrace = hostCloseGrace;
        }

        public EngineBoundary Boundary
        {
            get { return boundary; }
        }

        public EngineStartupState State
        {
            get { return (EngineStartupState)Volatile.Read(ref state); }
        }

        public EngineLaunchFailure LastLaunchFailure
        {
            get { return lastFailure; }
        }

        public EngineHostCloseState LastHostCloseState
        {
            get { return lastClose; }
        }

        public bool IsBusy
        {
            get
            {
                EngineStartupState current = State;
                return current == EngineStartupState.Launching
                    || current == EngineStartupState.Connecting;
            }
        }

        // One fixed sentence for the current startup state. It holds no path,
        // handle value, port, or secret.
        public string StatusText
        {
            get
            {
                switch (State)
                {
                    case EngineStartupState.Idle:
                        return "The engine has not started.";
                    case EngineStartupState.Launching:
                        return "Starting the engine.";
                    case EngineStartupState.Connecting:
                        return "Waiting for the engine.";
                    case EngineStartupState.Connected:
                        return "The engine is connected.";
                    case EngineStartupState.Failed:
                        return EngineLaunchText.Reason(lastFailure);
                    default:
                        return EngineLaunchText.Reason(EngineLaunchFailure.Closed);
                }
            }
        }

        // Launch the engine and read its status. This is the page-load path. It
        // never turns the tunnel on. A second call reuses the first result, so a
        // failed launch is not retried and a working engine is not relaunched.
        public Task<EngineCommandResult> EnsureStartedAsync(EngineLaunchPlan plan)
        {
            if (plan == null)
            {
                return Task.FromResult(Fail(EngineLaunchFailure.NotConfigured));
            }
            Task<EngineCommandResult> pending;
            lock (gate)
            {
                if (State == EngineStartupState.Closed)
                {
                    return Task.FromResult(ClosedResult());
                }
                if (ensure == null)
                {
                    if (State == EngineStartupState.Failed)
                    {
                        return Task.FromResult(failureResult ?? ClosedResult());
                    }
                    activePlan = plan;
                    ensure = ConnectOnceAsync(plan);
                }
                else if (activePlan != null && !activePlan.IsSameAs(plan))
                {
                    // A launch already ran. A different engine, port, or handle
                    // pair needs an app restart, so the app never claims to have
                    // moved a working engine to new settings.
                    return Task.FromResult(EngineCommandResult.FailureWithText(
                        EngineLaunchText.WireCode(EngineLaunchFailure.AlreadyStarted),
                        EngineLaunchText.Reason(EngineLaunchFailure.AlreadyStarted),
                        boundary.Session.Status));
                }
                pending = ensure;
            }
            return pending;
        }

        // A person asked to turn the tunnel on. The launch happens first and
        // only once. The start request is sent only through the session, which
        // waits for a fresh status before the app claims the tunnel is on.
        public async Task<EngineCommandResult> StartTunnelAsync(EngineLaunchPlan plan, bool ping)
        {
            EngineCommandResult started = await EnsureStartedAsync(plan).ConfigureAwait(false);
            if (!started.Ok)
            {
                return started;
            }
            return await boundary.StartAsync(ping).ConfigureAwait(false);
        }

        // A person asked to turn the tunnel off. The engine stays launched so a
        // later start needs no second launch.
        public async Task<EngineCommandResult> StopTunnelAsync()
        {
            if (State == EngineStartupState.Closed)
            {
                return ClosedResult();
            }
            return await boundary.StopAsync().ConfigureAwait(false);
        }

        // A person asked to try again after a failed launch. Nothing calls this
        // on a timer and nothing calls it after a host loss.
        public Task<EngineCommandResult> RetryAsync(EngineLaunchPlan plan)
        {
            if (plan == null)
            {
                return Task.FromResult(Fail(EngineLaunchFailure.NotConfigured));
            }
            lock (gate)
            {
                if (State == EngineStartupState.Closed || boundary.Session.IsClosed)
                {
                    return Task.FromResult(ClosedResult());
                }
                if (State == EngineStartupState.Connected)
                {
                    return Task.FromResult(EngineCommandResult.Success(
                        boundary.Session.Status,
                        true,
                        "The engine is already started."));
                }
                if (!boundary.Session.IsClosed
                    && State != EngineStartupState.Failed
                    && State != EngineStartupState.Idle)
                {
                    return Task.FromResult(EngineCommandResult.FailureWithText(
                        EngineProtocol.ErrorCodes.Busy,
                        "Wait for the current action to finish.",
                        boundary.Session.Status));
                }
                ensure = null;
                failureResult = null;
                lastFailure = EngineLaunchFailure.None;
                SetState(EngineStartupState.Idle);
            }
            return EnsureStartedAsync(plan);
        }

        // The host reported that the engine process is gone. The app cannot
        // confirm the tunnel state, and it must not claim that the tunnel is
        // off. A person restarts the app to reconnect.
        public EngineCommandResult HostLost()
        {
            EngineCommandResult result;
            lock (gate)
            {
                if (State == EngineStartupState.Closed)
                {
                    return ClosedResult();
                }
                lastFailure = EngineLaunchFailure.EngineLost;
                SetStateUnlessClosed(EngineStartupState.Failed);
                // A later connect must not replay the first, successful result.
                ensure = null;
                result = EngineCommandResult.FailureWithText(
                    EngineLaunchText.WireCode(EngineLaunchFailure.EngineLost),
                    EngineLaunchText.Reason(EngineLaunchFailure.EngineLost),
                    boundary.Session.Status);
                failureResult = result;
            }
            boundary.Close();
            return result;
        }

        // The exit path. It asks the engine to stop, closes the parent-liveness
        // channel, and closes the app session. Every step runs even when an
        // earlier step fails, and a second call does nothing.
        public async Task<EngineCommandResult> ShutdownAsync()
        {
            Task<EngineCommandResult> pending;
            lock (gate)
            {
                if (State == EngineStartupState.Closed)
                {
                    return ClosedResult();
                }
                SetState(EngineStartupState.Closed);
                pending = ensure;
            }

            // A launch call is bounded by launchTimeout, so this wait is
            // bounded too. It lets a half-started host settle before the close
            // path runs.
            if (pending != null)
            {
                try
                {
                    await pending.ConfigureAwait(false);
                }
                catch (Exception)
                {
                    // The launch failure already travels through its result.
                }
            }

            // Ask the engine to stop first. It may refuse or not answer, so the
            // reply is not the stop signal.
            try
            {
                await boundary.ShutdownAsync().ConfigureAwait(false);
            }
            catch (Exception)
            {
                // The host close below is the authoritative stop path.
            }

            EngineHostCloseState close = await CloseHostAsync().ConfigureAwait(false);
            boundary.Close();

            // The observed engine exit is the stop signal. The engine removes
            // what it created on its exit path, so a refused or unanswered
            // shutdown request does not change the outcome. Only a host that
            // did not exit is reported to the person.
            if (close == EngineHostCloseState.Exited)
            {
                return EngineCommandResult.Success(
                    boundary.Session.Status,
                    true,
                    "The engine stopped.");
            }
            return EngineCommandResult.FailureWithText(
                EngineProtocol.ErrorCodes.EngineUnavailable,
                EngineLaunchText.CloseText(close),
                boundary.Session.Status);
        }

        // The diagnostic record for the target device app. It never holds a
        // secret, a path, a handle value, or a port.
        public string DescribeForDiagnostics()
        {
            return "Engine startup: " + EngineLaunchText.StateWord(State)
                + ". Launch: " + EngineLaunchText.FailureWord(lastFailure)
                + ". Stop: " + EngineLaunchText.CloseWord(lastClose) + ".";
        }

        private async Task<EngineCommandResult> ConnectOnceAsync(EngineLaunchPlan plan)
        {
            SetStateUnlessClosed(EngineStartupState.Launching);
            lastFailure = EngineLaunchFailure.None;
            EngineLaunchSecret secret = EngineLaunchSecret.CreateRandom();
            EngineLaunchOutcome outcome = null;
            try
            {
                if (plan.DisclosesSecret(secret))
                {
                    return Fail(EngineLaunchFailure.SecretDisclosed);
                }
                EngineLaunchRequest request;
                try
                {
                    request = new EngineLaunchRequest(plan, secret);
                }
                catch (ArgumentException)
                {
                    return Fail(EngineLaunchFailure.SecretDisclosed);
                }
                outcome = await LaunchBoundedAsync(request).ConfigureAwait(false);
            }
            finally
            {
                // The host contract requires a copy before LaunchAsync
                // returns. The app keeps no copy after this point, even when
                // the launch timed out and the host is still finishing.
                secret.Clear();
            }

            if (outcome == null)
            {
                await CloseHostAsync().ConfigureAwait(false);
                return Fail(EngineLaunchFailure.LaunchTimeout);
            }
            if (!outcome.Launched)
            {
                await CloseHostAsync().ConfigureAwait(false);
                return Fail(outcome.Failure);
            }

            SetStateUnlessClosed(EngineStartupState.Connecting);
            EngineCommandResult connect;
            try
            {
                connect = await boundary.ConnectAsync().ConfigureAwait(false);
            }
            catch (Exception)
            {
                connect = null;
            }
            if (connect == null || !connect.Ok)
            {
                await CloseHostAsync().ConfigureAwait(false);
                lastFailure = EngineLaunchFailure.ConnectFailed;
                SetStateUnlessClosed(EngineStartupState.Failed);
                failureResult = connect ?? EngineCommandResult.FailureWithText(
                    EngineProtocol.ErrorCodes.EngineUnavailable,
                    EngineLaunchText.Reason(EngineLaunchFailure.ConnectFailed),
                    boundary.Session.Status);
                return failureResult;
            }

            lastFailure = EngineLaunchFailure.None;
            SetStateUnlessClosed(EngineStartupState.Connected);
            return connect;
        }

        // Returns null when the launch call did not finish inside the bound.
        private async Task<EngineLaunchOutcome> LaunchBoundedAsync(EngineLaunchRequest request)
        {
            using (CancellationTokenSource timeout = new CancellationTokenSource())
            {
                Task<EngineLaunchOutcome> call;
                try
                {
                    call = host.LaunchAsync(request, timeout.Token);
                }
                catch (Exception)
                {
                    return EngineLaunchOutcome.Failed(EngineLaunchFailure.BrokerRefused);
                }
                if (call == null)
                {
                    return EngineLaunchOutcome.Failed(EngineLaunchFailure.BrokerRefused);
                }

                Task delay = Task.Delay(launchTimeout, timeout.Token);
                Task completed = await Task.WhenAny(call, delay).ConfigureAwait(false);
                if (completed != call)
                {
                    // The host gets a cancelled token. Do not wait for it and do
                    // not trust a late answer.
                    timeout.Cancel();
                    Observe(call);
                    return null;
                }

                timeout.Cancel();
                try
                {
                    EngineLaunchOutcome outcome = await call.ConfigureAwait(false);
                    return outcome ?? EngineLaunchOutcome.Failed(EngineLaunchFailure.BrokerRefused);
                }
                catch (Exception)
                {
                    return EngineLaunchOutcome.Failed(EngineLaunchFailure.BrokerRefused);
                }
            }
        }

        private async Task<EngineHostCloseState> CloseHostAsync()
        {
            Task<bool> call;
            try
            {
                call = host.CloseAsync(hostCloseGrace);
            }
            catch (Exception)
            {
                lastClose = EngineHostCloseState.NotExited;
                return lastClose;
            }
            if (call == null)
            {
                lastClose = EngineHostCloseState.Exited;
                return lastClose;
            }

            Task delay = Task.Delay(hostCloseGrace);
            if (await Task.WhenAny(call, delay).ConfigureAwait(false) != call)
            {
                Observe(call);
                lastClose = EngineHostCloseState.TimedOut;
                return lastClose;
            }

            try
            {
                lastClose = (await call.ConfigureAwait(false))
                    ? EngineHostCloseState.Exited
                    : EngineHostCloseState.NotExited;
            }
            catch (Exception)
            {
                lastClose = EngineHostCloseState.NotExited;
            }
            return lastClose;
        }

        private EngineCommandResult Fail(EngineLaunchFailure failure)
        {
            if (failure == EngineLaunchFailure.None)
            {
                failure = EngineLaunchFailure.BrokerRefused;
            }
            lastFailure = failure;
            SetStateUnlessClosed(EngineStartupState.Failed);
            failureResult = EngineCommandResult.FailureWithText(
                EngineLaunchText.WireCode(failure),
                EngineLaunchText.Reason(failure),
                boundary.Session.Status);
            return failureResult;
        }

        private EngineCommandResult ClosedResult()
        {
            return EngineCommandResult.FailureWithText(
                EngineLaunchText.WireCode(EngineLaunchFailure.Closed),
                EngineLaunchText.Reason(EngineLaunchFailure.Closed),
                boundary.Session.Status);
        }

        private void SetState(EngineStartupState next)
        {
            Volatile.Write(ref state, (int)next);
        }

        // A launch that is still running must not overwrite the closed state
        // that the stop path set. The stop path then asks the engine to stop
        // through the session that the launch just opened.
        private void SetStateUnlessClosed(EngineStartupState next)
        {
            if (Volatile.Read(ref state) == (int)EngineStartupState.Closed)
            {
                return;
            }
            Volatile.Write(ref state, (int)next);
        }

        private static void Observe(Task task)
        {
            if (task == null)
            {
                return;
            }
            task.ContinueWith(
                delegate(Task finished)
                {
                    Exception error = finished.Exception;
                    if (error != null)
                    {
                        GC.KeepAlive(error);
                    }
                },
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted,
                TaskScheduler.Default);
        }
    }
}
