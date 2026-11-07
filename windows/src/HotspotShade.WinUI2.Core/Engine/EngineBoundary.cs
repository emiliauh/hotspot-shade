using System;
using System.Globalization;
using System.Text;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.Core.Engine
{
    public enum EngineBoundaryKind
    {
        NotChecked,
        Checking,
        Unavailable,
        Ready,
        On,
        Attention
    }

    // One read-only view of the engine boundary. The view layer binds these
    // strings and flags. It must not build a tunnel claim from them: only
    // StatusText and IsRunning say "On", and they are set only from a fresh,
    // confirmed engine status.
    public sealed class EngineBoundaryContent
    {
        internal EngineBoundaryContent(
            EngineBoundaryKind kind,
            string title,
            string message,
            string statusText,
            string checkedText,
            string pairingText,
            string sourceText,
            string trustText,
            string connectionText,
            string pingText,
            string stopText,
            string actionText,
            bool isEngineAvailable,
            bool isRunning,
            bool isStatusStale,
            bool isStatusUnknown,
            bool canStart,
            bool canStop,
            bool canForget,
            bool canCheck,
            bool isBusy)
        {
            Kind = kind;
            Title = title ?? "";
            Message = message ?? "";
            StatusText = statusText ?? "";
            CheckedText = checkedText ?? "";
            PairingText = pairingText ?? "";
            SourceText = sourceText ?? "";
            TrustText = trustText ?? "";
            ConnectionText = connectionText ?? "";
            PingText = pingText ?? "";
            StopText = stopText ?? "";
            ActionText = actionText ?? "";
            IsEngineAvailable = isEngineAvailable;
            IsRunning = isRunning;
            IsStatusStale = isStatusStale;
            IsStatusUnknown = isStatusUnknown;
            CanStart = canStart;
            CanStop = canStop;
            CanForget = canForget;
            CanCheck = canCheck;
            IsBusy = isBusy;
        }

        public EngineBoundaryKind Kind { get; private set; }

        public string Title { get; private set; }

        public string Message { get; private set; }

        public string StatusText { get; private set; }

        public string CheckedText { get; private set; }

        public string PairingText { get; private set; }

        public string SourceText { get; private set; }

        public string TrustText { get; private set; }

        public string ConnectionText { get; private set; }

        public string PingText { get; private set; }

        public string StopText { get; private set; }

        public string ActionText { get; private set; }

        public bool IsEngineAvailable { get; private set; }

        // True only for a tunnel that the app can currently confirm.
        public bool IsRunning { get; private set; }

        public bool IsStatusStale { get; private set; }

        public bool IsStatusUnknown { get; private set; }

        public bool CanStart { get; private set; }

        public bool CanStop { get; private set; }

        public bool CanForget { get; private set; }

        public bool CanCheck { get; private set; }

        public bool IsBusy { get; private set; }

        public string AccessibilityText
        {
            get
            {
                StringBuilder text = new StringBuilder();
                text.Append(Title);
                text.Append(". ");
                text.Append(Message);
                text.Append(" Status: ");
                text.Append(StatusText);
                text.Append(". ");
                text.Append(CheckedText);
                if (!string.IsNullOrEmpty(ActionText))
                {
                    text.Append(" ");
                    text.Append(ActionText);
                }
                return text.ToString();
            }
        }
    }

    // The app-side boundary controller. It owns one EngineSession and turns
    // its validated state into display content. It sends no network traffic
    // itself. A transport must implement IEngineBroker and must keep the
    // source device token and the identity key outside this process.
    public sealed class EngineBoundary
    {
        private readonly EngineSession session;
        private readonly IEngineClock clock;
        private string lastMessage;

        public EngineBoundary(IEngineBroker broker, IEngineClock clock)
            : this(broker, clock, EngineServiceCallBudgets.Default)
        {
        }

        // One budget for every operation. This keeps the diagnostic form.
        public EngineBoundary(IEngineBroker broker, IEngineClock clock, TimeSpan callTimeout)
            : this(broker, clock, EngineServiceCallBudgets.Uniform(callTimeout))
        {
        }

        // Per-operation budgets. A start and a stop wait longer than a status
        // read, so a long operation is not cut at the short budget.
        public EngineBoundary(
            IEngineBroker broker,
            IEngineClock clock,
            EngineServiceCallBudgets budgets)
        {
            if (broker == null)
            {
                throw new ArgumentNullException("broker");
            }
            if (clock == null)
            {
                throw new ArgumentNullException("clock");
            }
            if (budgets == null)
            {
                throw new ArgumentNullException("budgets");
            }
            this.clock = clock;
            session = new EngineSession(broker, clock, budgets);
            Content = BuildContent();
        }

        public EngineSession Session
        {
            get { return session; }
        }

        public EngineBoundaryContent Content { get; private set; }

        public async System.Threading.Tasks.Task<EngineCommandResult> ConnectAsync()
        {
            EngineCommandResult result = await session.ConnectAsync().ConfigureAwait(false);
            Publish(result);
            return result;
        }

        // Poll the current state. It connects when no connection exists and
        // refreshes afterwards. It never starts a tunnel and never retries a
        // start or stop on its own.
        public async System.Threading.Tasks.Task<EngineCommandResult> PollAsync()
        {
            EngineCommandResult result;
            if (session.IsClosed)
            {
                result = await session.RefreshAsync().ConfigureAwait(false);
                Publish(result);
                return result;
            }
            if (session.Connection == EngineConnectionState.NotConnected)
            {
                return await ConnectAsync().ConfigureAwait(false);
            }
            result = await session.RefreshAsync().ConfigureAwait(false);
            Publish(result);
            return result;
        }

        public async System.Threading.Tasks.Task<EngineCommandResult> StartAsync(bool ping)
        {
            EngineCommandResult result = await session.StartAsync(ping).ConfigureAwait(false);
            Publish(result);
            return result;
        }

        public async System.Threading.Tasks.Task<EngineCommandResult> StopAsync()
        {
            EngineCommandResult result = await session.StopAsync().ConfigureAwait(false);
            Publish(result);
            return result;
        }

        public async System.Threading.Tasks.Task<EngineCommandResult> ForgetAsync()
        {
            EngineCommandResult result = await session.ForgetAsync().ConfigureAwait(false);
            Publish(result);
            return result;
        }

        public async System.Threading.Tasks.Task<EngineCommandResult> ShutdownAsync()
        {
            EngineCommandResult result = await session.ShutdownAsync().ConfigureAwait(false);
            Publish(result);
            return result;
        }

        // Recompute the clock-dependent freshness without a request. The page
        // calls this before it reads the content on a timer tick.
        public void RefreshView()
        {
            Publish(null);
        }

        public void Close()
        {
            session.Close();
            Publish(null);
        }

        private void Publish(EngineCommandResult result)
        {
            if (result != null)
            {
                if (!result.Ok)
                {
                    lastMessage = result.Message;
                }
                else if (!result.Confirmed && !string.IsNullOrEmpty(result.Message))
                {
                    lastMessage = result.Message;
                }
                else if (result.Confirmed)
                {
                    lastMessage = "";
                }
            }
            Content = BuildContent();
        }

        private EngineBoundaryContent BuildContent()
        {
            EngineStatus status = session.Status;
            EngineFreshness freshness = session.Freshness;
            EngineConnectionState connection = session.Connection;
            bool closed = session.IsClosed;
            bool hasStatus = status != null;
            bool displayable = hasStatus && !closed && freshness != EngineFreshness.Unavailable;
            bool running = session.CanClaimRunning;
            bool stale = displayable && freshness == EngineFreshness.Stale;
            bool unknown = !displayable || connection == EngineConnectionState.Unavailable;
            bool available = !closed
                && connection == EngineConnectionState.Available
                && hasStatus
                && freshness != EngineFreshness.Unavailable;
            bool cleanupBlocks = displayable
                && !running
                && status.Cleanup != EngineCleanup.Ok;

            EngineBoundaryKind kind;
            string title;
            string message;
            if (closed)
            {
                kind = EngineBoundaryKind.Unavailable;
                title = "Engine: connection closed";
                message = "The app is no longer connected to the engine. The tunnel state is unknown.";
            }
            else if (connection == EngineConnectionState.NotConnected)
            {
                kind = EngineBoundaryKind.NotChecked;
                title = "Engine: not checked";
                message = "No engine status yet. The tunnel state is unknown.";
            }
            else if (connection == EngineConnectionState.Connecting)
            {
                kind = EngineBoundaryKind.Checking;
                title = "Engine: checking";
                message = "Waiting for the engine to answer.";
            }
            else if (connection == EngineConnectionState.Unavailable)
            {
                kind = EngineBoundaryKind.Unavailable;
                title = "Engine: not available";
                message = string.IsNullOrEmpty(lastMessage)
                    ? EngineProtocol.ErrorText(EngineProtocol.ErrorCodes.EngineUnavailable)
                    : lastMessage;
            }
            else if (!hasStatus)
            {
                kind = EngineBoundaryKind.Checking;
                title = "Engine: no status";
                message = "The engine answered but sent no status. The tunnel state is unknown.";
            }
            else if (session.HasPendingAction)
            {
                kind = EngineBoundaryKind.Checking;
                title = "Engine: waiting for status";
                message = string.IsNullOrEmpty(lastMessage)
                    ? "Waiting for the engine to confirm the last request."
                    : lastMessage;
            }
            else if (displayable && running && status.TtlBad > 0)
            {
                kind = EngineBoundaryKind.Attention;
                title = "Engine: TTL audit failed";
                message = "The engine counted "
                    + status.TtlBad.ToString(CultureInfo.InvariantCulture)
                    + (status.TtlBad == 1
                        ? " wrong TTL read-back. The traffic may not match the source device."
                        : " wrong TTL read-backs. The traffic may not match the source device.");
            }
            else if (running && stale)
            {
                kind = EngineBoundaryKind.Attention;
                title = "Engine: tunnel on, status stale";
                message = "The last status says the tunnel is on. It is out of date, so check again.";
            }
            else if (running)
            {
                kind = EngineBoundaryKind.On;
                title = "Engine: tunnel on";
                message = "The engine confirms that the tunnel is on.";
            }
            else if (freshness == EngineFreshness.Unavailable)
            {
                kind = EngineBoundaryKind.Attention;
                title = "Engine: status unavailable";
                message = "The engine status is out of date. The tunnel state is unknown.";
            }
            else if (status.Running)
            {
                kind = EngineBoundaryKind.Attention;
                title = "Engine: tunnel state unconfirmed";
                message = "The last status says the tunnel is on, but the app cannot confirm it now. The tunnel state is unknown.";
            }
            else if (cleanupBlocks)
            {
                kind = EngineBoundaryKind.Attention;
                title = "Engine: cleanup not confirmed";
                message = status.Cleanup == EngineCleanup.Failed
                    ? EngineProtocol.ErrorText(EngineProtocol.ErrorCodes.CleanupBlocked)
                    : status.Cleanup == EngineCleanup.Pending
                        ? EngineProtocol.ErrorText(EngineProtocol.ErrorCodes.CleanupPending)
                        : EngineProtocol.ErrorText(EngineProtocol.ErrorCodes.CleanupUnknown);
            }
            else if (stale)
            {
                kind = EngineBoundaryKind.Attention;
                title = "Engine: tunnel off, status stale";
                message = "The last status says the tunnel is off. It is out of date, so check again.";
            }
            else
            {
                kind = EngineBoundaryKind.Ready;
                title = "Engine: tunnel off";
                message = "The engine is ready. The tunnel is off.";
            }

            string statusText;
            if (closed)
            {
                statusText = "Closed";
            }
            else if (connection == EngineConnectionState.Unavailable)
            {
                statusText = "Unavailable";
            }
            else if (connection == EngineConnectionState.NotConnected)
            {
                statusText = "Not checked";
            }
            else if (connection == EngineConnectionState.Connecting)
            {
                statusText = "Checking";
            }
            else if (!hasStatus)
            {
                statusText = "Unknown";
            }
            else if (session.HasPendingAction)
            {
                statusText = "Unknown";
            }
            else if (session.CanClaimRunning)
            {
                statusText = freshness == EngineFreshness.Fresh ? "On" : "On, stale";
            }
            else if (cleanupBlocks)
            {
                statusText = "Off, cleanup not confirmed";
            }
            else if (freshness == EngineFreshness.Unavailable)
            {
                statusText = "Unknown";
            }
            else if (status.Running)
            {
                statusText = "On, unconfirmed";
            }
            else if (freshness == EngineFreshness.Fresh)
            {
                statusText = "Off";
            }
            else if (freshness == EngineFreshness.Stale)
            {
                statusText = "Off, stale";
            }
            else
            {
                statusText = "Unknown";
            }

            string pairingText;
            string sourceText = "Source device: unknown.";
            string trustText = "";
            string connectionText = "Connections: unknown.";
            string pingText = "";
            if (displayable)
            {
                pairingText = status.Paired ? "Pairing: paired." : "Pairing: not paired.";
                if (status.Paired)
                {
                    sourceText = status.SourcePresent
                        ? "Source device: present."
                        : "Source device: not present.";
                    trustText = status.TrustedBySource
                        ? "The source device trusts this target device."
                        : "The source device does not trust this target device. Pair again.";
                }
                else
                {
                    sourceText = "Source device: not paired.";
                }
                if (session.CanClaimRunning)
                {
                    connectionText = status.ConnectionsKnown
                        ? "Connections: "
                            + status.Connections.ToString(CultureInfo.InvariantCulture)
                            + "."
                        : "Connections: unknown.";
                    pingText = status.PingEnabled ? "Ping is on." : "Ping is off.";
                }
                else if (status.Running)
                {
                    connectionText = status.ConnectionsKnown
                        ? "Connections: "
                            + status.Connections.ToString(CultureInfo.InvariantCulture)
                            + " (unconfirmed)."
                        : "Connections: unknown (unconfirmed).";
                }
                else
                {
                    connectionText = "Connections: 0.";
                }
            }
            else
            {
                pairingText = "Pairing: unknown.";
            }

            string stopText = "";
            if (session.LastStopReason != EngineStopReason.None)
            {
                stopText = EngineProtocol.StopText(EngineRules.StopWord(session.LastStopReason));
            }

            string checkedText = hasStatus && !closed
                ? "Checked at "
                    + (status.CheckedAt ?? status.ObservedAt)
                        .ToLocalTime()
                        .ToString("HH:mm:ss", CultureInfo.InvariantCulture)
                    + "."
                : "Not checked.";

            return new EngineBoundaryContent(
                kind,
                title,
                message,
                statusText,
                checkedText,
                pairingText,
                sourceText,
                trustText,
                connectionText,
                pingText,
                stopText,
                lastMessage ?? "",
                available,
                running,
                stale,
                unknown,
                session.CanStart,
                session.CanStop,
                session.CanForget,
                !closed,
                session.IsBusy || session.HasPendingAction);
        }
    }

    // One polling policy shared by the page and the tests. A working engine
    // polls every second while the page is visible and every five seconds
    // while it is hidden. An unavailable or unconnected engine retries more
    // slowly so a missing helper does not spin.
    public static class EnginePollPolicy
    {
        public static TimeSpan NextDelay(EngineConnectionState connection, bool visible)
        {
            if (connection == EngineConnectionState.Available)
            {
                return visible ? EngineTiming.VisiblePoll : EngineTiming.HiddenPoll;
            }
            if (connection == EngineConnectionState.Connecting)
            {
                return EngineTiming.VisiblePoll;
            }
            return visible ? EngineTiming.VisibleRetry : EngineTiming.HiddenRetry;
        }

        public static bool ShouldPoll(EngineConnectionState connection, bool closed)
        {
            return !closed && connection != EngineConnectionState.Closed;
        }
    }
}
