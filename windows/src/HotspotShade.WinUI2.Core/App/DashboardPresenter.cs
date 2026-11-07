using System;
using System.Collections.Generic;

namespace HotspotShade.WinUI2.Core.App
{
    public enum StatusFreshness
    {
        Fresh,
        Stale,
        Unavailable
    }

    public enum TunnelOperation
    {
        None,
        Starting,
        Stopping
    }

    // The pairing phase that the window tracks. Starting covers the request
    // and the connecting state; Confirming means a code is on the screen.
    public enum PairingView
    {
        Idle,
        Starting,
        Confirming,
        Paired,
        Failed
    }

    public enum StatusKind
    {
        Off,
        On,
        Attention,
        Pairing,
        Busy
    }

    public enum DashboardAction
    {
        None,
        Pair,
        PairAgain,
        TurnOn,
        TurnOff,
        Retry,
        CheckNow,
        TurnOffAndForget,
        Forget
    }

    // A cleanup mark that the broker owns. A retryable mark can be retried
    // with Turn off. A final mark offers no action.
    public enum CleanupKind
    {
        None,
        Retryable,
        Final
    }

    // Every input to one dashboard. The table is pure, so every row is a
    // test. The view model fills it from the real engine status and the
    // broker phase. Nothing here is invented: a missing value stays missing.
    public sealed class DashboardInput
    {
        public DashboardInput()
        {
            Phone = PhoneState.Unknown;
            Pairing = PairingView.Idle;
            Operation = TunnelOperation.None;
            Freshness = StatusFreshness.Fresh;
            Forget = ForgetPhase.None;
            Health = EngineHealth.Normal;
            Cleanup = CleanupKind.None;
        }

        public bool Running { get; set; }
        public bool Paired { get; set; }
        public PhoneState Phone { get; set; }
        public string PhoneMessage { get; set; }
        public PairingView Pairing { get; set; }
        public TunnelOperation Operation { get; set; }
        public string Error { get; set; }
        public StatusFreshness Freshness { get; set; }
        public string TokenRejected { get; set; }
        public bool? TrustedBySource { get; set; }
        public ForgetPhase Forget { get; set; }
        public bool SourceDeviceWarning { get; set; }
        public string PairingFailure { get; set; }
        public EngineHealth Health { get; set; }
        public string CleanupPending { get; set; }
        public CleanupKind Cleanup { get; set; }
        public bool TestDataEngine { get; set; }

        // Card and attention inputs.
        public string PingLine { get; set; }
        public string ConnectionsLabel { get; set; }
        public string LastStopLine { get; set; }
        public string LastCheckedText { get; set; }
        public string TtlAuditLine { get; set; }
        public bool ForgetBlocked { get; set; }
        public bool ForgetInFlight { get; set; }
        public bool PairingCancelInFlight { get; set; }
        public bool PairingStartInFlight { get; set; }
        public bool RetryStartsTunnel { get; set; }

        // Windows inputs. A non-empty reason makes Turn on unavailable and is
        // shown as is. EngineStarting is true before the first status answer.
        public string TurnOnUnavailable { get; set; }
        public bool EngineStarting { get; set; }
        public string BrokerFailure { get; set; }
        public bool ElevatedSource { get; set; }
    }

    public sealed class AttentionLine
    {
        public AttentionLine(string text, DashboardAction action)
        {
            Text = text;
            Action = action;
        }

        public string Text { get; private set; }

        public DashboardAction Action { get; private set; }
    }

    public sealed class DashboardCard
    {
        public DashboardCard(string title, string value, IList<string> details)
        {
            Title = title;
            Value = value;
            Details = details;
        }

        public string Title { get; private set; }

        public string Value { get; private set; }

        public IList<string> Details { get; private set; }

        public string AccessibilityText
        {
            get
            {
                string text = Title + ". " + Value + ".";
                for (int index = 0; index < Details.Count; index++)
                {
                    text += " " + Details[index];
                }
                return text;
            }
        }
    }

    // The visible dashboard and the enablement of every action. The menu and
    // the Settings page read the same flags, so no surface offers an action
    // that the dashboard would refuse.
    public sealed class DashboardModel
    {
        public string Title { get; internal set; }
        public string Subtitle { get; internal set; }
        public StatusKind Kind { get; internal set; }
        public DashboardAction Primary { get; internal set; }
        public DashboardAction Secondary { get; internal set; }
        public DashboardCard SourceCard { get; internal set; }
        public DashboardCard ConnectionCard { get; internal set; }
        public IList<AttentionLine> Attention { get; internal set; }
        public string CheckedText { get; internal set; }
        public bool ShowAdminNote { get; internal set; }
        public bool ShowPairHint { get; internal set; }

        public bool CanTurnOn { get; internal set; }
        public string TurnOnReason { get; internal set; }
        public bool CanTurnOff { get; internal set; }
        public string TurnOffReason { get; internal set; }
        public bool CanPair { get; internal set; }
        public string PairReason { get; internal set; }
        public bool CanCancelPairing { get; internal set; }
        public bool CanForget { get; internal set; }
        public string ForgetReason { get; internal set; }

        public string AccessibilityStatus
        {
            get { return Title + ". " + Subtitle; }
        }

        public static string Label(DashboardAction action)
        {
            switch (action)
            {
                case DashboardAction.Pair:
                    return AppText.Pair;
                case DashboardAction.PairAgain:
                    return AppText.PairAgain;
                case DashboardAction.TurnOn:
                    return AppText.TurnOn;
                case DashboardAction.TurnOff:
                    return AppText.TurnOff;
                case DashboardAction.Retry:
                    return AppText.TryAgain;
                case DashboardAction.CheckNow:
                    return AppText.CheckNow;
                case DashboardAction.TurnOffAndForget:
                    return AppText.TurnOffAndForget;
                case DashboardAction.Forget:
                    return AppText.Forget;
                default:
                    return "";
            }
        }
    }

    public static class DashboardPresenter
    {
        private sealed class Derived
        {
            public string Title;
            public string Subtitle;
            public DashboardAction Action;
        }

        public static DashboardModel Build(DashboardInput input)
        {
            if (input == null)
            {
                throw new ArgumentNullException("input");
            }
            PairingView pairing = LivePairing(input);
            bool busy = ActionBusy(input);
            DashboardModel model = new DashboardModel();

            // Before the broker and the engine answer once, the app claims
            // nothing about the tunnel.
            if (!string.IsNullOrEmpty(input.BrokerFailure) || input.EngineStarting)
            {
                bool failed = !string.IsNullOrEmpty(input.BrokerFailure);
                model.Title = failed ? AppText.Attention : AppText.StartingEngine;
                model.Subtitle = failed ? input.BrokerFailure : AppText.StartingEngineSubtitle;
                model.Kind = failed ? StatusKind.Attention : StatusKind.Busy;
                model.Primary = failed ? DashboardAction.Retry : DashboardAction.None;
                model.Secondary = DashboardAction.None;
                model.SourceCard = new DashboardCard(AppText.SourceDevice, AppText.StatusUnavailableLine, new[] { AppText.CheckStatusAgain });
                model.ConnectionCard = new DashboardCard(AppText.Connection, AppText.StatusUnavailableLine, new[] { AppText.CheckStatusAgain });
                model.Attention = new List<AttentionLine>();
                model.TurnOnReason = model.Subtitle;
                model.TurnOffReason = model.Subtitle;
                model.PairReason = model.Subtitle;
                model.ForgetReason = model.Subtitle;
                return model;
            }

            Derived derived = Derive(input, pairing);
            model.Title = derived.Title;
            model.Subtitle = derived.Subtitle;
            if (input.ForgetInFlight && input.Operation == TunnelOperation.None)
            {
                model.Subtitle = AppText.ForgetPending;
            }
            else if (input.PairingCancelInFlight && input.Operation == TunnelOperation.None)
            {
                model.Subtitle = AppText.CancelingPairing;
            }
            model.Primary = busy ? DashboardAction.None : derived.Action;
            model.Kind = Kind(input, pairing);

            bool forgetBlocked = input.ForgetBlocked && input.Running && input.Freshness == StatusFreshness.Fresh;
            List<AttentionLine> attention = AttentionItems(input, model.Subtitle);
            if (forgetBlocked)
            {
                attention.Insert(0, new AttentionLine(AppText.ForgetBlocked, DashboardAction.TurnOffAndForget));
            }
            model.Attention = attention;

            if (busy || input.Health != EngineHealth.Normal)
            {
                model.Secondary = DashboardAction.None;
            }
            else if (forgetBlocked)
            {
                model.Secondary = DashboardAction.TurnOffAndForget;
            }
            else if (input.Freshness == StatusFreshness.Stale)
            {
                model.Secondary = DashboardAction.CheckNow;
            }
            else if (input.Freshness == StatusFreshness.Unavailable || !string.IsNullOrEmpty(input.CleanupPending))
            {
                model.Secondary = DashboardAction.None;
            }
            else if (input.Paired && !input.Running && input.Operation == TunnelOperation.None && pairing == PairingView.Idle && !input.ElevatedSource)
            {
                model.Secondary = DashboardAction.Forget;
            }
            else
            {
                model.Secondary = DashboardAction.None;
            }

            BuildCards(input, model);
            model.ShowAdminNote = model.Primary == DashboardAction.TurnOn
                || (model.Primary == DashboardAction.Retry && input.RetryStartsTunnel);
            model.ShowPairHint = model.Title == AppText.NotPaired && model.Primary == DashboardAction.Pair && model.Attention.Count == 0;
            Enablement(input, pairing, busy, model);
            return model;
        }

        // A paired phase is live only while this target device still holds
        // the pairing and the source device still trusts it.
        public static PairingView LivePairing(DashboardInput input)
        {
            if (input.Pairing != PairingView.Paired)
            {
                return input.Pairing;
            }
            if (!input.Paired || input.Phone == PhoneState.NotTrusted || input.TrustedBySource == false)
            {
                return PairingView.Idle;
            }
            if (!string.IsNullOrEmpty(input.TokenRejected))
            {
                return PairingView.Idle;
            }
            return PairingView.Paired;
        }

        private static bool ActionBusy(DashboardInput input)
        {
            return input.ForgetInFlight || input.PairingCancelInFlight || input.PairingStartInFlight;
        }

        private static Derived State(string title, string subtitle, DashboardAction action)
        {
            Derived value = new Derived();
            value.Title = title;
            value.Subtitle = subtitle;
            value.Action = action;
            return value;
        }

        private static Derived Derive(DashboardInput input, PairingView pairing)
        {
            if (input.Operation == TunnelOperation.Starting)
            {
                return State(AppText.StartingTunnel, AppText.TakesAMinute, DashboardAction.None);
            }
            if (input.Operation == TunnelOperation.Stopping)
            {
                return State(AppText.Stopping, AppText.TakesAMinute, DashboardAction.None);
            }
            if (input.Freshness == StatusFreshness.Unavailable)
            {
                return State(
                    AppText.UnknownTitle,
                    input.TestDataEngine ? AppText.TestDataEngine : AppText.StatusUnavailableSubtitle,
                    DashboardAction.CheckNow);
            }
            if (input.Health == EngineHealth.StateUnknown)
            {
                return State(AppText.ServiceStateUnknownTitle, AppText.ServiceStateUnknownBody, DashboardAction.CheckNow);
            }
            if (input.Health == EngineHealth.CleanupBlocked)
            {
                return State(AppText.CleanupBlockedTitle, AppText.CleanupBlockedBody, DashboardAction.CheckNow);
            }
            if (!string.IsNullOrEmpty(input.CleanupPending))
            {
                string message = AppText.Sanitized(input.CleanupPending);
                DashboardAction action = input.Cleanup == CleanupKind.Final
                    ? DashboardAction.None
                    : (input.Running ? DashboardAction.TurnOff : DashboardAction.Retry);
                return State(AppText.CleanupBlockedTitle, message, action);
            }
            if (!string.IsNullOrEmpty(input.TokenRejected))
            {
                return State(AppText.PairAgain, AppText.Sanitized(input.TokenRejected), DashboardAction.PairAgain);
            }
            if (!string.IsNullOrEmpty(input.Error))
            {
                return State(AppText.Attention, AppText.Sanitized(input.Error), DashboardAction.Retry);
            }
            if (input.Running)
            {
                return State(AppText.On, AppText.Sanitized(input.PhoneMessage) ?? AppText.OnSubtitle, DashboardAction.TurnOff);
            }
            if (pairing == PairingView.Starting || pairing == PairingView.Confirming)
            {
                return State(AppText.Pairing, AppText.PairingSubtitle, DashboardAction.None);
            }
            switch (input.Phone)
            {
                case PhoneState.Unpaired:
                    if (input.Paired)
                    {
                        return State(AppText.Waiting, AppText.OpenSourceDeviceApp, DashboardAction.None);
                    }
                    return Unpaired(input);
                case PhoneState.NotTrusted:
                    if (input.Paired)
                    {
                        return State(AppText.NotTrustedTitle, AppText.NotTrustedSubtitle, DashboardAction.PairAgain);
                    }
                    return Unpaired(input);
                case PhoneState.ProxyOff:
                    if (input.Paired)
                    {
                        return State(AppText.Paired, AppText.ProxyOffSubtitle, DashboardAction.None);
                    }
                    return Unpaired(input);
                case PhoneState.Ready:
                case PhoneState.Connected:
                    if (input.Paired)
                    {
                        if (!string.IsNullOrEmpty(input.TurnOnUnavailable))
                        {
                            return State(AppText.Ready, input.TurnOnUnavailable, DashboardAction.None);
                        }
                        string subtitle = input.Phone == PhoneState.Ready
                            ? AppText.Sanitized(input.PhoneMessage) ?? AppText.ReadySubtitle
                            : AppText.ReadySubtitle;
                        return State(AppText.Ready, subtitle, DashboardAction.TurnOn);
                    }
                    return Unpaired(input);
                case PhoneState.NoHotspot:
                    return State(AppText.Waiting, AppText.Sanitized(input.PhoneMessage) ?? AppText.NoHotspotSubtitle, DashboardAction.None);
                case PhoneState.NotRunning:
                    return State(AppText.Waiting, AppText.Sanitized(input.PhoneMessage) ?? AppText.NotRunningSubtitle, DashboardAction.None);
                case PhoneState.NotResponding:
                    return State(AppText.Waiting, AppText.NotRespondingSubtitle, DashboardAction.None);
                case PhoneState.Checking:
                    return State(AppText.Waiting, AppText.Sanitized(input.PhoneMessage) ?? AppText.CheckingSubtitle, DashboardAction.None);
                default:
                    return State(AppText.UnknownTitle, AppText.Sanitized(input.PhoneMessage) ?? AppText.UnknownSubtitle, DashboardAction.None);
            }
        }

        private static Derived Unpaired(DashboardInput input)
        {
            if (input.Forget == ForgetPhase.Pending)
            {
                return State(AppText.NotPaired, AppText.ForgetPending, DashboardAction.Pair);
            }
            if (input.Forget == ForgetPhase.Confirmed || input.Forget == ForgetPhase.NotDelivered)
            {
                return State(AppText.NotPaired, AppText.ForgetResult, DashboardAction.Pair);
            }
            string failure = AppText.Sanitized(input.PairingFailure);
            if (!string.IsNullOrEmpty(failure))
            {
                return State(AppText.NotPaired, failure, DashboardAction.Pair);
            }
            if (input.TrustedBySource == true)
            {
                return State(AppText.NotPaired, AppText.TrustedBySource, DashboardAction.Pair);
            }
            return State(AppText.NotPaired, AppText.UnpairedSubtitle, DashboardAction.Pair);
        }

        private static StatusKind Kind(DashboardInput input, PairingView pairing)
        {
            if (input.Freshness == StatusFreshness.Unavailable)
            {
                return StatusKind.Attention;
            }
            if (!string.IsNullOrEmpty(input.CleanupPending))
            {
                return StatusKind.Attention;
            }
            if (!string.IsNullOrEmpty(input.TokenRejected))
            {
                return StatusKind.Attention;
            }
            if (input.Health != EngineHealth.Normal)
            {
                return StatusKind.Attention;
            }
            if (input.ForgetInFlight || input.PairingCancelInFlight)
            {
                return StatusKind.Busy;
            }
            if (input.Operation != TunnelOperation.None)
            {
                return StatusKind.Busy;
            }
            if (pairing == PairingView.Starting || pairing == PairingView.Confirming)
            {
                return StatusKind.Pairing;
            }
            if (input.Running)
            {
                return StatusKind.On;
            }
            if (input.Phone == PhoneState.Unknown || input.Phone == PhoneState.NotTrusted && input.Paired)
            {
                return StatusKind.Attention;
            }
            if (!string.IsNullOrEmpty(input.Error))
            {
                return StatusKind.Attention;
            }
            return StatusKind.Off;
        }

        private static List<AttentionLine> AttentionItems(DashboardInput input, string subtitle)
        {
            List<AttentionLine> items = new List<AttentionLine>();
            bool healthy = input.Health == EngineHealth.Normal;
            if (input.SourceDeviceWarning && healthy)
            {
                items.Add(new AttentionLine(AppText.SourceStoppedTitle, DashboardAction.None));
            }
            if (input.Running && input.Phone == PhoneState.NotTrusted && healthy)
            {
                items.Add(new AttentionLine(AppText.NotTrustedWhileRunning, DashboardAction.TurnOff));
            }
            if (input.Health == EngineHealth.StateUnknown)
            {
                items.Add(new AttentionLine(AppText.ServiceStateUnknownHint, DashboardAction.None));
            }
            else if (input.Health == EngineHealth.CleanupBlocked)
            {
                items.Add(new AttentionLine(AppText.CleanupBlockedHint, DashboardAction.None));
            }
            string pending = AppText.Sanitized(input.CleanupPending);
            if (!string.IsNullOrEmpty(pending) && pending != subtitle)
            {
                items.Add(new AttentionLine(pending, DashboardAction.None));
            }
            string failure = AppText.Sanitized(input.PairingFailure);
            if (!string.IsNullOrEmpty(failure) && failure != subtitle)
            {
                items.Add(new AttentionLine(failure, DashboardAction.None));
            }
            if (!string.IsNullOrEmpty(input.TtlAuditLine) && input.Running)
            {
                items.Add(new AttentionLine(input.TtlAuditLine, DashboardAction.None));
            }
            if (!string.IsNullOrEmpty(input.TurnOnUnavailable) && input.TurnOnUnavailable != subtitle && input.Paired && !input.Running)
            {
                items.Add(new AttentionLine(input.TurnOnUnavailable, DashboardAction.None));
            }
            if (input.Freshness != StatusFreshness.Fresh && AppText.StaleStatus != subtitle)
            {
                items.Add(new AttentionLine(AppText.StaleStatus, DashboardAction.CheckNow));
            }
            // Remove duplicates but keep the order.
            HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
            List<AttentionLine> unique = new List<AttentionLine>();
            for (int index = 0; index < items.Count; index++)
            {
                if (seen.Add(items[index].Text))
                {
                    unique.Add(items[index]);
                }
            }
            return unique;
        }

        private static void BuildCards(DashboardInput input, DashboardModel model)
        {
            bool unavailable = input.Freshness == StatusFreshness.Unavailable;
            if (input.Health == EngineHealth.StateUnknown)
            {
                model.SourceCard = new DashboardCard(AppText.SourceDevice, AppText.UnknownValue, new[] { AppText.UnknownCardHint });
                model.ConnectionCard = new DashboardCard(AppText.Connection, AppText.UnknownValue, new[] { AppText.ServiceStateUnknownHint });
                model.CheckedText = null;
                return;
            }
            if (unavailable)
            {
                model.SourceCard = new DashboardCard(AppText.SourceDevice, AppText.StatusUnavailableLine, new[] { AppText.CheckStatusAgain });
                model.ConnectionCard = new DashboardCard(AppText.Connection, AppText.StatusUnavailableLine, new[] { AppText.CheckStatusAgain });
                model.CheckedText = null;
                return;
            }

            string sourceValue;
            List<string> sourceDetails = new List<string>();
            if (model.Title == AppText.NotTrustedTitle)
            {
                sourceValue = AppText.NotTrustedTitle;
                sourceDetails.Add(AppText.PairToRestoreTrust);
            }
            else if (input.Paired)
            {
                sourceValue = AppText.Paired;
                switch (model.Title)
                {
                    case AppText.Pairing:
                        sourceDetails.Add(AppText.LookingForSourceDevice);
                        break;
                    case AppText.Waiting:
                        sourceDetails.Add(AppText.ChecksEverySecond);
                        break;
                    case AppText.On:
                        sourceDetails.Add(AppText.TunnelUsesSourceDevice);
                        break;
                    case AppText.Attention:
                        sourceDetails.Add(AppText.ReadTheMessageAbove);
                        break;
                    default:
                        sourceDetails.Add(AppText.PairingIsSaved);
                        break;
                }
            }
            else
            {
                sourceValue = AppText.NotPaired;
                sourceDetails.Add(model.Subtitle == AppText.TrustedBySource ? AppText.PressPairToContinue : AppText.PairWhenReady);
            }
            model.SourceCard = new DashboardCard(AppText.SourceDevice, sourceValue, sourceDetails);

            bool healthy = input.Health == EngineHealth.Normal && string.IsNullOrEmpty(input.CleanupPending);
            string connectionValue;
            switch (model.Title)
            {
                case AppText.StartingTunnel:
                    connectionValue = AppText.ConnectionStarting;
                    break;
                case AppText.Stopping:
                    connectionValue = AppText.Stopping;
                    break;
                case AppText.On:
                    connectionValue = AppText.TunnelOn;
                    break;
                default:
                    connectionValue = AppText.TunnelOff;
                    break;
            }
            List<string> connectionDetails = new List<string>();
            if (healthy && !string.IsNullOrEmpty(input.PingLine))
            {
                connectionDetails.Add(input.PingLine);
            }
            if (healthy && !string.IsNullOrEmpty(input.ConnectionsLabel))
            {
                connectionDetails.Add(input.ConnectionsLabel);
            }
            if (!string.IsNullOrEmpty(input.LastStopLine))
            {
                connectionDetails.Add(input.LastStopLine);
            }
            if (input.Running && input.ElevatedSource && healthy)
            {
                connectionDetails.Add(AppText.ElevatedSource);
            }
            if (connectionDetails.Count == 0)
            {
                connectionDetails.Add(AppText.NoConnectionYet);
            }
            model.ConnectionCard = new DashboardCard(AppText.Connection, connectionValue, connectionDetails);
            model.CheckedText = healthy ? input.LastCheckedText : null;
        }

        private static void Enablement(DashboardInput input, PairingView pairing, bool busy, DashboardModel model)
        {
            bool pairingActive = pairing == PairingView.Starting || pairing == PairingView.Confirming;
            bool anyBusy = input.Operation != TunnelOperation.None || pairingActive || busy;
            bool unavailable = input.Freshness == StatusFreshness.Unavailable;
            bool healthy = input.Health == EngineHealth.Normal;
            bool pending = !string.IsNullOrEmpty(input.CleanupPending);

            bool ready = healthy && input.Paired && (input.Phone == PhoneState.Ready || input.Phone == PhoneState.Connected)
                && !input.Running && !anyBusy && !unavailable && string.IsNullOrEmpty(input.TokenRejected)
                && !pending && string.IsNullOrEmpty(input.TurnOnUnavailable) && !input.ElevatedSource;
            model.CanTurnOn = ready;
            if (ready)
            {
                model.TurnOnReason = null;
            }
            else if (!healthy)
            {
                model.TurnOnReason = Recovery(input.Health);
            }
            else if (unavailable)
            {
                model.TurnOnReason = AppText.StatusUnavailableSubtitle;
            }
            else if (pending)
            {
                model.TurnOnReason = AppText.Sanitized(input.CleanupPending);
            }
            else if (anyBusy)
            {
                model.TurnOnReason = AppText.WaitForAction;
            }
            else if (!string.IsNullOrEmpty(input.TokenRejected))
            {
                model.TurnOnReason = AppText.PairAgain;
            }
            else if (!input.Paired)
            {
                model.TurnOnReason = AppText.UnpairedSubtitle;
            }
            else if (input.Running || input.ElevatedSource)
            {
                model.TurnOnReason = "The tunnel is already on.";
            }
            else if (!string.IsNullOrEmpty(input.TurnOnUnavailable))
            {
                model.TurnOnReason = input.TurnOnUnavailable;
            }
            else
            {
                model.TurnOnReason = "The source device is not ready.";
            }

            // Turn off stays available for a retryable cleanup mark, so a
            // stop that could not be confirmed can be tried again.
            bool stopTarget = input.Running || (input.ElevatedSource && input.Cleanup == CleanupKind.Retryable);
            model.CanTurnOff = healthy && stopTarget && input.Operation == TunnelOperation.None && !busy && !unavailable;
            if (model.CanTurnOff)
            {
                model.TurnOffReason = null;
            }
            else if (!healthy)
            {
                model.TurnOffReason = Recovery(input.Health);
            }
            else if (unavailable)
            {
                model.TurnOffReason = AppText.StatusUnavailableSubtitle;
            }
            else if (anyBusy)
            {
                model.TurnOffReason = AppText.WaitForAction;
            }
            else
            {
                model.TurnOffReason = "The tunnel is not on.";
            }

            model.CanPair = healthy && !unavailable && !pending && !input.Running && !input.ElevatedSource
                && input.Operation == TunnelOperation.None && !busy
                && (pairing == PairingView.Idle || pairing == PairingView.Failed);
            if (model.CanPair)
            {
                model.PairReason = null;
            }
            else if (!healthy)
            {
                model.PairReason = Recovery(input.Health);
            }
            else if (unavailable)
            {
                model.PairReason = AppText.StatusUnavailableSubtitle;
            }
            else if (pending)
            {
                model.PairReason = AppText.Sanitized(input.CleanupPending);
            }
            else if (input.Running || input.ElevatedSource)
            {
                model.PairReason = "Turn off the tunnel first.";
            }
            else if (input.Operation != TunnelOperation.None || busy)
            {
                model.PairReason = AppText.WaitForAction;
            }
            else if (pairingActive)
            {
                model.PairReason = "Pairing is already running.";
            }
            else
            {
                model.PairReason = AppText.AlreadyPaired;
            }

            model.CanCancelPairing = pairingActive && !input.PairingCancelInFlight && !input.ForgetInFlight;

            model.CanForget = healthy && !unavailable && !pending && input.Paired && !input.Running && !input.ElevatedSource
                && input.Operation == TunnelOperation.None && !busy && !pairingActive;
            if (model.CanForget)
            {
                model.ForgetReason = null;
            }
            else if (input.Running || input.ElevatedSource)
            {
                model.ForgetReason = AppText.ForgetBlocked;
            }
            else if (!input.Paired)
            {
                model.ForgetReason = AppText.UnpairedSubtitle;
            }
            else if (unavailable)
            {
                model.ForgetReason = AppText.StatusUnavailableSubtitle;
            }
            else if (!healthy)
            {
                model.ForgetReason = Recovery(input.Health);
            }
            else if (pending)
            {
                model.ForgetReason = AppText.Sanitized(input.CleanupPending);
            }
            else
            {
                model.ForgetReason = AppText.WaitForAction;
            }
        }

        private static string Recovery(EngineHealth health)
        {
            switch (health)
            {
                case EngineHealth.StateUnknown:
                    return AppText.ServiceStateUnknownBody;
                case EngineHealth.CleanupBlocked:
                    return AppText.CleanupBlockedBody;
                default:
                    return "";
            }
        }
    }
}
