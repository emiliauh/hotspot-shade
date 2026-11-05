using System;
using System.Collections.Generic;
using System.Globalization;

namespace HotspotShade.WinUI2.Core
{
    // One card on the dashboard. A card has one value line and zero or more
    // detail lines. The view draws the lines without changes.
    public sealed class DemoCard
    {
        public DemoCard(string title, string value, IReadOnlyList<string> details)
        {
            Title = title ?? "";
            Value = value ?? "";
            Details = details ?? Array.Empty<string>();
        }

        public string Title { get; private set; }

        public string Value { get; private set; }

        public IReadOnlyList<string> Details { get; private set; }
    }

    // One line in the attention card. Some lines offer one action.
    public sealed class DemoAttentionItem
    {
        public DemoAttentionItem(string text, DemoAttentionAction action)
        {
            Text = text ?? "";
            Action = action;
        }

        public string Text { get; private set; }

        public DemoAttentionAction Action { get; private set; }

        public string ActionLabel
        {
            get { return DemoText.AttentionActionLabel(Action); }
        }

        public bool HasAction
        {
            get { return Action != DemoAttentionAction.None; }
        }
    }

    // One simulated activity line. The page labels the whole list as
    // simulated. No engine log is read.
    public sealed class DemoLogLine
    {
        public DemoLogLine(DateTimeOffset timestamp, string level, int sequence, string message)
        {
            Timestamp = timestamp;
            Level = level ?? "";
            Sequence = sequence;
            Message = message ?? "";
        }

        public DateTimeOffset Timestamp { get; private set; }

        public string Level { get; private set; }

        public int Sequence { get; private set; }

        public string Message { get; private set; }

        public string TimeText
        {
            get { return Timestamp.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture); }
        }

        public string DetailsText
        {
            get
            {
                if (string.IsNullOrEmpty(Level))
                {
                    return "seq " + Sequence.ToString(CultureInfo.InvariantCulture);
                }
                return Level + ", seq " + Sequence.ToString(CultureInfo.InvariantCulture);
            }
        }

        public string AccessibilityText(bool showDetails)
        {
            string text = TimeText + ". " + Message + ".";
            if (showDetails && !string.IsNullOrEmpty(Level))
            {
                text = text + " " + Level + ".";
            }
            return text;
        }
    }

    // One simulated failure group. The target uses documentation addresses
    // and example names only.
    public sealed class DemoFailureRow
    {
        public DemoFailureRow(int count, string kind, string target, string reason)
            : this(count, kind, target, reason, null)
        {
        }

        public DemoFailureRow(int count, string kind, string target, string reason, string phase)
        {
            Count = count;
            Kind = kind ?? "";
            Target = target ?? "";
            Reason = reason ?? "";
            Phase = DemoText.DecodeFailurePhase(phase);
        }

        public int Count { get; private set; }

        public string Kind { get; private set; }

        public string Target { get; private set; }

        public string Reason { get; private set; }

        public DemoFailurePhase Phase { get; private set; }

        public string PhaseLabel
        {
            get { return DemoText.FailurePhaseLabel(Phase); }
        }

        public string PhaseWord
        {
            get { return DemoText.FailurePhaseWord(Phase); }
        }

        // The group identity includes the stage. One destination and reason
        // with two stages stays two visible groups.
        public string GroupKey
        {
            get { return Kind + "|" + Target + "|" + Reason + "|" + PhaseWord; }
        }

        public string AccessibilityLabel
        {
            get
            {
                return Count.ToString(CultureInfo.InvariantCulture)
                    + (Count == 1 ? " failure. " : " failures. ")
                    + Kind + ". " + Target + ". " + Reason + ". Stage: " + PhaseLabel + ".";
            }
        }
    }

    // The visible dashboard content. The core state machine builds a new
    // object for each change. The view layer reads it and never writes it.
    public sealed class DemoDashboardContent
    {
        public DemoDashboardContent()
        {
            Title = "";
            Subtitle = "";
            CheckedText = "";
            PairingCode = "";
            PairingCodeAccessibility = "";
            PairingTitle = "";
            PairingSubtitle = "";
            PairingStatus = "";
            BusyText = "";
            CanCheckNow = true;
            CanAct = true;
            SourceDevice = new DemoCard(DemoText.SourceDevice, DemoText.NotPaired, Array.Empty<string>());
            Connection = new DemoCard(DemoText.Connection, DemoText.TunnelOff, Array.Empty<string>());
            Attention = Array.Empty<DemoAttentionItem>();
        }

        public DemoStatusKind StatusKind { get; internal set; }

        public DemoStatusDot StatusDot
        {
            get
            {
                switch (StatusKind)
                {
                    case DemoStatusKind.On:
                        return DemoStatusDot.On;
                    case DemoStatusKind.Attention:
                        return DemoStatusDot.Attention;
                    case DemoStatusKind.Pairing:
                        return DemoStatusDot.Pairing;
                    case DemoStatusKind.Busy:
                        return DemoStatusDot.Pairing;
                    default:
                        return DemoStatusDot.Off;
                }
            }
        }

        public string Title { get; internal set; }

        public string Subtitle { get; internal set; }

        public string CheckedText { get; internal set; }

        public DemoPrimaryAction PrimaryAction { get; internal set; }

        public DemoSecondaryAction SecondaryAction { get; internal set; }

        public string PrimaryActionLabel
        {
            get { return DemoText.PrimaryActionLabel(PrimaryAction); }
        }

        public string SecondaryActionLabel
        {
            get { return DemoText.SecondaryActionLabel(SecondaryAction); }
        }

        public bool HasPrimaryAction
        {
            get { return PrimaryAction != DemoPrimaryAction.None; }
        }

        public bool HasSecondaryAction
        {
            get { return SecondaryAction != DemoSecondaryAction.None; }
        }

        public bool SecondaryActionIsDestructive
        {
            get
            {
                return SecondaryAction == DemoSecondaryAction.Forget
                    || SecondaryAction == DemoSecondaryAction.TurnOffAndForget;
            }
        }

        public bool HasNonDestructiveSecondaryAction
        {
            get { return HasSecondaryAction && !SecondaryActionIsDestructive; }
        }

        public DemoCard SourceDevice { get; internal set; }

        public DemoCard Connection { get; internal set; }

        public IReadOnlyList<DemoAttentionItem> Attention { get; internal set; }

        public bool HasAttention
        {
            get { return Attention != null && Attention.Count > 0; }
        }

        public bool ShowPairHint { get; internal set; }

        public bool IsPairing { get; internal set; }

        public bool IsBusy { get; internal set; }

        public bool CanCheckNow { get; internal set; }

        public bool CanAct { get; internal set; }

        public string BusyText { get; internal set; }

        public bool PairingCodeReady { get; internal set; }

        public string PairingCode { get; internal set; }

        public string PairingCodeAccessibility { get; internal set; }

        public string PairingTitle { get; internal set; }

        public string PairingSubtitle { get; internal set; }

        public string PairingStatus { get; internal set; }

        public bool IsRunning { get; internal set; }

        public bool IsPaired { get; internal set; }
    }

    // The visible activity page content.
    public sealed class DemoActivityContent
    {
        public DemoActivityContent()
        {
            Lines = Array.Empty<DemoLogLine>();
            Message = "";
            Detail = "";
        }

        public DemoActivityState State { get; internal set; }

        public IReadOnlyList<DemoLogLine> Lines { get; internal set; }

        public string Message { get; internal set; }

        public string Detail { get; internal set; }

        public bool IsLoading
        {
            get { return State == DemoActivityState.Loading; }
        }

        public bool IsEmpty
        {
            get { return State == DemoActivityState.Empty; }
        }

        public bool IsUnavailable
        {
            get { return State == DemoActivityState.Unavailable; }
        }

        public bool HasLines
        {
            get { return Lines != null && Lines.Count > 0; }
        }

        public bool ShowsLines
        {
            get { return State == DemoActivityState.Loaded && HasLines; }
        }

        public bool CanRefresh
        {
            get { return State != DemoActivityState.Loading; }
        }
    }

    // The visible recent failures content.
    public sealed class DemoFailuresContent
    {
        public DemoFailuresContent()
        {
            Rows = Array.Empty<DemoFailureRow>();
            Message = "";
        }

        public DemoFailuresState State { get; internal set; }

        public IReadOnlyList<DemoFailureRow> Rows { get; internal set; }

        public string Message { get; internal set; }

        public bool TunnelOff { get; internal set; }

        public int Total { get; internal set; }

        public bool IsLoading
        {
            get { return State == DemoFailuresState.Loading; }
        }

        public bool IsEmpty
        {
            get { return State == DemoFailuresState.Empty; }
        }

        public bool HasRows
        {
            get { return Rows != null && Rows.Count > 0; }
        }

        public bool CanRefresh
        {
            get { return !TunnelOff && !IsLoading; }
        }

        public bool ShowMessage
        {
            get { return !IsLoading && !HasRows && !string.IsNullOrEmpty(Message); }
        }
    }

    // The visible Settings content.
    public sealed class DemoSettingsContent
    {
        public DemoSettingsContent()
        {
            PairingStateText = "";
            PairingGlyph = "";
            PairActionReason = "";
            ForgetMessage = "";
            PingStateText = "";
            NotificationsText = "";
            LoginText = "";
            EngineText = "";
            ModeText = "";
            StatusText = "";
            Failures = new DemoFailuresContent();
        }

        public string PairingStateText { get; internal set; }

        public string PairingGlyph { get; internal set; }

        public bool PairActionEnabled { get; internal set; }

        public string PairActionReason { get; internal set; }

        public bool IsPairing { get; internal set; }

        public bool Paired { get; internal set; }

        public bool Running { get; internal set; }

        public bool ShowForget { get; internal set; }

        public bool ForgetBlocked { get; internal set; }

        public string ForgetMessage { get; internal set; }

        public string ForgetButtonLabel
        {
            get { return ForgetBlocked ? DemoText.TurnOffAndForget : DemoText.Forget; }
        }

        public bool PingEnabled { get; internal set; }

        public string PingStateText { get; internal set; }

        public DemoTheme Theme { get; internal set; }

        public string NotificationsText { get; internal set; }

        public string LoginText { get; internal set; }

        public string EngineText { get; internal set; }

        public string ModeText { get; internal set; }

        public string StatusText { get; internal set; }

        public DemoFailuresContent Failures { get; internal set; }
    }

    // One entry in the demo scenario picker.
    public sealed class DemoScenarioInfo
    {
        public DemoScenarioInfo(DemoScenario scenario, string title, string description)
        {
            Scenario = scenario;
            Title = title ?? "";
            Description = description ?? "";
        }

        public DemoScenario Scenario { get; private set; }

        public string Title { get; private set; }

        public string Description { get; private set; }
    }

    // The clock is injected, so every state change is a test with fixed time.
    public interface IDemoClock
    {
        DateTimeOffset Now { get; }
    }

    public sealed class SystemDemoClock : IDemoClock
    {
        public DateTimeOffset Now
        {
            get { return DateTimeOffset.Now; }
        }
    }
}
