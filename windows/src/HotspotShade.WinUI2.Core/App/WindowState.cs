using System;
using System.Collections.Generic;

namespace HotspotShade.WinUI2.Core.App
{
    // Every value that the window binds to, built from one AppSession. The
    // XAML shows these values as they are; it holds no state rule of its own.
    public sealed class WindowState
    {
        public string Title { get; private set; }
        public string Subtitle { get; private set; }
        public string CheckedText { get; private set; }
        public string StatusDot { get; private set; }
        public string AccessibilityStatus { get; private set; }

        public DashboardAction PrimaryAction { get; private set; }
        public string PrimaryLabel { get; private set; }
        public bool HasPrimary { get; private set; }
        public DashboardAction SecondaryAction { get; private set; }
        public string SecondaryLabel { get; private set; }
        public bool HasSecondary { get; private set; }
        public bool SecondaryIsDestructive { get; private set; }
        public bool HasPlainSecondary { get; private set; }
        public bool IsBusy { get; private set; }
        public bool ShowAdminNote { get; private set; }
        public bool ShowPairHint { get; private set; }

        public string SourceValue { get; private set; }
        public IList<string> SourceDetails { get; private set; }
        public string SourceAccessibility { get; private set; }
        public string ConnectionValue { get; private set; }
        public IList<string> ConnectionDetails { get; private set; }
        public string ConnectionAccessibility { get; private set; }
        public IList<AttentionLine> Attention { get; private set; }
        public bool HasAttention { get; private set; }

        public bool IsPairing { get; private set; }
        public bool ShowDashboardCards { get; private set; }
        public string PairingCode { get; private set; }
        public bool PairingCodeReady { get; private set; }
        public string PairingCodeAccessibility { get; private set; }

        public bool CanTurnOn { get; private set; }
        public bool CanTurnOff { get; private set; }
        public bool CanPair { get; private set; }
        public bool CanCancelPairing { get; private set; }
        public bool CanCheckNow { get; private set; }
        public string TurnOnReason { get; private set; }
        public string TurnOffReason { get; private set; }

        public string PairingStateText { get; private set; }
        public string PairingGlyph { get; private set; }
        public string PairReason { get; private set; }
        public bool ShowForget { get; private set; }
        public bool ForgetEnabled { get; private set; }
        public string ForgetLabel { get; private set; }
        public string ForgetMessage { get; private set; }
        public string PingStateText { get; private set; }

        public string EngineRoleText { get; private set; }
        public string StatusText { get; private set; }

        public bool ActivityLoading { get; private set; }
        public bool ActivityEmpty { get; private set; }
        public bool ActivityUnavailable { get; private set; }
        public bool ActivityShowsLines { get; private set; }

        public bool FailuresLoading { get; private set; }
        public bool FailuresHasRows { get; private set; }
        public string FailuresMessage { get; private set; }
        public bool ShowFailuresMessage { get; private set; }

        public static WindowState Build(AppSession session)
        {
            if (session == null)
            {
                throw new ArgumentNullException("session");
            }
            DashboardModel model = session.Dashboard();
            DashboardInput input = session.BuildInput();
            WindowState state = new WindowState();
            state.Title = model.Title;
            state.Subtitle = model.Subtitle;
            state.CheckedText = model.CheckedText ?? "";
            state.StatusDot = DotName(model);
            state.AccessibilityStatus = model.AccessibilityStatus;

            state.PrimaryAction = model.Primary;
            state.PrimaryLabel = DashboardModel.Label(model.Primary);
            state.HasPrimary = model.Primary != DashboardAction.None;
            state.SecondaryAction = model.Secondary;
            state.SecondaryLabel = DashboardModel.Label(model.Secondary);
            state.HasSecondary = model.Secondary != DashboardAction.None;
            state.SecondaryIsDestructive = model.Secondary == DashboardAction.Forget || model.Secondary == DashboardAction.TurnOffAndForget;
            state.HasPlainSecondary = state.HasSecondary && !state.SecondaryIsDestructive;
            state.IsBusy = model.Kind == StatusKind.Busy || session.HasPendingAction;
            state.ShowAdminNote = model.ShowAdminNote;
            state.ShowPairHint = model.ShowPairHint;

            state.SourceValue = model.SourceCard.Value;
            state.SourceDetails = model.SourceCard.Details;
            state.SourceAccessibility = model.SourceCard.AccessibilityText;
            state.ConnectionValue = model.ConnectionCard.Value;
            state.ConnectionDetails = model.ConnectionCard.Details;
            state.ConnectionAccessibility = model.ConnectionCard.AccessibilityText;
            state.Attention = model.Attention;
            state.HasAttention = model.Attention.Count > 0;

            state.IsPairing = session.PairingActive;
            state.ShowDashboardCards = !state.IsPairing;
            state.PairingCode = session.PairingCode;
            state.PairingCodeReady = state.PairingCode.Length > 0;
            state.PairingCodeAccessibility = state.PairingCodeReady
                ? AppText.PairingCode + " " + SpellDigits(state.PairingCode)
                : AppText.WaitingForCode;

            state.CanTurnOn = model.CanTurnOn;
            state.CanTurnOff = model.CanTurnOff;
            state.CanPair = model.CanPair;
            state.CanCancelPairing = model.CanCancelPairing;
            state.CanCheckNow = !session.HasPendingAction && !input.EngineStarting;
            state.TurnOnReason = model.TurnOnReason ?? "";
            state.TurnOffReason = model.TurnOffReason ?? "";

            bool unavailable = input.Freshness == StatusFreshness.Unavailable || input.EngineStarting || !string.IsNullOrEmpty(input.BrokerFailure);
            if (input.Health == EngineHealth.StateUnknown)
            {
                state.PairingStateText = AppText.ServiceStateUnknownTitle;
                state.PairingGlyph = "";
            }
            else if (unavailable)
            {
                state.PairingStateText = AppText.StatusUnavailableLine;
                state.PairingGlyph = "";
            }
            else if (model.Title == AppText.NotTrustedTitle)
            {
                state.PairingStateText = AppText.NotTrustedTitle;
                state.PairingGlyph = "";
            }
            else if (input.Paired)
            {
                state.PairingStateText = AppText.Paired;
                state.PairingGlyph = "";
            }
            else
            {
                state.PairingStateText = AppText.NotPaired;
                state.PairingGlyph = "";
            }
            state.PairReason = model.CanPair ? "" : (model.PairReason ?? "");
            state.ShowForget = input.Paired && !unavailable;
            bool blocked = input.Running || input.ElevatedSource;
            state.ForgetEnabled = model.CanForget || (blocked && model.CanTurnOff);
            state.ForgetLabel = blocked ? AppText.TurnOffAndForget : AppText.Forget;
            state.ForgetMessage = blocked ? AppText.ForgetBlocked : (model.CanForget ? "" : (model.ForgetReason ?? ""));
            if (input.Running && !string.IsNullOrEmpty(input.PingLine))
            {
                state.PingStateText = input.PingLine;
            }
            else
            {
                state.PingStateText = session.PingEnabled ? AppText.PingOn : AppText.PingOff;
            }

            state.EngineRoleText = session.EngineRoleText();
            state.StatusText = model.Title + ". " + model.Subtitle;

            state.ActivityLoading = session.ActivityState == ListState.Loading;
            state.ActivityEmpty = session.ActivityState == ListState.Empty;
            state.ActivityUnavailable = session.ActivityState == ListState.Unavailable;
            state.ActivityShowsLines = session.Activity.Count > 0 && session.ActivityState == ListState.Loaded;

            state.FailuresLoading = session.FailuresState == ListState.Loading;
            state.FailuresHasRows = session.FailuresState == ListState.Loaded && session.Failures.Groups.Count > 0;
            switch (session.FailuresState)
            {
                case ListState.Idle:
                    state.FailuresMessage = AppText.FailuresNotLoaded;
                    break;
                case ListState.Empty:
                    state.FailuresMessage = AppText.NoFailures;
                    break;
                case ListState.Unavailable:
                    state.FailuresMessage = AppText.FailuresUnavailable;
                    break;
                default:
                    state.FailuresMessage = "";
                    break;
            }
            state.ShowFailuresMessage = state.FailuresMessage.Length > 0;
            return state;
        }

        private static string DotName(DashboardModel model)
        {
            StatusKind kind = model.Kind;
            // Not trusted needs the person, so the dot shows attention.
            if (kind == StatusKind.Off && model.Title == AppText.NotTrustedTitle)
            {
                kind = StatusKind.Attention;
            }
            return kind.ToString();
        }

        // Narrator reads "4 8 2 1 9 3" digit by digit.
        private static string SpellDigits(string code)
        {
            System.Text.StringBuilder spelled = new System.Text.StringBuilder();
            for (int index = 0; index < code.Length; index++)
            {
                if (code[index] == ' ')
                {
                    continue;
                }
                if (spelled.Length > 0)
                {
                    spelled.Append(' ');
                }
                spelled.Append(code[index]);
            }
            return spelled.ToString();
        }
    }
}
