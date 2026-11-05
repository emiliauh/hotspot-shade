using System;
using System.Collections.Generic;

namespace HotspotShade.WinUI2.Core
{
    // The local demo state machine. Every method is deterministic and local.
    // The class has no network client, no file access, no process control, and
    // no service client. The page runs one short timer for the simulated
    // loading states. Tests call CompletePending() without a timer.
    public sealed class DemoSession
    {
        private enum SourceState
        {
            NotPaired,
            Ready,
            NotRunning,
            ProxyOff,
            NotResponding
        }

        private readonly IDemoClock clock;
        private readonly List<DemoLogLine> activity = new List<DemoLogLine>();
        private readonly List<DemoFailureRow> allFailureRows;
        private readonly List<DemoFailureRow> failureRows = new List<DemoFailureRow>();

        private DemoScenario scenario = DemoScenario.Unpaired;
        private DemoScenario lastGoodScenario = DemoScenario.Unpaired;
        private DemoPairingPhase pairing = DemoPairingPhase.Idle;
        private DemoForgetState forget = DemoForgetState.None;
        private DemoPendingAction pending = DemoPendingAction.None;
        private DemoFreshness freshness = DemoFreshness.Fresh;
        private DemoTheme theme = DemoTheme.System;
        private SourceState sourceState = SourceState.NotPaired;

        private bool paired;
        private bool running;
        private bool notTrusted;
        private bool error;
        private string errorText;
        private bool sourceDeviceWarning;
        private bool forgetBlocked;
        private bool startedWithPing;
        private bool pingEnabled = true;
        private bool showActivityDetails;
        private bool activityLoading;
        private bool failuresLoading;
        private bool failuresLoaded;
        private bool failuresCleared;

        private int nextSequence = 1;
        private int connectionCount = 3;

        private DateTimeOffset? lastChecked;
        private DateTimeOffset? lastStopAt;
        private string lastStopPhrase;

        public DemoSession(IDemoClock clock)
        {
            if (clock == null)
            {
                throw new ArgumentNullException("clock");
            }
            this.clock = clock;
            allFailureRows = DemoReports.CreateFailureRows();
            ApplyScenario(DemoScenario.Unpaired);
        }

        public DemoScenario Scenario
        {
            get { return scenario; }
        }

        public bool HasPendingAction
        {
            get { return pending != DemoPendingAction.None; }
        }

        public bool PingEnabled
        {
            get { return pingEnabled; }
        }

        public DemoTheme Theme
        {
            get { return theme; }
        }

        public bool ShowActivityDetails
        {
            get { return showActivityDetails; }
        }

        public void ApplyScenario(DemoScenario value)
        {
            pending = DemoPendingAction.None;
            activityLoading = false;
            failuresLoading = false;
            failuresLoaded = false;
            failuresCleared = false;
            failureRows.Clear();
            activity.Clear();
            nextSequence = 1;

            pairing = DemoPairingPhase.Idle;
            forget = DemoForgetState.None;
            freshness = DemoFreshness.Fresh;
            sourceState = SourceState.NotPaired;
            paired = false;
            running = false;
            notTrusted = false;
            error = false;
            errorText = null;
            sourceDeviceWarning = false;
            forgetBlocked = false;
            lastChecked = clock.Now.AddSeconds(-3);
            lastStopAt = null;
            lastStopPhrase = null;
            scenario = value;
            lastGoodScenario = value;

            switch (value)
            {
                case DemoScenario.PairingCode:
                    pairing = DemoPairingPhase.Confirming;
                    lastChecked = null;
                    break;
                case DemoScenario.PairingFailed:
                    pairing = DemoPairingPhase.Failed;
                    error = true;
                    errorText = DemoText.PairingFailedMessage;
                    lastGoodScenario = DemoScenario.Unpaired;
                    lastChecked = null;
                    break;
                case DemoScenario.NotTrusted:
                    paired = true;
                    notTrusted = true;
                    sourceState = SourceState.NotPaired;
                    lastChecked = clock.Now.AddSeconds(-4);
                    break;
                case DemoScenario.Waiting:
                    paired = true;
                    sourceState = SourceState.NotRunning;
                    lastChecked = clock.Now.AddSeconds(-6);
                    break;
                case DemoScenario.Ready:
                    paired = true;
                    sourceState = SourceState.Ready;
                    lastChecked = clock.Now.AddSeconds(-2);
                    break;
                case DemoScenario.On:
                    paired = true;
                    running = true;
                    sourceState = SourceState.Ready;
                    startedWithPing = pingEnabled;
                    lastChecked = clock.Now.AddSeconds(-2);
                    break;
                case DemoScenario.OnSourceStopped:
                    paired = true;
                    running = true;
                    sourceState = SourceState.NotResponding;
                    sourceDeviceWarning = true;
                    startedWithPing = pingEnabled;
                    lastChecked = clock.Now.AddSeconds(-12);
                    break;
                case DemoScenario.OnNotTrusted:
                    paired = true;
                    running = true;
                    notTrusted = true;
                    sourceState = SourceState.Ready;
                    startedWithPing = pingEnabled;
                    lastChecked = clock.Now.AddSeconds(-2);
                    break;
                case DemoScenario.Stale:
                    paired = true;
                    running = true;
                    sourceState = SourceState.Ready;
                    freshness = DemoFreshness.Stale;
                    startedWithPing = pingEnabled;
                    lastChecked = clock.Now.AddSeconds(-12);
                    break;
                case DemoScenario.Unavailable:
                    paired = true;
                    running = false;
                    sourceState = SourceState.Ready;
                    freshness = DemoFreshness.Unavailable;
                    lastGoodScenario = DemoScenario.On;
                    lastChecked = null;
                    break;
                case DemoScenario.Error:
                    paired = true;
                    sourceState = SourceState.Ready;
                    error = true;
                    errorText = DemoText.ErrorSubtitle;
                    lastGoodScenario = DemoScenario.Ready;
                    lastChecked = clock.Now.AddSeconds(-12);
                    break;
                case DemoScenario.ActivityEmpty:
                    paired = true;
                    sourceState = SourceState.Ready;
                    lastGoodScenario = DemoScenario.Ready;
                    lastChecked = clock.Now.AddSeconds(-2);
                    break;
                case DemoScenario.ForgetConfirmed:
                    paired = false;
                    forget = DemoForgetState.Confirmed;
                    lastGoodScenario = DemoScenario.Unpaired;
                    lastChecked = clock.Now.AddSeconds(-3);
                    break;
            }

            AddSeedLogs(value);
        }

        // MARK: - Visible content

        public DemoDashboardContent BuildDashboard()
        {
            DemoDashboardContent content = new DemoDashboardContent();
            content.IsRunning = running;
            content.IsPaired = paired;
            content.CanCheckNow = pending == DemoPendingAction.None;
            content.CanAct = pending == DemoPendingAction.None;
            content.CheckedText = freshness == DemoFreshness.Unavailable
                ? ""
                : DemoText.CheckedText(lastChecked, clock.Now);
            content.Attention = BuildAttention();
            content.PairingTitle = DemoText.PairingTitle;
            content.PairingSubtitle = DemoText.CheckBothScreens;

            if (pairing == DemoPairingPhase.Starting || pairing == DemoPairingPhase.Confirming)
            {
                bool ready = pairing == DemoPairingPhase.Confirming;
                content.StatusKind = DemoStatusKind.Pairing;
                content.Title = DemoText.Pairing;
                content.Subtitle = DemoText.PairingSubtitle;
                content.IsPairing = true;
                content.CanCheckNow = false;
                content.PairingCodeReady = ready;
                content.PairingCode = ready ? DemoText.PairingCodeDisplay : "";
                content.PairingCodeAccessibility = ready ? DemoText.PairingCodeAccessibility : "";
                content.PairingStatus = ready ? DemoText.CheckBothScreens : DemoText.WaitingForCode;
                content.SourceDevice = new DemoCard(
                    DemoText.SourceDevice,
                    paired ? DemoText.Paired : DemoText.NotPaired,
                    new string[] { DemoText.LookingForSourceDevice });
                content.Connection = new DemoCard(
                    DemoText.Connection,
                    DemoText.TunnelOff,
                    new string[] { DemoText.NoConnectionYet });
                content.Attention = Array.Empty<DemoAttentionItem>();
                return content;
            }

            if (pairing == DemoPairingPhase.Failed)
            {
                content.StatusKind = DemoStatusKind.Attention;
                content.Title = DemoText.PairingFailed;
                content.Subtitle = string.IsNullOrEmpty(errorText) ? DemoText.PairingFailedMessage : errorText;
                content.PrimaryAction = DemoPrimaryAction.PairAgain;
                content.CanCheckNow = false;
                content.SourceDevice = new DemoCard(
                    DemoText.SourceDevice,
                    DemoText.NotPaired,
                    new string[] { DemoText.PairWhenReady });
                content.Connection = new DemoCard(
                    DemoText.Connection,
                    DemoText.TunnelOff,
                    new string[] { DemoText.NoConnectionYet });
                return content;
            }

            if (DashboardIsBusy())
            {
                content.StatusKind = DemoStatusKind.Busy;
                content.Title = BusyTitle();
                content.Subtitle = pending == DemoPendingAction.CheckNow
                    ? DemoText.CheckingSubtitle
                    : DemoText.TakesAMoment;
                content.IsBusy = true;
                content.CanCheckNow = false;
                content.BusyText = content.Title;
                if (freshness == DemoFreshness.Unavailable)
                {
                    content.SourceDevice = new DemoCard(
                        DemoText.SourceDevice,
                        DemoText.StatusUnavailableLine,
                        new string[] { DemoText.CheckStatusAgain });
                    content.Connection = new DemoCard(
                        DemoText.Connection,
                        DemoText.StatusUnavailableLine,
                        new string[] { DemoText.CheckStatusAgain });
                }
                else
                {
                    content.SourceDevice = BuildSourceCard();
                    content.Connection = BuildConnectionCard();
                }
                return content;
            }

            if (freshness == DemoFreshness.Unavailable)
            {
                content.StatusKind = DemoStatusKind.Attention;
                content.Title = DemoText.StatusUnavailable;
                content.Subtitle = "The simulated engine did not answer.";
                content.PrimaryAction = DemoPrimaryAction.CheckNow;
                content.SecondaryAction = forgetBlocked
                    ? DemoSecondaryAction.TurnOffAndForget
                    : DemoSecondaryAction.None;
                content.SourceDevice = new DemoCard(
                    DemoText.SourceDevice,
                    DemoText.StatusUnavailableLine,
                    new string[] { DemoText.CheckStatusAgain });
                content.Connection = new DemoCard(
                    DemoText.Connection,
                    DemoText.StatusUnavailableLine,
                    new string[] { DemoText.CheckStatusAgain });
                return content;
            }

            if (error)
            {
                content.StatusKind = DemoStatusKind.Attention;
                content.Title = DemoText.NeedsAttention;
                content.Subtitle = string.IsNullOrEmpty(errorText) ? DemoText.ErrorSubtitle : errorText;
                content.PrimaryAction = DemoPrimaryAction.Retry;
                content.SecondaryAction = forgetBlocked
                    ? DemoSecondaryAction.TurnOffAndForget
                    : DemoSecondaryAction.None;
                content.SourceDevice = BuildSourceCard();
                content.Connection = BuildConnectionCard();
                return content;
            }

            if (running)
            {
                content.StatusKind = DemoStatusKind.On;
                content.Title = DemoText.On;
                content.Subtitle = sourceDeviceWarning ? DemoText.SourceStopped : DemoText.OnSubtitle;
                content.PrimaryAction = DemoPrimaryAction.TurnOff;
                if (forgetBlocked)
                {
                    content.SecondaryAction = DemoSecondaryAction.TurnOffAndForget;
                }
                else if (freshness == DemoFreshness.Stale)
                {
                    content.SecondaryAction = DemoSecondaryAction.CheckNow;
                }
                content.SourceDevice = BuildSourceCard();
                content.Connection = BuildConnectionCard();
                return content;
            }

            if (paired && notTrusted)
            {
                content.StatusKind = DemoStatusKind.Attention;
                content.Title = DemoText.NotTrusted;
                content.Subtitle = DemoText.NotTrustedSubtitle;
                content.PrimaryAction = DemoPrimaryAction.PairAgain;
                content.SourceDevice = BuildSourceCard();
                content.Connection = new DemoCard(
                    DemoText.Connection,
                    DemoText.TunnelOff,
                    new string[] { DemoText.NoConnectionYet });
                return content;
            }

            if (paired && sourceState == SourceState.Ready)
            {
                content.StatusKind = DemoStatusKind.Off;
                content.Title = DemoText.Ready;
                content.Subtitle = DemoText.ReadySubtitle;
                content.PrimaryAction = DemoPrimaryAction.TurnOn;
                content.SecondaryAction = DemoSecondaryAction.Forget;
                content.SourceDevice = BuildSourceCard();
                content.Connection = BuildConnectionCard();
                return content;
            }

            if (paired && sourceState == SourceState.NotRunning)
            {
                content.StatusKind = DemoStatusKind.Off;
                content.Title = DemoText.Waiting;
                content.Subtitle = DemoText.NotRunningSubtitle;
                content.SecondaryAction = DemoSecondaryAction.Forget;
                content.SourceDevice = BuildSourceCard();
                content.Connection = BuildConnectionCard();
                return content;
            }

            if (paired && sourceState == SourceState.ProxyOff)
            {
                content.StatusKind = DemoStatusKind.Off;
                content.Title = DemoText.Paired;
                content.Subtitle = DemoText.ProxyOffSubtitle;
                content.SecondaryAction = DemoSecondaryAction.Forget;
                content.SourceDevice = BuildSourceCard();
                content.Connection = BuildConnectionCard();
                return content;
            }

            content.StatusKind = DemoStatusKind.Off;
            content.Title = DemoText.NotPaired;
            if (forget == DemoForgetState.Confirmed)
            {
                content.Subtitle = DemoText.ForgetConfirmed;
            }
            else if (forget == DemoForgetState.NotDelivered)
            {
                content.Subtitle = DemoText.ForgetNotDelivered;
            }
            else
            {
                content.Subtitle = DemoText.UnpairedSubtitle;
            }
            content.PrimaryAction = DemoPrimaryAction.Pair;
            content.ShowPairHint = !content.HasAttention;
            content.SourceDevice = BuildSourceCard();
            content.Connection = BuildConnectionCard();
            return content;
        }

        public DemoActivityContent BuildActivity()
        {
            DemoActivityContent content = new DemoActivityContent();
            content.Lines = activity.ToArray();
            if (freshness == DemoFreshness.Unavailable)
            {
                content.State = DemoActivityState.Unavailable;
                content.Message = DemoText.ActivityUnavailable;
                content.Detail = DemoText.StatusUnavailableLine;
            }
            else if (activityLoading)
            {
                content.State = DemoActivityState.Loading;
                content.Message = DemoText.ActivityLoading;
                content.Detail = "";
            }
            else if (activity.Count == 0)
            {
                content.State = DemoActivityState.Empty;
                content.Message = DemoText.ActivityEmptyTitle;
                content.Detail = DemoText.ActivityEmptyDetail;
            }
            else
            {
                content.State = DemoActivityState.Loaded;
                content.Message = "";
                content.Detail = "";
            }
            return content;
        }

        public DemoFailuresContent BuildFailures()
        {
            DemoFailuresContent content = new DemoFailuresContent();
            if (!running)
            {
                content.Rows = Array.Empty<DemoFailureRow>();
                content.Total = 0;
                content.State = DemoFailuresState.Idle;
                content.TunnelOff = true;
                content.Message = DemoText.FailuresTunnelOff;
                return content;
            }

            content.Rows = failureRows.ToArray();
            int total = 0;
            for (int index = 0; index < failureRows.Count; index++)
            {
                total += failureRows[index].Count;
            }
            content.Total = total;

            if (failuresLoading)
            {
                content.State = DemoFailuresState.Loading;
                content.Message = DemoText.FailuresLoading;
            }
            else if (!failuresLoaded)
            {
                content.State = DemoFailuresState.Idle;
                content.Message = DemoText.FailuresIdle;
            }
            else if (failuresCleared || failureRows.Count == 0)
            {
                content.State = DemoFailuresState.Empty;
                content.Message = DemoText.FailuresEmpty;
            }
            else
            {
                content.State = DemoFailuresState.Loaded;
                content.Message = "";
            }
            return content;
        }

        public DemoSettingsContent BuildSettings()
        {
            DemoSettingsContent content = new DemoSettingsContent();
            content.Paired = paired;
            content.Running = running;
            content.IsPairing = pairing == DemoPairingPhase.Starting || pairing == DemoPairingPhase.Confirming;
            content.PairingStateText = PairingStateText();
            content.PairingGlyph = PairingGlyph();
            content.PairActionEnabled = !running && !HasPendingAction
                && (pairing == DemoPairingPhase.Idle || pairing == DemoPairingPhase.Failed
                    || pairing == DemoPairingPhase.Paired);
            if (running)
            {
                content.PairActionReason = "Turn off the tunnel first.";
            }
            else if (content.IsPairing)
            {
                content.PairActionReason = "Pairing is already running.";
            }
            else if (HasPendingAction)
            {
                content.PairActionReason = "Wait for the current action to finish.";
            }
            else
            {
                content.PairActionReason = "";
            }
            content.ShowForget = paired;
            content.ForgetBlocked = running;
            if (running)
            {
                content.ForgetMessage = DemoText.ForgetBlocked;
            }
            else
            {
                content.ForgetMessage = DemoText.ForgetMessage(forget);
            }
            content.PingEnabled = pingEnabled;
            content.PingStateText = running ? DemoText.PingLine(startedWithPing) : DemoText.PingSettingNote;
            content.Theme = theme;
            content.NotificationsText = DemoText.NotificationsText;
            content.LoginText = DemoText.LoginText;
            content.EngineText = DemoText.EngineNone;
            content.ModeText = DemoText.ModeDemo;
            content.StatusText = BuildDashboard().Title;
            content.Failures = BuildFailures();
            return content;
        }

        // MARK: - Actions

        public void PerformPrimaryAction()
        {
            DemoDashboardContent content = BuildDashboard();
            switch (content.PrimaryAction)
            {
                case DemoPrimaryAction.Pair:
                case DemoPrimaryAction.PairAgain:
                    BeginPairing();
                    break;
                case DemoPrimaryAction.TurnOn:
                    BeginTurnOn();
                    break;
                case DemoPrimaryAction.TurnOff:
                    BeginTurnOff();
                    break;
                case DemoPrimaryAction.Retry:
                    if (pairing == DemoPairingPhase.Failed)
                    {
                        BeginPairing();
                    }
                    else
                    {
                        BeginCheckNow();
                    }
                    break;
                case DemoPrimaryAction.CheckNow:
                    BeginCheckNow();
                    break;
            }
        }

        public void PerformSecondaryAction()
        {
            DemoDashboardContent content = BuildDashboard();
            switch (content.SecondaryAction)
            {
                case DemoSecondaryAction.Forget:
                    Forget();
                    break;
                case DemoSecondaryAction.TurnOffAndForget:
                    TurnOffAndForget();
                    break;
                case DemoSecondaryAction.CheckNow:
                    BeginCheckNow();
                    break;
            }
        }

        public void PerformAttentionAction(DemoAttentionAction action)
        {
            switch (action)
            {
                case DemoAttentionAction.CheckNow:
                    BeginCheckNow();
                    break;
                case DemoAttentionAction.TurnOff:
                    BeginTurnOff();
                    break;
                case DemoAttentionAction.TurnOffAndForget:
                    TurnOffAndForget();
                    break;
            }
        }

        public void BeginPairing()
        {
            if (running || HasPendingAction)
            {
                return;
            }
            paired = false;
            notTrusted = false;
            error = false;
            errorText = null;
            forget = DemoForgetState.None;
            forgetBlocked = false;
            sourceState = SourceState.NotPaired;
            pairing = DemoPairingPhase.Starting;
            pending = DemoPendingAction.PairingStart;
            scenario = DemoScenario.PairingCode;
            freshness = DemoFreshness.Fresh;
            lastChecked = null;
            AddLog("You started the simulated pairing.", "sim");
        }

        public void ApprovePairing()
        {
            if (pairing != DemoPairingPhase.Confirming)
            {
                return;
            }
            paired = true;
            notTrusted = false;
            pairing = DemoPairingPhase.Paired;
            pending = DemoPendingAction.None;
            sourceState = SourceState.Ready;
            freshness = DemoFreshness.Fresh;
            scenario = DemoScenario.Ready;
            lastGoodScenario = DemoScenario.Ready;
            error = false;
            errorText = null;
            forget = DemoForgetState.None;
            forgetBlocked = false;
            lastChecked = clock.Now;
            AddLog("You approved the simulated pairing.", "info");
        }

        public void CancelPairing()
        {
            if (pairing != DemoPairingPhase.Starting && pairing != DemoPairingPhase.Confirming)
            {
                return;
            }
            pairing = DemoPairingPhase.Idle;
            pending = DemoPendingAction.None;
            paired = false;
            sourceState = SourceState.NotPaired;
            scenario = DemoScenario.Unpaired;
            lastGoodScenario = DemoScenario.Unpaired;
            freshness = DemoFreshness.Fresh;
            error = false;
            errorText = null;
            lastChecked = clock.Now;
            AddLog("You cancelled the simulated pairing.", "sim");
        }

        public void SimulatePairingFailure()
        {
            if (pairing != DemoPairingPhase.Confirming)
            {
                return;
            }
            pairing = DemoPairingPhase.Failed;
            pending = DemoPendingAction.None;
            paired = false;
            sourceState = SourceState.NotPaired;
            scenario = DemoScenario.PairingFailed;
            lastGoodScenario = DemoScenario.Unpaired;
            error = true;
            errorText = DemoText.PairingFailedMessage;
            lastChecked = null;
            AddLog("The simulated pairing failed.", "sim");
        }

        public void BeginTurnOn()
        {
            if (!paired || running || HasPendingAction || notTrusted
                || (pairing != DemoPairingPhase.Idle && pairing != DemoPairingPhase.Paired)
                || sourceState != SourceState.Ready
                || freshness == DemoFreshness.Unavailable)
            {
                return;
            }
            pending = DemoPendingAction.TunnelStart;
            error = false;
            errorText = null;
            lastChecked = clock.Now;
            AddLog("You turned on the simulated tunnel.", "sim");
        }

        public void BeginTurnOff()
        {
            if (!running || HasPendingAction)
            {
                return;
            }
            pending = DemoPendingAction.TunnelStop;
            forgetBlocked = false;
            AddLog("You turned off the simulated tunnel.", "sim");
        }

        public bool Forget()
        {
            if (HasPendingAction)
            {
                return false;
            }
            if (running)
            {
                forgetBlocked = true;
                AddLog("Forget is blocked while the simulated tunnel runs.", "sim");
                return false;
            }
            CommitForget();
            return true;
        }

        public void TurnOffAndForget()
        {
            if (HasPendingAction)
            {
                return;
            }
            if (running)
            {
                pending = DemoPendingAction.ForgetAfterStop;
                forgetBlocked = false;
                AddLog("You turned off the simulated tunnel to forget the source device.", "sim");
                return;
            }
            CommitForget();
        }

        public void BeginCheckNow()
        {
            if (HasPendingAction
                || pairing == DemoPairingPhase.Starting
                || pairing == DemoPairingPhase.Confirming
                || pairing == DemoPairingPhase.Failed)
            {
                return;
            }
            pending = DemoPendingAction.CheckNow;
        }

        public void RefreshActivity()
        {
            if (activityLoading)
            {
                return;
            }
            activityLoading = true;
            pending = DemoPendingAction.RefreshActivity;
        }

        public void LoadFailures()
        {
            if (!running || failuresLoading)
            {
                return;
            }
            failuresLoading = true;
            pending = DemoPendingAction.LoadFailures;
        }

        public void ClearFailures()
        {
            failureRows.Clear();
            failuresCleared = true;
            failuresLoaded = true;
            AddLog("You cleared the simulated failures.", "sim");
        }

        public void SetPingEnabled(bool enabled)
        {
            pingEnabled = enabled;
        }

        public void SetTheme(DemoTheme value)
        {
            theme = value;
        }

        public void SetActivityDetails(bool enabled)
        {
            showActivityDetails = enabled;
        }

        // Complete the one delayed action. The page timer calls this after a
        // short local delay. A test calls it directly.
        public void CompletePending()
        {
            DemoPendingAction action = pending;
            if (action == DemoPendingAction.None)
            {
                return;
            }
            pending = DemoPendingAction.None;

            switch (action)
            {
                case DemoPendingAction.PairingStart:
                    pairing = DemoPairingPhase.Confirming;
                    scenario = DemoScenario.PairingCode;
                    AddLog("The simulated source device shows a code.", "info");
                    break;
                case DemoPendingAction.TunnelStart:
                    running = true;
                    sourceState = SourceState.Ready;
                    freshness = DemoFreshness.Fresh;
                    startedWithPing = pingEnabled;
                    scenario = DemoScenario.On;
                    lastGoodScenario = DemoScenario.On;
                    lastChecked = clock.Now;
                    lastStopAt = null;
                    lastStopPhrase = null;
                    ClearFailureData();
                    AddLog("The simulated tunnel is on.", "info");
                    break;
                case DemoPendingAction.TunnelStop:
                    FinishStop();
                    AddLog("The simulated tunnel is off.", "info");
                    break;
                case DemoPendingAction.ForgetAfterStop:
                    FinishStop();
                    CommitForget();
                    break;
                case DemoPendingAction.CheckNow:
                    FinishCheck();
                    AddLog("You checked the simulated source device.", "info");
                    break;
                case DemoPendingAction.RefreshActivity:
                    activityLoading = false;
                    break;
                case DemoPendingAction.LoadFailures:
                    failuresLoading = false;
                    failuresLoaded = true;
                    if (!failuresCleared)
                    {
                        failureRows.Clear();
                        failureRows.AddRange(allFailureRows);
                    }
                    break;
            }
        }

        public string FailureReport()
        {
            return DemoReports.FailureReport(BuildFailures());
        }

        public string DiagnosticsReport()
        {
            return DemoReports.DiagnosticsReport(
                BuildDashboard(),
                BuildActivity(),
                BuildFailures(),
                theme,
                pingEnabled,
                clock.Now);
        }

        // MARK: - Private builders

        private bool DashboardIsBusy()
        {
            return pending == DemoPendingAction.TunnelStart
                || pending == DemoPendingAction.TunnelStop
                || pending == DemoPendingAction.ForgetAfterStop
                || pending == DemoPendingAction.CheckNow;
        }

        private string BusyTitle()
        {
            switch (pending)
            {
                case DemoPendingAction.TunnelStart:
                    return DemoText.StartingTunnel;
                case DemoPendingAction.TunnelStop:
                case DemoPendingAction.ForgetAfterStop:
                    return DemoText.TurningOff;
                case DemoPendingAction.CheckNow:
                    return DemoText.Checking;
                default:
                    return DemoText.StartingTunnel;
            }
        }

        private IReadOnlyList<DemoAttentionItem> BuildAttention()
        {
            List<DemoAttentionItem> items = new List<DemoAttentionItem>();
            if (forgetBlocked)
            {
                items.Add(new DemoAttentionItem(DemoText.ForgetBlocked, DemoAttentionAction.TurnOffAndForget));
            }
            if (sourceDeviceWarning)
            {
                items.Add(new DemoAttentionItem(DemoText.SourceStopped, DemoAttentionAction.None));
            }
            if (running && notTrusted)
            {
                items.Add(new DemoAttentionItem(DemoText.NotTrustedWhileRunning, DemoAttentionAction.TurnOff));
            }
            if (freshness == DemoFreshness.Stale)
            {
                items.Add(new DemoAttentionItem(DemoText.StaleStatus, DemoAttentionAction.CheckNow));
            }

            List<DemoAttentionItem> unique = new List<DemoAttentionItem>();
            HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
            for (int index = 0; index < items.Count; index++)
            {
                if (seen.Add(items[index].Text))
                {
                    unique.Add(items[index]);
                }
            }
            return unique;
        }

        private DemoCard BuildSourceCard()
        {
            string value;
            List<string> details = new List<string>();
            if (notTrusted)
            {
                value = DemoText.NotTrusted;
                details.Add(running ? DemoText.PairAfterTurnOff : DemoText.PairToRestoreTrust);
            }
            else if (paired)
            {
                value = DemoText.Paired;
                if (sourceState == SourceState.NotRunning)
                {
                    details.Add(DemoText.OpenSourceDeviceApp);
                }
                else if (running)
                {
                    details.Add(DemoText.TunnelUsesSourceDevice);
                }
                else
                {
                    details.Add(DemoText.PairingIsSaved);
                }
            }
            else
            {
                value = DemoText.NotPaired;
                if (forget == DemoForgetState.None)
                {
                    details.Add(DemoText.PairWhenReady);
                }
                else
                {
                    details.Add("Press Pair to continue.");
                }
            }
            return new DemoCard(DemoText.SourceDevice, value, details);
        }

        private DemoCard BuildConnectionCard()
        {
            string value = DemoText.TunnelOff;
            if (running)
            {
                value = DemoText.TunnelOn;
            }
            if (pending == DemoPendingAction.TunnelStart)
            {
                value = DemoText.StartingValue;
            }
            else if (pending == DemoPendingAction.TunnelStop || pending == DemoPendingAction.ForgetAfterStop)
            {
                value = DemoText.TurningOffValue;
            }

            List<string> details = new List<string>();
            bool tunnelTransition = pending == DemoPendingAction.TunnelStart
                || pending == DemoPendingAction.TunnelStop
                || pending == DemoPendingAction.ForgetAfterStop;
            if (running && !tunnelTransition)
            {
                details.Add(DemoText.PingLine(startedWithPing));
                details.Add(DemoText.Connections(connectionCount));
            }
            else
            {
                details.Add(DemoText.NoConnectionYet);
            }
            string stop = DemoText.LastStop(lastStopPhrase, lastStopAt);
            if (!string.IsNullOrEmpty(stop))
            {
                details.Add(stop);
            }
            return new DemoCard(DemoText.Connection, value, details);
        }

        private string PairingStateText()
        {
            if (freshness == DemoFreshness.Unavailable)
            {
                return DemoText.StatusUnavailableLine;
            }
            if (pairing == DemoPairingPhase.Failed)
            {
                return DemoText.PairingFailed;
            }
            if (pairing == DemoPairingPhase.Starting || pairing == DemoPairingPhase.Confirming)
            {
                return DemoText.Pairing;
            }
            if (notTrusted)
            {
                return DemoText.NotTrusted;
            }
            return paired ? DemoText.Paired : DemoText.NotPaired;
        }

        private string PairingGlyph()
        {
            if (freshness == DemoFreshness.Unavailable)
            {
                return "\uE946";
            }
            if (pairing == DemoPairingPhase.Failed || notTrusted)
            {
                return "\uE7BA";
            }
            return paired ? "\uE73E" : "\uE71B";
        }

        private void FinishStop()
        {
            running = false;
            sourceState = SourceState.Ready;
            freshness = DemoFreshness.Fresh;
            scenario = DemoScenario.Ready;
            lastGoodScenario = DemoScenario.Ready;
            lastStopPhrase = "You turned the tunnel off.";
            lastStopAt = clock.Now;
            lastChecked = clock.Now;
            sourceDeviceWarning = false;
            notTrusted = false;
            forgetBlocked = false;
            ClearFailureData();
        }

        private void ClearFailureData()
        {
            failureRows.Clear();
            failuresLoading = false;
            failuresLoaded = false;
            failuresCleared = false;
        }

        private void FinishCheck()
        {
            freshness = DemoFreshness.Fresh;
            lastChecked = clock.Now;
            error = false;
            errorText = null;

            if (scenario == DemoScenario.Unavailable
                || scenario == DemoScenario.Stale
                || scenario == DemoScenario.Error)
            {
                if (lastGoodScenario == DemoScenario.On
                    || lastGoodScenario == DemoScenario.OnSourceStopped
                    || lastGoodScenario == DemoScenario.Stale)
                {
                    paired = true;
                    running = true;
                    sourceState = SourceState.Ready;
                    scenario = DemoScenario.On;
                    lastGoodScenario = DemoScenario.On;
                    startedWithPing = pingEnabled;
                    notTrusted = false;
                }
                else
                {
                    paired = true;
                    running = false;
                    sourceState = SourceState.Ready;
                    scenario = DemoScenario.Ready;
                    lastGoodScenario = DemoScenario.Ready;
                    notTrusted = false;
                }
            }

            if (sourceDeviceWarning)
            {
                sourceDeviceWarning = false;
                if (paired)
                {
                    running = true;
                    sourceState = SourceState.Ready;
                    scenario = DemoScenario.On;
                    lastGoodScenario = DemoScenario.On;
                }
            }
        }

        private void CommitForget()
        {
            paired = false;
            running = false;
            notTrusted = false;
            pairing = DemoPairingPhase.Idle;
            pending = DemoPendingAction.None;
            sourceState = SourceState.NotPaired;
            freshness = DemoFreshness.Fresh;
            error = false;
            errorText = null;
            forget = DemoForgetState.Confirmed;
            forgetBlocked = false;
            scenario = DemoScenario.Unpaired;
            lastGoodScenario = DemoScenario.Unpaired;
            lastChecked = clock.Now;
            lastStopAt = null;
            lastStopPhrase = null;
            ClearFailureData();
            AddLog("You forgot the simulated source device.", "sim");
        }

        private void AddSeedLogs(DemoScenario value)
        {
            DateTimeOffset now = clock.Now;
            switch (value)
            {
                case DemoScenario.On:
                case DemoScenario.OnSourceStopped:
                case DemoScenario.OnNotTrusted:
                case DemoScenario.Stale:
                    AddLogAt(now.AddSeconds(-40), "sim", "Demo mode started. No engine is present.");
                    AddLogAt(now.AddSeconds(-20), "info", "The simulated source device is ready.");
                    AddLogAt(now.AddSeconds(-8), "info", "The simulated tunnel is on.");
                    AddLogAt(now.AddSeconds(-2), "info", "The simulated source device reports 3 active connections.");
                    break;
                case DemoScenario.ActivityEmpty:
                    break;
                case DemoScenario.PairingCode:
                    AddLogAt(now.AddSeconds(-15), "sim", "Demo mode started. No engine is present.");
                    AddLogAt(now.AddSeconds(-2), "info", "The simulated source device shows a code.");
                    break;
                case DemoScenario.PairingFailed:
                    AddLogAt(now.AddSeconds(-15), "sim", "Demo mode started. No engine is present.");
                    AddLogAt(now.AddSeconds(-2), "sim", "The simulated pairing failed.");
                    break;
                case DemoScenario.NotTrusted:
                    AddLogAt(now.AddSeconds(-15), "sim", "Demo mode started. No engine is present.");
                    AddLogAt(now.AddSeconds(-2), "sim", "The source device does not know this target device.");
                    break;
                case DemoScenario.Waiting:
                    AddLogAt(now.AddSeconds(-15), "sim", "Demo mode started. No engine is present.");
                    AddLogAt(now.AddSeconds(-2), "sim", "Waiting for the simulated source device.");
                    break;
                case DemoScenario.Ready:
                    AddLogAt(now.AddSeconds(-15), "sim", "Demo mode started. No engine is present.");
                    AddLogAt(now.AddSeconds(-2), "info", "The simulated source device is ready.");
                    break;
                case DemoScenario.Error:
                    AddLogAt(now.AddSeconds(-15), "sim", "Demo mode started. No engine is present.");
                    AddLogAt(now.AddSeconds(-2), "sim", "The simulated source device did not answer.");
                    break;
                case DemoScenario.Unavailable:
                    AddLogAt(now.AddSeconds(-15), "sim", "Demo mode started. No engine is present.");
                    AddLogAt(now.AddSeconds(-2), "sim", "The simulated status is unavailable.");
                    break;
                case DemoScenario.ForgetConfirmed:
                    AddLogAt(now.AddSeconds(-15), "sim", "Demo mode started. No engine is present.");
                    AddLogAt(now.AddSeconds(-2), "sim", "You forgot the simulated source device.");
                    break;
                default:
                    AddLogAt(now.AddSeconds(-15), "sim", "Demo mode started. No engine is present.");
                    AddLogAt(now.AddSeconds(-2), "sim", "The simulated source device is not paired.");
                    break;
            }
        }

        private void AddLogAt(DateTimeOffset at, string level, string message)
        {
            DemoLogLine line = new DemoLogLine(at, level, nextSequence, message);
            nextSequence++;
            activity.Insert(0, line);
            if (activity.Count > 50)
            {
                activity.RemoveAt(activity.Count - 1);
            }
        }

        private void AddLog(string message, string level)
        {
            AddLogAt(clock.Now, level, message);
        }
    }
}
