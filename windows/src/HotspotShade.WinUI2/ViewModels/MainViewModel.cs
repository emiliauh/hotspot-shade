using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.App;
using HotspotShade.WinUI2.Services;
using Windows.UI.Core;
using Windows.UI.Xaml;

namespace HotspotShade.WinUI2.ViewModels
{
    // The one view model for the window. It drives the Core AppSession over
    // the real broker connection and rebuilds the bindable WindowState after
    // every answer. Every value comes from the engine.
    public sealed class MainViewModel : INotifyPropertyChanged
    {
        private static readonly TimeSpan VisiblePoll = TimeSpan.FromSeconds(1);
        private static readonly TimeSpan HiddenPoll = TimeSpan.FromSeconds(5);

        private readonly AppSession session;
        private readonly BrokerConnection broker;
        private readonly CoreDispatcher dispatcher;
        private readonly DispatcherTimer statusTimer = new DispatcherTimer();
        private readonly DispatcherTimer pairTimer = new DispatcherTimer();
        private readonly DispatcherTimer activityTimer = new DispatcherTimer();
        private bool refreshing;
        private bool polling;
        private bool activityVisible;
        private bool started;

        public MainViewModel(BrokerConnection broker, CoreDispatcher dispatcher)
        {
            if (broker == null)
            {
                throw new ArgumentNullException("broker");
            }
            this.broker = broker;
            this.dispatcher = dispatcher;
            session = new AppSession(broker, delegate { return DateTime.UtcNow; });
            AttentionRows = new ObservableCollection<AttentionRow>();
            ActivityRows = new ObservableCollection<ActivityRow>();
            FailureRows = new ObservableCollection<FailureRow>();
            statusTimer.Interval = VisiblePoll;
            statusTimer.Tick += StatusTimer_Tick;
            pairTimer.Interval = TimeSpan.FromMilliseconds(700);
            pairTimer.Tick += PairTimer_Tick;
            activityTimer.Interval = TimeSpan.FromSeconds(2);
            activityTimer.Tick += ActivityTimer_Tick;
            broker.Changed += Broker_Changed;
            Rebuild();
        }

        public event PropertyChangedEventHandler PropertyChanged;

        public HotspotShade.WinUI2.Core.App.WindowState State { get; private set; }

        public ObservableCollection<AttentionRow> AttentionRows { get; private set; }

        public ObservableCollection<ActivityRow> ActivityRows { get; private set; }

        public ObservableCollection<FailureRow> FailureRows { get; private set; }

        public bool ShowActivityDetails { get; private set; }

        public bool PingEnabled
        {
            get { return session.PingEnabled; }
        }

        public string FailureReport
        {
            get { return session.FailureReport(); }
        }

        public async Task StartAsync()
        {
            if (started)
            {
                return;
            }
            started = true;
            statusTimer.Start();
            await EnsureBrokerAsync();
            await RefreshAsync();
        }

        // The window became visible or hidden. A hidden window polls slower,
        // like the macOS app.
        public void SetWindowVisible(bool visible)
        {
            statusTimer.Interval = visible ? VisiblePoll : HiddenPoll;
        }

        public void SetActivityVisible(bool visible)
        {
            activityVisible = visible;
            if (visible)
            {
                activityTimer.Start();
            }
            else
            {
                activityTimer.Stop();
            }
        }

        public async Task EnsureBrokerAsync()
        {
            await broker.EnsureStartedAsync();
            if (broker.LaunchFailure != null)
            {
                session.SetBrokerFailure(broker.LaunchFailure);
                Rebuild();
            }
        }

        public async Task RefreshAsync()
        {
            if (refreshing)
            {
                return;
            }
            refreshing = true;
            try
            {
                await session.RefreshAsync();
            }
            finally
            {
                refreshing = false;
            }
            Rebuild();
        }

        public async Task PerformAsync(DashboardAction action)
        {
            switch (action)
            {
                case DashboardAction.Pair:
                case DashboardAction.PairAgain:
                    await PairAsync();
                    return;
                case DashboardAction.TurnOn:
                    await RunAsync(session.TurnOnAsync());
                    return;
                case DashboardAction.TurnOff:
                    await RunAsync(session.TurnOffAsync());
                    return;
                case DashboardAction.TurnOffAndForget:
                    await RunAsync(session.TurnOffAndForgetAsync());
                    return;
                case DashboardAction.Forget:
                    await RunAsync(session.ForgetAsync());
                    return;
                case DashboardAction.CheckNow:
                    await RunAsync(session.CheckNowAsync());
                    return;
                case DashboardAction.Retry:
                    if (session.HasBrokerFailure)
                    {
                        session.SetBrokerFailure(null);
                        Rebuild();
                        await EnsureBrokerAsync();
                        await RefreshAsync();
                    }
                    else
                    {
                        await RunAsync(session.RetryAsync());
                    }
                    return;
            }
        }

        public async Task PairAsync()
        {
            await RunAsync(session.PairAsync());
            if (session.PairingActive)
            {
                pairTimer.Start();
            }
        }

        public async Task CancelPairingAsync()
        {
            pairTimer.Stop();
            await RunAsync(session.CancelPairingAsync());
        }

        public async Task LoadActivityAsync(bool reset)
        {
            await session.LoadActivityAsync(reset);
            RebuildActivity();
            Rebuild();
        }

        public async Task LoadFailuresAsync()
        {
            Task load = session.LoadFailuresAsync();
            Rebuild();
            await load;
            RebuildFailures();
            Rebuild();
        }

        public Task<string> DiagnosticsReportAsync(string appVersion, string windowsVersion)
        {
            return session.DiagnosticsReportAsync(appVersion, windowsVersion);
        }

        public void SetPing(bool enabled)
        {
            session.PingEnabled = enabled;
            Rebuild();
        }

        public void SetActivityDetails(bool enabled)
        {
            ShowActivityDetails = enabled;
            RebuildActivity();
            Raise("ShowActivityDetails");
        }

        private async Task RunAsync(Task work)
        {
            // Show the busy state at once, then the result.
            Rebuild();
            await work;
            Rebuild();
        }

        private async void StatusTimer_Tick(object sender, object e)
        {
            await RefreshAsync();
        }

        private async void PairTimer_Tick(object sender, object e)
        {
            if (polling)
            {
                return;
            }
            polling = true;
            try
            {
                await session.PollPairingAsync();
                if (!session.PairingActive)
                {
                    pairTimer.Stop();
                }
            }
            finally
            {
                polling = false;
            }
            Rebuild();
        }

        private async void ActivityTimer_Tick(object sender, object e)
        {
            if (activityVisible)
            {
                await LoadActivityAsync(false);
            }
        }

        private async void Broker_Changed(object sender, EventArgs e)
        {
            if (dispatcher == null)
            {
                return;
            }
            await dispatcher.RunAsync(CoreDispatcherPriority.Normal, async delegate
            {
                await RefreshAsync();
            });
        }

        private void Rebuild()
        {
            State = HotspotShade.WinUI2.Core.App.WindowState.Build(session);
            AttentionRows.Clear();
            for (int index = 0; index < State.Attention.Count; index++)
            {
                AttentionRows.Add(new AttentionRow(State.Attention[index]));
            }
            Raise("State");
            Raise("PingEnabled");
        }

        private void RebuildActivity()
        {
            ActivityRows.Clear();
            for (int index = session.Activity.Count - 1; index >= 0; index--)
            {
                ActivityRows.Add(new ActivityRow(session.Activity[index], ShowActivityDetails));
            }
        }

        private void RebuildFailures()
        {
            FailureRows.Clear();
            for (int index = 0; index < session.Failures.Groups.Count; index++)
            {
                FailureRows.Add(new FailureRow(session.Failures.Groups[index]));
            }
        }

        private void Raise(string name)
        {
            PropertyChangedEventHandler handler = PropertyChanged;
            if (handler != null)
            {
                handler(this, new PropertyChangedEventArgs(name));
            }
        }
    }
}
