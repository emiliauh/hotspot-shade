using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using HotspotShade.WinUI2.Core;

namespace HotspotShade.WinUI2.ViewModels
{
    // The one view model for the window. It wraps the local demo state
    // machine. It has no service client and starts no background work.
    public sealed class DemoViewModel : INotifyPropertyChanged
    {
        private readonly DemoSession session;

        public DemoViewModel(DemoSession session)
        {
            if (session == null)
            {
                throw new ArgumentNullException("session");
            }
            this.session = session;
            AttentionRows = new ObservableCollection<AttentionRow>();
            ActivityRows = new ObservableCollection<ActivityRow>();
            Scenarios = DemoScenarios.All;
            Refresh();
        }

        public DemoDashboardContent Dashboard { get; private set; }

        public DemoActivityContent Activity { get; private set; }

        public DemoSettingsContent Settings { get; private set; }

        public ObservableCollection<AttentionRow> AttentionRows { get; private set; }

        public ObservableCollection<ActivityRow> ActivityRows { get; private set; }

        public IReadOnlyList<DemoScenarioInfo> Scenarios { get; private set; }

        public bool HasPendingAction
        {
            get { return session.HasPendingAction; }
        }

        public bool ShowActivityDetails
        {
            get { return session.ShowActivityDetails; }
        }

        public bool PingEnabled
        {
            get { return session.PingEnabled; }
        }

        public DemoTheme Theme
        {
            get { return session.Theme; }
        }

        public int ScenarioIndex
        {
            get
            {
                for (int index = 0; index < Scenarios.Count; index++)
                {
                    if (Scenarios[index].Scenario == session.Scenario)
                    {
                        return index;
                    }
                }
                return 0;
            }
        }

        public string FailureReport
        {
            get { return session.FailureReport(); }
        }

        public string DiagnosticsReport
        {
            get { return session.DiagnosticsReport(); }
        }

        public event PropertyChangedEventHandler PropertyChanged;

        public void Refresh()
        {
            Dashboard = session.BuildDashboard();
            Activity = session.BuildActivity();
            Settings = session.BuildSettings();
            RebuildAttention();
            RebuildActivity();
            Raise("Dashboard");
            Raise("Activity");
            Raise("Settings");
            Raise("HasPendingAction");
            Raise("ShowActivityDetails");
            Raise("PingEnabled");
            Raise("Theme");
            Raise("ScenarioIndex");
        }

        public void PerformPrimaryAction()
        {
            session.PerformPrimaryAction();
            Refresh();
        }

        public void PerformSecondaryAction()
        {
            session.PerformSecondaryAction();
            Refresh();
        }

        public void PerformAttentionAction(DemoAttentionAction action)
        {
            session.PerformAttentionAction(action);
            Refresh();
        }

        public void BeginPairing()
        {
            session.BeginPairing();
            Refresh();
        }

        public void ApprovePairing()
        {
            session.ApprovePairing();
            Refresh();
        }

        public void CancelPairing()
        {
            session.CancelPairing();
            Refresh();
        }

        public void SimulatePairingFailure()
        {
            session.SimulatePairingFailure();
            Refresh();
        }

        public void Forget()
        {
            session.Forget();
            Refresh();
        }

        public void TurnOffAndForget()
        {
            session.TurnOffAndForget();
            Refresh();
        }

        public void CheckNow()
        {
            session.BeginCheckNow();
            Refresh();
        }

        public void RefreshActivity()
        {
            session.RefreshActivity();
            Refresh();
        }

        public void LoadFailures()
        {
            session.LoadFailures();
            Refresh();
        }

        public void ClearFailures()
        {
            session.ClearFailures();
            Refresh();
        }

        public void CompletePending()
        {
            session.CompletePending();
            Refresh();
        }

        public void ApplyScenario(DemoScenario scenario)
        {
            session.ApplyScenario(scenario);
            Refresh();
        }

        public void SetPing(bool enabled)
        {
            session.SetPingEnabled(enabled);
            Refresh();
        }

        public void SetTheme(DemoTheme theme)
        {
            session.SetTheme(theme);
            Refresh();
        }

        public void SetActivityDetails(bool enabled)
        {
            session.SetActivityDetails(enabled);
            RebuildActivity();
            Raise("ShowActivityDetails");
        }

        private void RebuildAttention()
        {
            AttentionRows.Clear();
            for (int index = 0; index < Dashboard.Attention.Count; index++)
            {
                AttentionRows.Add(new AttentionRow(Dashboard.Attention[index]));
            }
        }

        private void RebuildActivity()
        {
            ActivityRows.Clear();
            for (int index = 0; index < Activity.Lines.Count; index++)
            {
                ActivityRows.Add(new ActivityRow(Activity.Lines[index], session.ShowActivityDetails));
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
