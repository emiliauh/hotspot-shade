using System;
using System.ComponentModel;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core;
using HotspotShade.WinUI2.Services;
using HotspotShade.WinUI2.ViewModels;
using Windows.UI.ViewManagement;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Input;
using muxc = Microsoft.UI.Xaml.Controls;

namespace HotspotShade.WinUI2
{
    // The one window. It shows a native WinUI 2 menu bar, a NavigationView with
    // Dashboard, Activity, and Settings, and simulated data only. No engine,
    // service, route, network listener, or credential is present.
    public sealed partial class MainPage : Page
    {
        private readonly LocalSettingsStore settingsStore;
        private DispatcherTimer pendingTimer;
        private bool syncingControls;
        private bool syncingNavigation;
        private bool dialogOpen;
        private bool initialized;
        private bool codeCopied;

        public MainPage()
        {
            ViewModel = new DemoViewModel(new DemoSession(new SystemDemoClock()));
            settingsStore = new LocalSettingsStore();
            this.InitializeComponent();
            ViewModel.PropertyChanged += ViewModel_PropertyChanged;
            Loaded += MainPage_Loaded;
            Unloaded += MainPage_Unloaded;
        }

        public DemoViewModel ViewModel { get; private set; }

        private void ViewModel_PropertyChanged(object sender, PropertyChangedEventArgs e)
        {
            // The core replaces its content objects. Update every compiled
            // binding after one change, including nested card and failure
            // paths.
            if (this.Bindings != null)
            {
                this.Bindings.Update();
            }
        }

        private void MainPage_Loaded(object sender, RoutedEventArgs e)
        {
            if (!initialized)
            {
                initialized = true;
                LoadSavedSettings();
                ApplyTheme(ViewModel.Theme);
                RefreshControls();
                SelectSection("dashboard");
                try
                {
                    ApplicationView.GetForCurrentView().Title = DemoText.WindowTitle;
                }
                catch
                {
                    // The manifest display name remains the window title.
                }
            }
            else
            {
                RefreshControls();
                if (ViewModel.HasPendingAction)
                {
                    StartPendingTimer();
                }
            }
        }

        private void MainPage_Unloaded(object sender, RoutedEventArgs e)
        {
            StopPendingTimer();
        }

        private void LoadSavedSettings()
        {
            string theme = settingsStore.Read("demo.theme");
            DemoTheme parsedTheme;
            if (theme != null && Enum.TryParse<DemoTheme>(theme, out parsedTheme))
            {
                ViewModel.SetTheme(parsedTheme);
            }

            string ping = settingsStore.Read("demo.ping");
            if (ping == "on")
            {
                ViewModel.SetPing(true);
            }
            else if (ping == "off")
            {
                ViewModel.SetPing(false);
            }

            string details = settingsStore.Read("demo.details");
            if (details == "on")
            {
                ViewModel.SetActivityDetails(true);
            }
            else if (details == "off")
            {
                ViewModel.SetActivityDetails(false);
            }
        }

        // MARK: - Section navigation

        private void ShowSection(string tag)
        {
            if (tag == null)
            {
                tag = "dashboard";
            }
            DashboardScroll.Visibility = tag == "dashboard" ? Visibility.Visible : Visibility.Collapsed;
            ActivityScroll.Visibility = tag == "activity" ? Visibility.Visible : Visibility.Collapsed;
            SettingsScroll.Visibility = tag == "settings" ? Visibility.Visible : Visibility.Collapsed;
        }

        private void FocusSection(string tag)
        {
            if (tag == "dashboard")
            {
                DashboardScroll.Focus(FocusState.Programmatic);
            }
            else if (tag == "activity")
            {
                ActivityScroll.Focus(FocusState.Programmatic);
            }
            else
            {
                SettingsScroll.Focus(FocusState.Programmatic);
            }
        }

        private void SelectSection(string tag)
        {
            if (tag == null)
            {
                tag = "dashboard";
            }
            syncingNavigation = true;
            if (tag == "settings")
            {
                if (Nav.SettingsItem != null)
                {
                    Nav.SelectedItem = Nav.SettingsItem;
                }
            }
            else if (tag == "activity")
            {
                Nav.SelectedItem = ActivityNavItem;
            }
            else
            {
                Nav.SelectedItem = DashboardNavItem;
            }
            syncingNavigation = false;
            ShowSection(tag);
            FocusSection(tag);
        }

        private void Nav_SelectionChanged(muxc.NavigationView sender, muxc.NavigationViewSelectionChangedEventArgs args)
        {
            if (syncingNavigation)
            {
                return;
            }
            if (args.IsSettingsSelected)
            {
                ShowSection("settings");
                return;
            }
            muxc.NavigationViewItem item = args.SelectedItem as muxc.NavigationViewItem;
            if (item != null)
            {
                ShowSection(item.Tag as string);
            }
        }

        private void Nav_ItemInvoked(muxc.NavigationView sender, muxc.NavigationViewItemInvokedEventArgs args)
        {
            if (args.IsSettingsInvoked)
            {
                ShowSection("settings");
                return;
            }
            muxc.NavigationViewItem item = args.InvokedItemContainer as muxc.NavigationViewItem;
            if (item != null)
            {
                ShowSection(item.Tag as string);
            }
        }

        // MARK: - Dashboard actions

        private void PrimaryAction_Click(object sender, RoutedEventArgs e)
        {
            ViewModel.PerformPrimaryAction();
            AfterAction();
        }

        private void SecondaryAction_Click(object sender, RoutedEventArgs e)
        {
            ViewModel.PerformSecondaryAction();
            AfterAction();
        }

        private void AttentionAction_Click(object sender, RoutedEventArgs e)
        {
            FrameworkElement element = sender as FrameworkElement;
            AttentionRow row = element == null ? null : element.DataContext as AttentionRow;
            if (row == null)
            {
                return;
            }
            ViewModel.PerformAttentionAction(row.Action);
            AfterAction();
        }

        private void ApprovePairing_Click(object sender, RoutedEventArgs e)
        {
            ViewModel.ApprovePairing();
            AfterAction();
        }

        private void CancelPairing_Click(object sender, RoutedEventArgs e)
        {
            ViewModel.CancelPairing();
            AfterAction();
        }

        private void SimulatePairingFailure_Click(object sender, RoutedEventArgs e)
        {
            ViewModel.SimulatePairingFailure();
            AfterAction();
        }

        private void CopyCode_Click(object sender, RoutedEventArgs e)
        {
            bool copied = ClipboardService.TrySetText(ViewModel.Dashboard.PairingCode);
            codeCopied = copied;
            CodeCopiedText.Text = copied ? DemoText.CodeCopied : DemoText.CodeCopyFailed;
            CodeCopiedText.Visibility = Visibility.Visible;
        }

        // MARK: - Activity actions

        private void RefreshActivity_Click(object sender, RoutedEventArgs e)
        {
            ViewModel.RefreshActivity();
            AfterAction();
        }

        private void CheckNowFromActivity_Click(object sender, RoutedEventArgs e)
        {
            CheckNow();
        }

        private void CheckNowFromDashboard_Click(object sender, RoutedEventArgs e)
        {
            CheckNow();
        }

        private void ActivityDetails_Changed(object sender, RoutedEventArgs e)
        {
            if (syncingControls)
            {
                return;
            }
            ViewModel.SetActivityDetails(ActivityDetailsToggle.IsChecked == true);
            settingsStore.Write("demo.details", ViewModel.ShowActivityDetails ? "on" : "off");
            RefreshControls();
        }

        // MARK: - Settings actions

        private void PingSwitch_Toggled(object sender, RoutedEventArgs e)
        {
            if (syncingControls)
            {
                return;
            }
            ViewModel.SetPing(PingSwitch.IsOn);
            settingsStore.Write("demo.ping", PingSwitch.IsOn ? "on" : "off");
            RefreshControls();
        }

        private void ThemeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (syncingControls)
            {
                return;
            }
            DemoTheme theme;
            if (ThemeCombo.SelectedIndex == 1)
            {
                theme = DemoTheme.Light;
            }
            else if (ThemeCombo.SelectedIndex == 2)
            {
                theme = DemoTheme.Dark;
            }
            else
            {
                theme = DemoTheme.System;
            }
            ApplyThemeAndSave(theme);
        }

        private void PairFromSettings_Click(object sender, RoutedEventArgs e)
        {
            ViewModel.BeginPairing();
            AfterAction();
            SelectSection("dashboard");
        }

        private void CancelPairingSettings_Click(object sender, RoutedEventArgs e)
        {
            ViewModel.CancelPairing();
            AfterAction();
        }

        private void ForgetButton_Click(object sender, RoutedEventArgs e)
        {
            if (ViewModel.Settings.ForgetBlocked)
            {
                ViewModel.TurnOffAndForget();
            }
            else
            {
                ViewModel.Forget();
            }
            AfterAction();
        }

        // MARK: - Failure actions

        private void RefreshFailures_Click(object sender, RoutedEventArgs e)
        {
            ViewModel.LoadFailures();
            AfterAction();
        }

        private void ClearFailures_Click(object sender, RoutedEventArgs e)
        {
            ViewModel.ClearFailures();
            RefreshControls();
        }

        private void CopyFailureReport_Click(object sender, RoutedEventArgs e)
        {
            bool copied = ClipboardService.TrySetText(ViewModel.FailureReport);
            ReportCopiedText.Text = copied ? DemoText.ReportCopied : DemoText.CopyFailed;
            ReportCopiedText.Visibility = Visibility.Visible;
        }

        private void CopyDiagnostics_Click(object sender, RoutedEventArgs e)
        {
            bool copied = ClipboardService.TrySetText(ViewModel.DiagnosticsReport);
            DiagnosticsCopiedText.Text = copied ? DemoText.DiagnosticsCopied : DemoText.CopyFailed;
            DiagnosticsCopiedText.Visibility = Visibility.Visible;
        }

        // MARK: - Scenario picker

        private void ScenarioCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (syncingControls)
            {
                return;
            }
            int index = ScenarioCombo.SelectedIndex;
            if (index < 0 || index >= ViewModel.Scenarios.Count)
            {
                return;
            }
            StopPendingTimer();
            ViewModel.ApplyScenario(ViewModel.Scenarios[index].Scenario);
            AfterAction();
        }

        private async void ResetDemoButton_Click(object sender, RoutedEventArgs e)
        {
            await ResetDemoAsync();
        }

        private async void ResetDemoMenu_Click(object sender, RoutedEventArgs e)
        {
            await ResetDemoAsync();
        }

        private async Task ResetDemoAsync()
        {
            ContentDialogResult result = await ShowDialogAsync(DemoText.ResetDemoTitle, DemoText.ResetDemoMessage, DemoText.Reset);
            if (result == ContentDialogResult.Primary)
            {
                StopPendingTimer();
                ViewModel.ApplyScenario(DemoScenario.Unpaired);
                AfterAction();
                SelectSection("dashboard");
            }
        }

        // MARK: - Menus

        private void DashboardMenu_Click(object sender, RoutedEventArgs e)
        {
            SelectSection("dashboard");
        }

        private void ActivityMenu_Click(object sender, RoutedEventArgs e)
        {
            SelectSection("activity");
        }

        private void SettingsMenu_Click(object sender, RoutedEventArgs e)
        {
            SelectSection("settings");
        }

        private void RefreshStatusMenu_Click(object sender, RoutedEventArgs e)
        {
            CheckNow();
        }

        private void CheckSourceNowMenu_Click(object sender, RoutedEventArgs e)
        {
            CheckNow();
        }

        private void ThemeSystemMenu_Click(object sender, RoutedEventArgs e)
        {
            ApplyThemeAndSave(DemoTheme.System);
        }

        private void ThemeLightMenu_Click(object sender, RoutedEventArgs e)
        {
            ApplyThemeAndSave(DemoTheme.Light);
        }

        private void ThemeDarkMenu_Click(object sender, RoutedEventArgs e)
        {
            ApplyThemeAndSave(DemoTheme.Dark);
        }

        private void ScenarioMenu_Click(object sender, RoutedEventArgs e)
        {
            MenuFlyoutItem item = sender as MenuFlyoutItem;
            if (item == null)
            {
                return;
            }
            string tag = item.Tag as string;
            DemoScenario scenario;
            if (tag != null && Enum.TryParse<DemoScenario>(tag, out scenario))
            {
                StopPendingTimer();
                ViewModel.ApplyScenario(scenario);
                AfterAction();
                SelectSection("dashboard");
            }
        }

        private async void DemoLimitations_Click(object sender, RoutedEventArgs e)
        {
            await ShowDialogAsync(DemoText.LimitationsTitle, DemoText.LimitationsText, null);
        }

        private async void About_Click(object sender, RoutedEventArgs e)
        {
            await ShowDialogAsync(DemoText.AboutTitle, DemoText.AboutText + " Version " + DemoText.PrototypeVersion + ".", null);
        }

        // MARK: - Keyboard accelerators

        private void DashboardAccelerator_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
        {
            args.Handled = true;
            SelectSection("dashboard");
        }

        private void ActivityAccelerator_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
        {
            args.Handled = true;
            SelectSection("activity");
        }

        private void SettingsAccelerator_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
        {
            args.Handled = true;
            SelectSection("settings");
        }

        private void RefreshAccelerator_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
        {
            args.Handled = true;
            CheckNow();
        }

        private void CheckNowAccelerator_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
        {
            args.Handled = true;
            CheckNow();
        }

        // MARK: - Local helpers

        private void CheckNow()
        {
            if (!ViewModel.Dashboard.CanCheckNow)
            {
                return;
            }
            ViewModel.CheckNow();
            AfterAction();
        }

        private void ApplyThemeAndSave(DemoTheme theme)
        {
            ApplyTheme(theme);
            ViewModel.SetTheme(theme);
            settingsStore.Write("demo.theme", theme.ToString());
            RefreshControls();
        }

        private void ApplyTheme(DemoTheme theme)
        {
            if (theme == DemoTheme.Light)
            {
                RequestedTheme = ElementTheme.Light;
            }
            else if (theme == DemoTheme.Dark)
            {
                RequestedTheme = ElementTheme.Dark;
            }
            else
            {
                RequestedTheme = ElementTheme.Default;
            }
            AppMenu.RequestedTheme = RequestedTheme;
        }

        private void RefreshControls()
        {
            if (PingSwitch == null || ThemeCombo == null || ActivityDetailsToggle == null
                || ScenarioCombo == null || ScenarioDescriptionText == null)
            {
                return;
            }

            syncingControls = true;
            PingSwitch.IsOn = ViewModel.PingEnabled;
            ActivityDetailsToggle.IsChecked = ViewModel.ShowActivityDetails;
            ThemeCombo.SelectedIndex = (int)ViewModel.Theme;
            ScenarioCombo.SelectedIndex = ViewModel.ScenarioIndex;
            RefreshStatusMenu.IsEnabled = ViewModel.Dashboard.CanCheckNow;
            CheckSourceNowMenu.IsEnabled = ViewModel.Dashboard.CanCheckNow;
            int scenarioIndex = ViewModel.ScenarioIndex;
            if (scenarioIndex >= 0 && scenarioIndex < ViewModel.Scenarios.Count)
            {
                ScenarioDescriptionText.Text = ViewModel.Scenarios[scenarioIndex].Description;
            }
            UpdateThemeMenuIcons();
            if (!ViewModel.Dashboard.PairingCodeReady)
            {
                codeCopied = false;
            }
            CodeCopiedText.Visibility = codeCopied ? Visibility.Visible : Visibility.Collapsed;
            syncingControls = false;
        }

        private void UpdateThemeMenuIcons()
        {
            ThemeSystemMenu.Icon = ViewModel.Theme == DemoTheme.System ? CheckIcon() : null;
            ThemeLightMenu.Icon = ViewModel.Theme == DemoTheme.Light ? CheckIcon() : null;
            ThemeDarkMenu.Icon = ViewModel.Theme == DemoTheme.Dark ? CheckIcon() : null;
        }

        private static FontIcon CheckIcon()
        {
            return new FontIcon { Glyph = "\uE73E", FontSize = 12 };
        }

        private void AfterAction()
        {
            RefreshControls();
            if (ViewModel.HasPendingAction)
            {
                StartPendingTimer();
            }
            else
            {
                StopPendingTimer();
            }
        }

        private void StartPendingTimer()
        {
            if (pendingTimer == null)
            {
                pendingTimer = new DispatcherTimer();
                pendingTimer.Interval = TimeSpan.FromMilliseconds(900);
                pendingTimer.Tick += PendingTimer_Tick;
            }
            if (pendingTimer.IsEnabled)
            {
                return;
            }
            pendingTimer.Start();
        }

        private void StopPendingTimer()
        {
            if (pendingTimer != null)
            {
                pendingTimer.Stop();
            }
        }

        private void PendingTimer_Tick(object sender, object e)
        {
            StopPendingTimer();
            ViewModel.CompletePending();
            AfterAction();
        }

        private async Task<ContentDialogResult> ShowDialogAsync(string title, string message, string primaryButtonText)
        {
            if (dialogOpen)
            {
                return ContentDialogResult.None;
            }
            dialogOpen = true;
            try
            {
                ContentDialog dialog = new ContentDialog();
                dialog.Title = title;
                dialog.RequestedTheme = this.RequestedTheme;
                dialog.CloseButtonText = DemoText.Close;
                dialog.DefaultButton = ContentDialogButton.Close;
                if (!string.IsNullOrEmpty(primaryButtonText))
                {
                    dialog.PrimaryButtonText = primaryButtonText;
                }
                TextBlock body = new TextBlock();
                body.Text = message;
                body.TextWrapping = TextWrapping.Wrap;
                dialog.Content = body;
                return await dialog.ShowAsync();
            }
            catch
            {
                return ContentDialogResult.None;
            }
            finally
            {
                dialogOpen = false;
            }
        }
    }
}
