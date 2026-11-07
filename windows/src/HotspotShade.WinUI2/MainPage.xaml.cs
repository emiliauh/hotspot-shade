using System;
using System.ComponentModel;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.App;
using HotspotShade.WinUI2.Services;
using HotspotShade.WinUI2.ViewModels;
using Windows.ApplicationModel;
using Windows.System.Profile;
using Windows.UI.Core;
using Windows.UI.ViewManagement;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Automation;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Input;
using muxc = Microsoft.UI.Xaml.Controls;

namespace HotspotShade.WinUI2
{
    // The one window: a native WinUI 2 menu bar and a NavigationView with
    // Dashboard, Activity, and Settings. Every value comes from the real
    // engine through the broker.
    public sealed partial class MainPage : Page
    {
        private const string ThemeKey = "app.theme";
        private const string PingKey = "app.ping";
        private const string DetailsKey = "app.details";

        private readonly LocalSettingsStore settingsStore;
        private bool syncingControls;
        private bool syncingNavigation;
        private bool dialogOpen;
        private bool initialized;
        private bool codeCopied;
        private string section = "dashboard";
        private ElementTheme theme = ElementTheme.Default;

        public MainPage()
        {
            settingsStore = new LocalSettingsStore();
            // CoreWindow.GetForCurrentThread() is null on a thread without a
            // window; fall back to the current window's dispatcher.
            CoreWindow coreWindow = CoreWindow.GetForCurrentThread();
            CoreDispatcher dispatcher = coreWindow != null
                ? coreWindow.Dispatcher
                : (Window.Current != null ? Window.Current.Dispatcher : null);
            ViewModel = new MainViewModel(BrokerConnection.Instance, dispatcher);
            Privacy = new PrivacyCapabilityViewModel();
            this.InitializeComponent();
            ViewModel.PropertyChanged += ViewModel_PropertyChanged;
            Loaded += MainPage_Loaded;
        }

        public MainViewModel ViewModel { get; private set; }

        // The read-only destination-privacy card. It is fixed capability
        // text, the same as the macOS Settings card. It offers no control.
        public PrivacyCapabilityViewModel Privacy { get; private set; }

        private void ViewModel_PropertyChanged(object sender, PropertyChangedEventArgs e)
        {
            // The OneWay x:Bind bindings refresh themselves from the "State"
            // notification. Calling Bindings.Update() here re-evaluated every
            // binding on every poll, so it is not called.
            RefreshControls();
        }

        private async void MainPage_Loaded(object sender, RoutedEventArgs e)
        {
            if (initialized)
            {
                return;
            }
            initialized = true;
            LoadSavedSettings();
            ApplyTheme(theme);
            SelectSection("dashboard");
            try
            {
                ApplicationView.GetForCurrentView().Title = "";
            }
            catch
            {
                // The manifest display name remains the window title.
            }
            AppVersionText.Text = AppVersion();
            WindowsVersionText.Text = WindowsVersion();
            BrokerConnection.Instance.OwnerWindow = WindowHandle.Current();
            Window.Current.VisibilityChanged += Window_VisibilityChanged;
            RefreshControls();
            await ViewModel.StartAsync();
            // One refresh of the compiled bindings after start, in case the
            // first answer arrived before the bindings were initialized.
            if (this.Bindings != null)
            {
                this.Bindings.Update();
            }
        }

        private void Window_VisibilityChanged(object sender, VisibilityChangedEventArgs e)
        {
            ViewModel.SetWindowVisible(e.Visible);
        }

        private void LoadSavedSettings()
        {
            string savedTheme = settingsStore.Read(ThemeKey);
            if (savedTheme == "light")
            {
                theme = ElementTheme.Light;
            }
            else if (savedTheme == "dark")
            {
                theme = ElementTheme.Dark;
            }
            else
            {
                theme = ElementTheme.Default;
            }

            // Let ping work is on by default, like the macOS app.
            ViewModel.SetPing(settingsStore.Read(PingKey) != "off");
            ViewModel.SetActivityDetails(settingsStore.Read(DetailsKey) == "on");
        }

        // MARK: - Section navigation

        private void ShowSection(string tag)
        {
            section = tag ?? "dashboard";
            DashboardScroll.Visibility = section == "dashboard" ? Visibility.Visible : Visibility.Collapsed;
            ActivityScroll.Visibility = section == "activity" ? Visibility.Visible : Visibility.Collapsed;
            SettingsScroll.Visibility = section == "settings" ? Visibility.Visible : Visibility.Collapsed;
            ViewModel.SetActivityVisible(section == "activity");
            if (section == "activity")
            {
                Task ignored = ViewModel.LoadActivityAsync(false);
            }
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

        private async void PrimaryAction_Click(object sender, RoutedEventArgs e)
        {
            await ViewModel.PerformAsync(ViewModel.State.PrimaryAction);
        }

        private async void SecondaryAction_Click(object sender, RoutedEventArgs e)
        {
            DashboardAction action = ViewModel.State.SecondaryAction;
            if (action == DashboardAction.Forget || action == DashboardAction.TurnOffAndForget)
            {
                if (!await ConfirmForgetAsync(action))
                {
                    return;
                }
            }
            await ViewModel.PerformAsync(action);
        }

        private async void AttentionAction_Click(object sender, RoutedEventArgs e)
        {
            FrameworkElement element = sender as FrameworkElement;
            AttentionRow row = element == null ? null : element.DataContext as AttentionRow;
            if (row == null || row.Action == DashboardAction.None)
            {
                return;
            }
            if (row.Action == DashboardAction.TurnOffAndForget && !await ConfirmForgetAsync(row.Action))
            {
                return;
            }
            await ViewModel.PerformAsync(row.Action);
        }

        private async void CancelPairing_Click(object sender, RoutedEventArgs e)
        {
            await ViewModel.CancelPairingAsync();
        }

        private void CopyCode_Click(object sender, RoutedEventArgs e)
        {
            bool copied = ClipboardService.TrySetText(ViewModel.State.PairingCode);
            codeCopied = copied;
            CodeCopiedText.Text = copied ? AppText.CodeCopied : AppText.CopyFailed;
            CodeCopiedText.Visibility = Visibility.Visible;
        }

        private async void CheckNowFromDashboard_Click(object sender, RoutedEventArgs e)
        {
            await CheckNowAsync();
        }

        // MARK: - Activity actions

        private async void RefreshActivity_Click(object sender, RoutedEventArgs e)
        {
            await ViewModel.LoadActivityAsync(false);
        }

        private async void CheckNowFromActivity_Click(object sender, RoutedEventArgs e)
        {
            await CheckNowAsync();
            await ViewModel.LoadActivityAsync(false);
        }

        private void ActivityDetails_Changed(object sender, RoutedEventArgs e)
        {
            if (syncingControls)
            {
                return;
            }
            bool on = ActivityDetailsToggle.IsChecked == true;
            ViewModel.SetActivityDetails(on);
            settingsStore.Write(DetailsKey, on ? "on" : "off");
        }

        // MARK: - Settings actions

        private void PingSwitch_Toggled(object sender, RoutedEventArgs e)
        {
            if (syncingControls)
            {
                return;
            }
            ViewModel.SetPing(PingSwitch.IsOn);
            settingsStore.Write(PingKey, PingSwitch.IsOn ? "on" : "off");
        }

        private void ThemeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (syncingControls)
            {
                return;
            }
            if (ThemeCombo.SelectedIndex == 1)
            {
                ApplyThemeAndSave(ElementTheme.Light);
            }
            else if (ThemeCombo.SelectedIndex == 2)
            {
                ApplyThemeAndSave(ElementTheme.Dark);
            }
            else
            {
                ApplyThemeAndSave(ElementTheme.Default);
            }
        }

        private async void PairFromSettings_Click(object sender, RoutedEventArgs e)
        {
            SelectSection("dashboard");
            await ViewModel.PairAsync();
        }

        private async void ForgetButton_Click(object sender, RoutedEventArgs e)
        {
            DashboardAction action = ViewModel.State.ForgetLabel == AppText.TurnOffAndForget
                ? DashboardAction.TurnOffAndForget
                : DashboardAction.Forget;
            if (!await ConfirmForgetAsync(action))
            {
                return;
            }
            await ViewModel.PerformAsync(action);
        }

        private async void SettingsPivot_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // The failure list loads when the person opens Advanced. It
            // never polls.
            if (SettingsPivot.SelectedIndex == 2 && !ViewModel.State.FailuresLoading)
            {
                await ViewModel.LoadFailuresAsync();
            }
        }

        // MARK: - Failure and diagnostics actions

        private async void RefreshFailures_Click(object sender, RoutedEventArgs e)
        {
            await ViewModel.LoadFailuresAsync();
        }

        private void CopyFailureReport_Click(object sender, RoutedEventArgs e)
        {
            bool copied = ClipboardService.TrySetText(ViewModel.FailureReport);
            ReportCopiedText.Text = copied ? AppText.ReportCopied : AppText.CopyFailed;
            ReportCopiedText.Visibility = Visibility.Visible;
        }

        private async void CopyDiagnostics_Click(object sender, RoutedEventArgs e)
        {
            string report = await ViewModel.DiagnosticsReportAsync(AppVersion(), WindowsVersion());
            bool copied = ClipboardService.TrySetText(report);
            DiagnosticsCopiedText.Text = copied ? AppText.DiagnosticsCopied : AppText.CopyFailed;
            DiagnosticsCopiedText.Visibility = Visibility.Visible;
        }

        // MARK: - Menus

        private async void TurnOnMenu_Click(object sender, RoutedEventArgs e)
        {
            await ViewModel.PerformAsync(DashboardAction.TurnOn);
        }

        private async void TurnOffMenu_Click(object sender, RoutedEventArgs e)
        {
            await ViewModel.PerformAsync(DashboardAction.TurnOff);
        }

        private async void PairMenu_Click(object sender, RoutedEventArgs e)
        {
            SelectSection("dashboard");
            await ViewModel.PairAsync();
        }

        private async void CancelPairingMenu_Click(object sender, RoutedEventArgs e)
        {
            await ViewModel.CancelPairingAsync();
        }

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

        private async void RefreshStatusMenu_Click(object sender, RoutedEventArgs e)
        {
            await ViewModel.RefreshAsync();
        }

        private async void CheckSourceNowMenu_Click(object sender, RoutedEventArgs e)
        {
            await CheckNowAsync();
        }

        private void ThemeSystemMenu_Click(object sender, RoutedEventArgs e)
        {
            ApplyThemeAndSave(ElementTheme.Default);
        }

        private void ThemeLightMenu_Click(object sender, RoutedEventArgs e)
        {
            ApplyThemeAndSave(ElementTheme.Light);
        }

        private void ThemeDarkMenu_Click(object sender, RoutedEventArgs e)
        {
            ApplyThemeAndSave(ElementTheme.Dark);
        }

        // Quitting closes the app process. The broker sees the process end,
        // stops the tunnel, and stops both engines.
        private async void QuitMenu_Click(object sender, RoutedEventArgs e)
        {
            if (ViewModel.State.CanTurnOff)
            {
                ContentDialogResult result = await ShowDialogAsync(
                    "Quit HotspotShade?",
                    "Quitting turns the tunnel off and removes its routes.",
                    "Quit");
                if (result != ContentDialogResult.Primary)
                {
                    return;
                }
            }
            Application.Current.Exit();
        }

        private async void Unavailable_Click(object sender, RoutedEventArgs e)
        {
            await ShowDialogAsync(
                AppText.UnavailableHeading,
                AppText.UnavailableNotifications + " " + AppText.UnavailableLaunchAtLogin + " "
                    + AppText.UnavailableTray + " " + AppText.UnavailableDirect
                    + " HotspotShade does not offer these features on Windows.",
                null);
        }

        private async void About_Click(object sender, RoutedEventArgs e)
        {
            await ShowDialogAsync(
                "About HotspotShade",
                "HotspotShade for Windows " + AppVersion() + ". It runs the HotspotShade engine on this target device and uses the source device proxy on your phone. Windows asks for administrator approval only when you turn on the tunnel.",
                null);
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

        private async void RefreshAccelerator_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
        {
            args.Handled = true;
            await ViewModel.RefreshAsync();
        }

        private async void CheckNowAccelerator_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
        {
            args.Handled = true;
            await CheckNowAsync();
        }

        // MARK: - Local helpers

        private async Task CheckNowAsync()
        {
            if (!ViewModel.State.CanCheckNow)
            {
                return;
            }
            await ViewModel.PerformAsync(DashboardAction.CheckNow);
        }

        private async Task<bool> ConfirmForgetAsync(DashboardAction action)
        {
            string title = action == DashboardAction.TurnOffAndForget ? "Turn off and forget?" : "Forget this source device?";
            string body = action == DashboardAction.TurnOffAndForget
                ? "HotspotShade turns the tunnel off, waits for a confirmed stop, then forgets the pairing. You must pair again to use this source device."
                : "HotspotShade forgets the pairing on this target device. You must pair again to use this source device.";
            ContentDialogResult result = await ShowDialogAsync(title, body, action == DashboardAction.TurnOffAndForget ? AppText.TurnOffAndForget : "Forget");
            return result == ContentDialogResult.Primary;
        }

        private void ApplyThemeAndSave(ElementTheme value)
        {
            ApplyTheme(value);
            settingsStore.Write(ThemeKey, value == ElementTheme.Light ? "light" : value == ElementTheme.Dark ? "dark" : "system");
            RefreshControls();
        }

        private void ApplyTheme(ElementTheme value)
        {
            theme = value;
            RequestedTheme = value;
            AppMenu.RequestedTheme = value;
        }

        private void RefreshControls()
        {
            if (PingSwitch == null || ThemeCombo == null || ActivityDetailsToggle == null)
            {
                return;
            }
            syncingControls = true;
            PingSwitch.IsOn = ViewModel.PingEnabled;
            ActivityDetailsToggle.IsChecked = ViewModel.ShowActivityDetails;
            ThemeCombo.SelectedIndex = theme == ElementTheme.Light ? 1 : theme == ElementTheme.Dark ? 2 : 0;
            HotspotShade.WinUI2.Core.App.WindowState state = ViewModel.State;
            TurnOnMenu.IsEnabled = state.CanTurnOn;
            TurnOffMenu.IsEnabled = state.CanTurnOff;
            PairMenu.IsEnabled = state.CanPair;
            CancelPairingMenu.IsEnabled = state.CanCancelPairing;
            RefreshStatusMenu.IsEnabled = true;
            CheckSourceNowMenu.IsEnabled = state.CanCheckNow;
            ToolTipService.SetToolTip(TurnOnMenu, state.CanTurnOn ? AppText.AdminAuthorization : state.TurnOnReason);
            ToolTipService.SetToolTip(TurnOffMenu, state.CanTurnOff ? null : state.TurnOffReason);
            // A Turn on button is never shown disabled without its reason.
            // The reason is a visible caption under the button, the tooltip,
            // and the help text a screen reader reads with the button.
            bool turnOnBlocked = state.PrimaryAction == DashboardAction.TurnOn && !state.CanTurnOn;
            PrimaryButton.IsEnabled = !turnOnBlocked;
            string blockedReason = turnOnBlocked
                ? (string.IsNullOrEmpty(state.TurnOnReason) ? AppText.WaitForAction : state.TurnOnReason)
                : "";
            TurnOnReasonText.Text = blockedReason;
            TurnOnReasonText.Visibility = turnOnBlocked ? Visibility.Visible : Visibility.Collapsed;
            ToolTipService.SetToolTip(PrimaryButton, turnOnBlocked ? blockedReason : null);
            AutomationProperties.SetHelpText(PrimaryButton, blockedReason);
            ThemeSystemMenu.Icon = theme == ElementTheme.Default ? CheckIcon() : null;
            ThemeLightMenu.Icon = theme == ElementTheme.Light ? CheckIcon() : null;
            ThemeDarkMenu.Icon = theme == ElementTheme.Dark ? CheckIcon() : null;
            if (!state.PairingCodeReady)
            {
                codeCopied = false;
            }
            CodeCopiedText.Visibility = codeCopied ? Visibility.Visible : Visibility.Collapsed;
            syncingControls = false;
        }

        private static FontIcon CheckIcon()
        {
            return new FontIcon { Glyph = "", FontSize = 12 };
        }

        private static string AppVersion()
        {
            try
            {
                PackageVersion version = Package.Current.Id.Version;
                return version.Major + "." + version.Minor + "." + version.Build + "." + version.Revision;
            }
            catch
            {
                return "unknown";
            }
        }

        private static string WindowsVersion()
        {
            try
            {
                ulong value = ulong.Parse(AnalyticsInfo.VersionInfo.DeviceFamilyVersion);
                ulong major = (value & 0xFFFF000000000000UL) >> 48;
                ulong minor = (value & 0x0000FFFF00000000UL) >> 32;
                ulong build = (value & 0x00000000FFFF0000UL) >> 16;
                ulong revision = value & 0x000000000000FFFFUL;
                return major + "." + minor + "." + build + "." + revision;
            }
            catch
            {
                return "unknown";
            }
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
                dialog.CloseButtonText = primaryButtonText == null ? AppText.Close : AppText.Cancel;
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
