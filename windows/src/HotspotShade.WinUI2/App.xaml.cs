using Windows.ApplicationModel;
using Windows.ApplicationModel.Activation;
using Windows.Foundation;
using Windows.UI.ViewManagement;
using Windows.UI.Xaml;

namespace HotspotShade.WinUI2
{
    // The app is a UI-only WinUI 2 prototype. It starts no engine, no service,
    // no network listener, and no tunnel. All displayed data is simulated.
    public sealed partial class App : Application
    {
        public App()
        {
            InitializeComponent();
            Suspending += OnSuspending;
        }

        protected override void OnLaunched(LaunchActivatedEventArgs e)
        {
            // Set a preferred launch size. UWP SetPreferredMinSize caps the
            // preferred minimum at 500 by 500, so the macOS minimum of 780 by
            // 560 cannot be enforced. The page layout is responsive.
            ApplicationView.PreferredLaunchViewSize = new Size(1000, 720);
            ApplicationView.PreferredLaunchWindowingMode = ApplicationViewWindowingMode.PreferredLaunchViewSize;
            try
            {
                ApplicationView.GetForCurrentView().SetPreferredMinSize(new Size(500, 500));
            }
            catch
            {
                // A host that does not support the preferred minimum keeps the
                // system minimum.
            }

            if (Window.Current.Content == null)
            {
                Window.Current.Content = new MainPage();
            }
            Window.Current.Activate();
        }

        private void OnSuspending(object sender, SuspendingEventArgs e)
        {
            // The demo has no background work. UWP suspends the UI process and
            // may terminate it. The page timer stops when the page unloads.
        }
    }
}
