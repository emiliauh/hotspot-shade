using System;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Services;
using Windows.ApplicationModel;
using Windows.ApplicationModel.Activation;
using Windows.ApplicationModel.AppService;
using Windows.Foundation;
using Windows.UI.ViewManagement;
using Windows.UI.Xaml;

namespace HotspotShade.WinUI2
{
    // The UWP window. It runs in an AppContainer as the signed-in user and
    // never asks for administrator approval at launch. It starts the packaged
    // full-trust broker, which starts the standard-user engine. Only Turn on
    // makes the broker show a UAC prompt.
    public sealed partial class App : Application
    {
        public App()
        {
            InitializeComponent();
            Resuming += OnResuming;
        }

        protected override void OnLaunched(LaunchActivatedEventArgs e)
        {
            // UWP SetPreferredMinSize caps the preferred minimum at 500 by
            // 500, so the macOS minimum of 780 by 560 cannot be enforced. The
            // page layout is responsive.
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

        // The broker opens the in-process app service. BrokerConnection
        // accepts it only from this package.
        protected override void OnBackgroundActivated(BackgroundActivatedEventArgs args)
        {
            base.OnBackgroundActivated(args);
            AppServiceTriggerDetails details = args.TaskInstance.TriggerDetails as AppServiceTriggerDetails;
            if (details != null)
            {
                BrokerConnection.Instance.Attach(args.TaskInstance, details);
            }
        }

        // Windows may close the app-service connection while the window is
        // suspended. The broker keeps the engines while this process lives;
        // on resume the window asks it to connect again.
        private void OnResuming(object sender, object e)
        {
            Task ignored = BrokerConnection.Instance.EnsureStartedAsync();
        }
    }
}
