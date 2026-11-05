using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace HotspotShade.WinUI2.Core
{
    // The fixed demo states. The Settings page and the Demo menu use this one
    // list. A scenario changes only local demo data. No engine is contacted.
    public static class DemoScenarios
    {
        public static readonly IReadOnlyList<DemoScenarioInfo> All =
            new ReadOnlyCollection<DemoScenarioInfo>(new DemoScenarioInfo[]
            {
                new DemoScenarioInfo(
                    DemoScenario.Unpaired,
                    "Unpaired",
                    "The target device has no saved pairing."),
                new DemoScenarioInfo(
                    DemoScenario.PairingCode,
                    "Pairing code",
                    "The simulated source device shows a six-digit code."),
                new DemoScenarioInfo(
                    DemoScenario.PairingFailed,
                    "Pairing failed",
                    "The simulated source device rejected the code."),
                new DemoScenarioInfo(
                    DemoScenario.NotTrusted,
                    "Not trusted",
                    "The source device does not know this target device."),
                new DemoScenarioInfo(
                    DemoScenario.Waiting,
                    "Waiting for source device",
                    "The pairing is saved, but the source device app is closed."),
                new DemoScenarioInfo(
                    DemoScenario.Ready,
                    "Ready",
                    "The source device is ready. The tunnel is off."),
                new DemoScenarioInfo(
                    DemoScenario.On,
                    "On",
                    "The simulated tunnel runs with ping and three connections."),
                new DemoScenarioInfo(
                    DemoScenario.OnSourceStopped,
                    "On, source device stopped",
                    "The tunnel runs, but the source device stopped answering."),
                new DemoScenarioInfo(
                    DemoScenario.OnNotTrusted,
                    "On, not trusted",
                    "The tunnel runs, but the source device forgot this target device."),
                new DemoScenarioInfo(
                    DemoScenario.Stale,
                    "On, stale status",
                    "The last status is older than three seconds."),
                new DemoScenarioInfo(
                    DemoScenario.Unavailable,
                    "Status unavailable",
                    "The last status is older than ten seconds. The app claims no state."),
                new DemoScenarioInfo(
                    DemoScenario.Error,
                    "Error",
                    "A simulated start or probe error needs attention."),
                new DemoScenarioInfo(
                    DemoScenario.ActivityEmpty,
                    "Activity empty",
                    "The simulated activity list has no entries."),
                new DemoScenarioInfo(
                    DemoScenario.ForgetConfirmed,
                    "After forget",
                    "The target device forgot the source device.")
            });
    }
}
