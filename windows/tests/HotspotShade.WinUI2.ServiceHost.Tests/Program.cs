using System;

namespace HotspotShade.WinUI2.ServiceHost.Tests
{
    internal static class Program
    {
        private static int Main()
        {
            Console.WriteLine("HotspotShade Windows service host foundation checks");
            Console.WriteLine("All checks are hermetic. No pipe, service, process, route, or endpoint is created.");
            Console.WriteLine("");
            ServiceHostCheckRunner runner = new ServiceHostCheckRunner();
            ServiceHostFrameReaderChecks.Run(runner);
            ServiceHostAuthenticationChecks.Run(runner);
            ServiceHostServerProofChecks.Run(runner);
            ServiceHostOverlappedLifetimeRepairChecks.Run(runner);
            ServiceHostOverlappedNativeChecks.Run(runner);
            ServiceHostSessionChecks.Run(runner);
            ServiceHostStateChecks.Run(runner);
            ServiceHostLifecycleChecks.Run(runner);
            ServiceHostIdlePolicyChecks.Run(runner);
            ServiceHostReadLivenessChecks.Run(runner);
            ServiceHostClientBudgetChecks.Run(runner);
            ServiceHostHostChecks.Run(runner);
            ServiceHostControlChecks.Run(runner);
            ServiceHostGuardChecks.Run(runner);
            WindowsServiceScmChecks.Run(runner);
            WindowsServiceConfigurationChecks.Run(runner);
            return runner.Finish();
        }
    }
}
