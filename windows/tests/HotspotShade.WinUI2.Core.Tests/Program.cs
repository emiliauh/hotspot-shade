using System;

namespace HotspotShade.WinUI2.Core.Tests
{
    internal static class Program
    {
        private static int Main()
        {
            Console.WriteLine("HotspotShade Windows checks");
            Console.WriteLine("All checks are hermetic. No network, route, or tunnel is created.");
            Console.WriteLine("");
            TestRunner runner = new TestRunner();
            AppSessionTests.Run(runner);
            InstallSecurityTests.Run(runner);
            EngineTests.Run(runner);
            EngineBoundaryTests.Run(runner);
            BrokerBoundaryTests.Run(runner);
            ServiceBoundaryTests.Run(runner);
            EngineServiceAppTests.Run(runner);
            ReleaseProbeTests.Run(runner);
            PrivacyCapabilityTests.Run(runner);
            TestLauncherTests.Run(runner);
            ContractTests.Run(runner);
            return runner.Finish();
        }
    }
}
