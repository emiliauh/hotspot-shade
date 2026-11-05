using System;

namespace HotspotShade.WinUI2.Core.Tests
{
    internal static class Program
    {
        private static int Main()
        {
            Console.WriteLine("HotspotShade WinUI 2 prototype checks");
            Console.WriteLine("All checks are hermetic. No network, route, or tunnel is created.");
            Console.WriteLine("");
            TestRunner runner = new TestRunner();
            CoreTests.Run(runner);
            ContractTests.Run(runner);
            return runner.Finish();
        }
    }
}
