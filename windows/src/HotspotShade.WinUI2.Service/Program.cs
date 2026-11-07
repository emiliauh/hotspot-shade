using System;
using HotspotShade.WinUI2.Core.Engine.Service;
using HotspotShade.WinUI2.ServiceHost;

namespace HotspotShade.WinUI2.Service
{
    // The executable entry point. It only connects this process to the SCM.
    // It does not install a service, start a service, or change the service
    // configuration. A console launch is answered with the documented
    // ERROR_FAILED_SERVICE_CONTROLLER_CONNECT result.
    internal static class Program
    {
        // The SCM keeps the function pointer after the dispatch table returns.
        // The static field keeps the delegate alive for the process lifetime.
        private static readonly WindowsServiceControlNativeMethods.ServiceMainFunction
            ServiceMainDelegate = ServiceMain;

        // The install-time options are the service image command line from the
        // service record. The SCM service main vector carries the service name
        // and any start parameters instead, so it is not the configuration
        // source.
        private static string[] processArguments = new string[0];

        private static int Main(string[] args)
        {
            processArguments = CopyArguments(args);
            if (!EngineServicePlatform.IsWindows)
            {
                Console.Error.WriteLine(
                    "HotspotShadeEngineSvc: this build is a Windows x64 service host. It does not run on this platform.");
                return EngineServiceScmExitCodes.Platform;
            }

            try
            {
                int error;
                if (!WindowsServiceScmDispatcher.TryRun(
                    ServiceMainDelegate,
                    EngineServiceBoundary.ServiceName,
                    out error))
                {
                    if (error == WindowsServiceControlNativeMethods.ErrorFailedServiceControlConnect)
                    {
                        Console.Error.WriteLine(
                            "HotspotShadeEngineSvc: the Windows Service Control Manager did not start this process. This build does not install a service.");
                    }
                    return EngineServiceScmExitCodes.ForDispatcherError(error);
                }
                return EngineServiceScmExitCodes.Success;
            }
            catch (Exception)
            {
                return EngineServiceScmExitCodes.Internal;
            }
            finally
            {
                GC.KeepAlive(ServiceMainDelegate);
            }
        }

        // An exception must not escape the SCM service main thread. The
        // service body catches its own path and sends the final fixed status.
        private static void ServiceMain(uint argumentCount, IntPtr argumentValues)
        {
            try
            {
                EngineServiceScmEntryPoint.Run(CopyArguments(processArguments));
            }
            catch (Exception)
            {
                // The SCM sees the process exit. No secret or path is written.
            }
        }

        private static string[] CopyArguments(string[] values)
        {
            if (values == null || values.Length == 0)
            {
                return new string[0];
            }
            string[] copy = new string[values.Length];
            Array.Copy(values, copy, values.Length);
            return copy;
        }
    }
}
