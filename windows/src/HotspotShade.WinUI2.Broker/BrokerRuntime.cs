using System;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.App;

namespace HotspotShade.WinUI2.Broker
{
    // One broker lifetime:
    // 1. Require package identity and one instance per session. A second
    //    copy asks the first one to connect again and exits.
    // 2. Start the standard-user engine with the bearer secret pipe, the
    //    parent-liveness pipe, and the pairing handoff pipe.
    // 3. Connect to the app service that the UWP window hosts.
    // 4. Serve fixed operations. The window names its process in "hello".
    //    The broker lives as long as that process: a suspended window that
    //    closes the connection does not stop a tunnel, and a closed window
    //    does.
    // 5. Stop the elevated tunnel, then close every parent-liveness pipe and
    //    wait for the engines to exit.
    internal static class BrokerRuntime
    {
        // A window that never says hello is gone. The window gives the broker
        // 15 seconds to attach, so the broker uses the same budget.
        private static readonly TimeSpan HelloBudget = TimeSpan.FromSeconds(15);

        public static int Run()
        {
            string root;
            if (!BrokerPackage.TryGetRoot(out root))
            {
                BrokerTrace.Event(BrokerTrace.NoPackage);
                return 3;
            }

            SingleInstanceLease lease = SingleInstanceLease.TryAcquire();
            if (lease == null)
            {
                // The app starts the broker again after a resume. The
                // running broker owns the engines; ask it to reconnect.
                ReconnectSignal.Raise();
                BrokerTrace.Event(BrokerTrace.AlreadyRunning);
                BrokerLog.Write(BrokerLogStages.Lease, BrokerLogCodes.LeaseHeld);
                return 0;
            }
            BrokerLog.Write(BrokerLogStages.Lease, BrokerLogCodes.LeaseOwned);
            using (lease)
            {
                using (ReconnectSignal signal = ReconnectSignal.Create())
                {
                    return RunOwned(root, signal);
                }
            }
        }

        private static int RunOwned(string root, ReconnectSignal signal)
        {
            BrokerService service = new BrokerService(root);
            AppProcessWatch app = new AppProcessWatch();
            Task engineStart = Task.Run(delegate { service.StartUserEngine(); });
            try
            {
                while (true)
                {
                    AppServiceBrokerTransport transport = new AppServiceBrokerTransport(service, app.Set);
                    bool connected = transport.ConnectAsync(TimeSpan.FromSeconds(10)).GetAwaiter().GetResult();
                    if (!connected)
                    {
                        BrokerLog.Write(BrokerLogStages.Transport, BrokerLogCodes.ConnectFailed);
                        if (!app.Known)
                        {
                            BrokerTrace.Event(BrokerTrace.ServiceUnavailable);
                            return 4;
                        }
                    }
                    else
                    {
                        DateTime helloDeadline = DateTime.UtcNow + HelloBudget;
                        bool helloSeen = false;
                        while (!transport.Closed.IsCompleted)
                        {
                            if (!helloSeen && app.Known)
                            {
                                helloSeen = true;
                                BrokerLog.Write(BrokerLogStages.Hello, BrokerLogCodes.HelloReceived);
                            }
                            if (app.Exited)
                            {
                                transport.Close();
                                BrokerLog.Write(BrokerLogStages.Transport, BrokerLogCodes.WindowExited);
                                return 0;
                            }
                            if (!app.Known && DateTime.UtcNow > helloDeadline)
                            {
                                transport.Close();
                                BrokerTrace.Event(BrokerTrace.ServiceUnavailable);
                                BrokerLog.Write(BrokerLogStages.Hello, BrokerLogCodes.HelloTimeout);
                                return 4;
                            }
                            transport.Closed.Wait(250);
                        }
                        BrokerLog.Write(
                            BrokerLogStages.Transport,
                            app.Known ? BrokerLogCodes.TransportClosed : BrokerLogCodes.ClosedBeforeHello);
                    }
                    // The connection closed. Wait for the window to come back
                    // or for its process to end.
                    if (!app.Known)
                    {
                        return 0;
                    }
                    while (true)
                    {
                        if (app.Exited)
                        {
                            return 0;
                        }
                        if (signal.Wait(500))
                        {
                            break;
                        }
                    }
                }
            }
            catch (Exception error)
            {
                BrokerTrace.Event(BrokerTrace.Fatal);
                BrokerLog.Write(
                    BrokerLogStages.Fatal,
                    BrokerLogCodes.Unhandled,
                    BrokerLogFormat.ExceptionName(error),
                    null,
                    null,
                    error.HResult);
                return 1;
            }
            finally
            {
                BrokerTrace.Event(BrokerTrace.Stopping);
                BrokerLog.Write(BrokerLogStages.Shutdown, BrokerLogCodes.ShutdownBegin);
                try
                {
                    engineStart.Wait(TimeSpan.FromSeconds(20));
                }
                catch (Exception)
                {
                }
                try
                {
                    service.Shutdown();
                }
                catch (Exception)
                {
                }
                app.Dispose();
                BrokerTrace.Event(BrokerTrace.Stopped);
                BrokerLog.Write(BrokerLogStages.Shutdown, BrokerLogCodes.ShutdownEnd);
            }
        }
    }

    // The window process. The first hello fixes it for the broker lifetime.
    internal sealed class AppProcessWatch : IDisposable
    {
        private readonly object gate = new object();
        private IntPtr process;

        public bool Known
        {
            get
            {
                lock (gate)
                {
                    return process != IntPtr.Zero;
                }
            }
        }

        public bool Exited
        {
            get
            {
                lock (gate)
                {
                    return process != IntPtr.Zero
                        && BrokerNative.WaitForSingleObject(process, 0) == BrokerNative.WaitObject0;
                }
            }
        }

        public void Set(int id)
        {
            lock (gate)
            {
                if (process != IntPtr.Zero)
                {
                    // A reconnect from the same window keeps the first value.
                    return;
                }
                IntPtr opened = BrokerNative.OpenProcess(BrokerNative.Synchronize, false, id);
                if (opened != IntPtr.Zero)
                {
                    process = opened;
                }
            }
        }

        public void Dispose()
        {
            lock (gate)
            {
                if (process != IntPtr.Zero)
                {
                    BrokerNative.CloseHandle(process);
                    process = IntPtr.Zero;
                }
            }
        }
    }

    // A session-local event that a second broker copy raises so the first
    // copy opens a new app-service connection.
    internal sealed class ReconnectSignal : IDisposable
    {
        private const string Name = @"Local\HotspotShade.WinUI2.Broker.Reconnect";

        private readonly EventWaitHandle handle;

        private ReconnectSignal(EventWaitHandle handle)
        {
            this.handle = handle;
        }

        public static ReconnectSignal Create()
        {
            return new ReconnectSignal(new EventWaitHandle(false, EventResetMode.AutoReset, Name));
        }

        public static void Raise()
        {
            EventWaitHandle existing;
            if (EventWaitHandle.TryOpenExisting(Name, out existing))
            {
                using (existing)
                {
                    existing.Set();
                }
            }
        }

        public bool Wait(int milliseconds)
        {
            return handle.WaitOne(milliseconds);
        }

        public void Dispose()
        {
            handle.Dispose();
        }
    }

    internal static class Program
    {
        [System.MTAThread]
        private static int Main(string[] args)
        {
            int exitCode;
            BrokerLog.Write(
                BrokerLogStages.Main,
                BrokerLogCodes.Entry,
                null,
                args == null ? 0 : args.Length);
            if (args != null && args.Length != 0)
            {
                // The launcher passes no arguments. A path, port, or secret is
                // never accepted from the command line. Only the count is
                // logged, never the values.
                BrokerTrace.Event(BrokerTrace.BadArgument);
                BrokerLog.Write(BrokerLogStages.Main, BrokerLogCodes.BadArgs);
                exitCode = 2;
            }
            else
            {
                BrokerTrace.Event(BrokerTrace.Start);
                try
                {
                    exitCode = BrokerRuntime.Run();
                }
                catch (Exception error)
                {
                    BrokerTrace.Event(BrokerTrace.Fatal);
                    BrokerLog.Write(
                        BrokerLogStages.Fatal,
                        BrokerLogCodes.Unhandled,
                        BrokerLogFormat.ExceptionName(error),
                        null,
                        null,
                        error.HResult);
                    exitCode = 1;
                }
            }
            BrokerTrace.Event(BrokerTrace.Exit);
            BrokerLog.Write(
                BrokerLogStages.Exit,
                BrokerLogCodes.ExitCode,
                null,
                exitCode);
            return exitCode;
        }
    }
}
