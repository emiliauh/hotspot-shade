using System;
using System.Runtime.InteropServices;
using System.Threading;
using Windows.ApplicationModel;
using Windows.Storage;

namespace HotspotShade.WinUI2.Broker
{
    // Fixed debugger events. A value, path, port, or secret is never passed.
    // The broker writes no file and keeps no log on disk.
    internal static class BrokerTrace
    {
        public const string Start = "start";
        public const string Exit = "exit";
        public const string NoPackage = "no_package";
        public const string AlreadyRunning = "already_running";
        public const string PlanFailed = "plan_failed";
        public const string ServiceUnavailable = "service_unavailable";
        public const string Stopping = "stopping";
        public const string Stopped = "stopped";
        public const string BadArgument = "argument";
        public const string Fatal = "fatal";

        public static void Event(string code)
        {
            if (!IsKnown(code))
            {
                return;
            }
            OutputDebugStringW("HotspotShade broker: " + code + "\n");
        }

        private static bool IsKnown(string code)
        {
            switch (code)
            {
                case Start:
                case Exit:
                case NoPackage:
                case AlreadyRunning:
                case PlanFailed:
                case ServiceUnavailable:
                case Stopping:
                case Stopped:
                case BadArgument:
                case Fatal:
                    return true;
                default:
                    return false;
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern void OutputDebugStringW(string text);
    }

    // The broker only runs with package identity. An unpackaged copy cannot
    // open the app service and does not start the engine.
    internal static class BrokerPackage
    {
        public static bool TryGetRoot(out string root)
        {
            root = null;
            try
            {
                Package package = Package.Current;
                if (package == null)
                {
                    return false;
                }
                StorageFolder folder = package.InstalledLocation;
                if (folder == null || string.IsNullOrEmpty(folder.Path))
                {
                    return false;
                }
                root = folder.Path;
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }

    // One broker per signed-in session. A second copy exits without touching
    // the engine. An abandoned mutex means the earlier broker process is gone,
    // so its pipes are closed and the engine has already started its stop path.
    internal sealed class SingleInstanceLease : IDisposable
    {
        private const string Name = @"Local\HotspotShade.WinUI2.Broker";

        private readonly Mutex mutex;
        private bool owned;

        private SingleInstanceLease(Mutex mutex)
        {
            this.mutex = mutex;
            owned = true;
        }

        public static SingleInstanceLease TryAcquire()
        {
            Mutex mutex = new Mutex(false, Name);
            try
            {
                bool owned;
                try
                {
                    owned = mutex.WaitOne(0);
                }
                catch (AbandonedMutexException)
                {
                    owned = true;
                }
                if (!owned)
                {
                    mutex.Dispose();
                    return null;
                }
                return new SingleInstanceLease(mutex);
            }
            catch (Exception)
            {
                mutex.Dispose();
                throw;
            }
        }

        public void Dispose()
        {
            if (owned)
            {
                owned = false;
                try
                {
                    mutex.ReleaseMutex();
                }
                catch (ApplicationException)
                {
                }
            }
            mutex.Dispose();
        }
    }
}
