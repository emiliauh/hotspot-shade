using System;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.App;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.TestLauncher;

namespace HotspotShade.WinUI2.Broker
{
    // One answer from an engine request. Code is empty when the request
    // reached the engine.
    internal sealed class EngineAnswer
    {
        public EngineAnswer(int status, string body, string code)
        {
            Status = status;
            Body = body ?? "";
            Code = code ?? "";
        }

        public int Status { get; private set; }

        public string Body { get; private set; }

        public string Code { get; private set; }

        public bool Reached
        {
            get { return Code.Length == 0; }
        }

        public bool IsOk
        {
            get { return Reached && Status >= 200 && Status <= 299; }
        }

        public static EngineAnswer Failure(string code)
        {
            return new EngineAnswer(0, "", code);
        }
    }

    // One running engine that the broker can talk to.
    internal interface IEngineEndpoint
    {
        int Port { get; }

        int ProcessId { get; }

        bool HasExited(out int exitCode);

        EngineAnswer Request(string method, string path, byte[] body, int timeoutMilliseconds);

        // Close the parent-liveness pipe and wait for the engine to run its
        // own stop path. True when the process exited within the wait.
        Task<bool> CloseAsync(TimeSpan grace);
    }

    // The shared request rule: before every request, the launched engine
    // must hold the port alone. Then one fixed request goes to 127.0.0.1
    // with WinHTTP, no proxy, and no redirects.
    internal static class EngineCall
    {
        public static EngineAnswer Send(
            IEngineEndpoint engine,
            byte[] secret,
            string method,
            string path,
            byte[] body,
            int timeoutMilliseconds)
        {
            int exitCode;
            if (engine.HasExited(out exitCode))
            {
                return EngineAnswer.Failure(BrokerCodes.EngineExited);
            }
            ListenerOwnership ownership = ListenerTable.Check(engine.Port, engine.ProcessId);
            if (ownership == ListenerOwnership.Unknown)
            {
                return EngineAnswer.Failure(BrokerCodes.ListenerUnknown);
            }
            if (ownership == ListenerOwnership.Missing)
            {
                return EngineAnswer.Failure(BrokerCodes.EngineStarting);
            }
            if (ownership != ListenerOwnership.Owned)
            {
                return EngineAnswer.Failure(BrokerCodes.ListenerNotOwned);
            }
            LauncherResponse response = LauncherHttp.Send(engine.Port, secret, method, path, body, timeoutMilliseconds);
            if (!response.Reached)
            {
                return EngineAnswer.Failure(MapCode(response.Code));
            }
            string text;
            try
            {
                text = response.Body == null ? "" : new System.Text.UTF8Encoding(false, true).GetString(response.Body);
            }
            catch (Exception)
            {
                return EngineAnswer.Failure(BrokerCodes.BadResponse);
            }
            return new EngineAnswer(response.Status, text, "");
        }

        private static string MapCode(string code)
        {
            switch (code)
            {
                case "timeout":
                    return BrokerCodes.Timeout;
                case "bad_response":
                    return BrokerCodes.BadResponse;
                default:
                    return BrokerCodes.EngineUnavailable;
            }
        }
    }

    // The standard-user engine. It serves the dashboard, pairing, Forget,
    // status, diagnostics, and failures without any administrator prompt. It
    // holds the pairing and writes the handoff frame only when asked.
    internal sealed class UserEngine : IEngineEndpoint
    {
        private readonly Win32EngineHost host;
        private readonly int port;
        private readonly int processId;

        private UserEngine(Win32EngineHost host, int port, int processId, bool handoff)
        {
            this.host = host;
            this.port = port;
            this.processId = processId;
            SupportsHandoff = handoff;
        }

        public int Port
        {
            get { return port; }
        }

        public int ProcessId
        {
            get { return processId; }
        }

        // False when this engine build refused --handoff-fd. Turn on is then
        // unavailable, because the elevated engine cannot get the pairing.
        public bool SupportsHandoff { get; private set; }

        public IntPtr HandoffReadHandle
        {
            get { return SupportsHandoff ? host.HandoffReadHandle : IntPtr.Zero; }
        }

        // Start the engine from the package. A build that refuses the
        // handoff switch exits at once. A taken port also ends in an exit, so
        // the broker tries the switch twice on two random ports before it
        // starts the engine without it. The dashboard then still works and
        // Turn on is shown as unavailable.
        public static UserEngine Start(string root, out string code)
        {
            UserEngine engine = StartOnce(root, true, out code);
            if (engine != null || code != BrokerCodes.EngineExited)
            {
                return engine;
            }
            engine = StartOnce(root, true, out code);
            if (engine != null || code != BrokerCodes.EngineExited)
            {
                return engine;
            }
            return StartOnce(root, false, out code);
        }

        private static UserEngine StartOnce(string root, bool handoff, out string code)
        {
            string path = System.IO.Path.Combine(root, "Engine", EngineLaunchRules.ExecutableName);
            if (!System.IO.File.Exists(path))
            {
                code = BrokerCodes.EngineMissing;
                return null;
            }
            int port = EngineBrokerRules.PickPort();
            Win32EngineHost host;
            EngineLaunchPlan plan;
            EngineLaunchFailure failure;
            if (!Win32EngineHost.TryCreate(path, root, port, false, handoff, out host, out plan, out failure))
            {
                code = BrokerCodes.EngineUnavailable;
                return null;
            }
            EngineLaunchOutcome outcome;
            using (EngineLaunchSecret secret = EngineLaunchSecret.CreateRandom())
            {
                if (plan.DisclosesSecret(secret))
                {
                    host.CloseAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();
                    code = BrokerCodes.EngineUnavailable;
                    return null;
                }
                outcome = host.LaunchAsync(new EngineLaunchRequest(plan, secret), CancellationToken.None)
                    .GetAwaiter().GetResult();
            }
            int processId;
            if (!outcome.Launched || !host.TryGetProcessId(out processId))
            {
                host.CloseAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();
                code = outcome.Failure == EngineLaunchFailure.BrokerMissing ? BrokerCodes.EngineMissing : BrokerCodes.EngineUnavailable;
                return null;
            }
            DateTime deadline = DateTime.UtcNow.AddSeconds(10);
            while (DateTime.UtcNow < deadline)
            {
                int exitCode;
                if (host.HasExited(out exitCode))
                {
                    host.CloseAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();
                    code = BrokerCodes.EngineExited;
                    return null;
                }
                ListenerOwnership ownership = ListenerTable.Check(port, processId);
                if (ownership == ListenerOwnership.Owned)
                {
                    code = BrokerCodes.None;
                    return new UserEngine(host, port, processId, handoff);
                }
                if (ownership == ListenerOwnership.Foreign)
                {
                    host.CloseAsync(TimeSpan.FromSeconds(8)).GetAwaiter().GetResult();
                    code = BrokerCodes.ListenerNotOwned;
                    return null;
                }
                Thread.Sleep(100);
            }
            host.CloseAsync(TimeSpan.FromSeconds(8)).GetAwaiter().GetResult();
            code = BrokerCodes.EngineUnavailable;
            return null;
        }

        public bool HasExited(out int exitCode)
        {
            return host.HasExited(out exitCode);
        }

        public EngineAnswer Request(string method, string path, byte[] body, int timeoutMilliseconds)
        {
            EngineHttpEndpoint endpoint;
            if (!host.TryGetEndpoint(out endpoint))
            {
                return EngineAnswer.Failure(BrokerCodes.EngineExited);
            }
            byte[] secret = endpoint.CopySecret();
            try
            {
                return EngineCall.Send(this, secret, method, path, body, timeoutMilliseconds);
            }
            finally
            {
                Array.Clear(secret, 0, secret.Length);
                endpoint.Clear();
            }
        }

        public Task<bool> CloseAsync(TimeSpan grace)
        {
            return host.CloseAsync(grace);
        }

        // Release the process handle after the engine exited.
        public void Release()
        {
            host.Release();
        }
    }

    // The engine that Turn on started with administrator rights. The broker
    // holds its bearer secret and the parent-liveness write end. Closing
    // that end, or a broker exit, makes the engine stop the tunnel, remove
    // its routes, and exit.
    internal sealed class ElevatedEngine : IEngineEndpoint
    {
        private readonly object gate = new object();
        private readonly int port;
        private readonly int processId;
        private IntPtr process;
        private IntPtr parentWrite;
        private byte[] secret;
        private Task<bool> closeTask;

        public ElevatedEngine(int port, int processId, IntPtr process, IntPtr parentWrite, byte[] secret)
        {
            this.port = port;
            this.processId = processId;
            this.process = process;
            this.parentWrite = parentWrite;
            this.secret = secret;
        }

        public int Port
        {
            get { return port; }
        }

        public int ProcessId
        {
            get { return processId; }
        }

        // True when no close is running. Release waits for this, so a close
        // never waits on a handle that Release already closed.
        public bool CloseFinished
        {
            get
            {
                lock (gate)
                {
                    return closeTask == null || closeTask.IsCompleted;
                }
            }
        }

        public bool Closing
        {
            get
            {
                lock (gate)
                {
                    return closeTask != null;
                }
            }
        }

        public bool HasExited(out int exitCode)
        {
            lock (gate)
            {
                exitCode = 0;
                if (process == IntPtr.Zero)
                {
                    return true;
                }
                if (BrokerNative.WaitForSingleObject(process, 0) != BrokerNative.WaitObject0)
                {
                    return false;
                }
                uint code;
                if (BrokerNative.GetExitCodeProcess(process, out code))
                {
                    exitCode = unchecked((int)code);
                }
                return true;
            }
        }

        public EngineAnswer Request(string method, string path, byte[] body, int timeoutMilliseconds)
        {
            byte[] copy;
            lock (gate)
            {
                if (secret == null || closeTask != null)
                {
                    return EngineAnswer.Failure(BrokerCodes.EngineExited);
                }
                copy = new byte[secret.Length];
                Array.Copy(secret, copy, secret.Length);
            }
            try
            {
                return EngineCall.Send(this, copy, method, path, body, timeoutMilliseconds);
            }
            finally
            {
                Array.Clear(copy, 0, copy.Length);
            }
        }

        public Task<bool> CloseAsync(TimeSpan grace)
        {
            lock (gate)
            {
                if (closeTask == null)
                {
                    IntPtr parent = parentWrite;
                    parentWrite = IntPtr.Zero;
                    if (secret != null)
                    {
                        Array.Clear(secret, 0, secret.Length);
                        secret = null;
                    }
                    closeTask = Task.Run(delegate
                    {
                        if (parent != IntPtr.Zero)
                        {
                            // The engine sees the end of the pipe and runs its
                            // own stop path. The broker never terminates it.
                            BrokerNative.CloseHandle(parent);
                        }
                        IntPtr handle;
                        lock (gate)
                        {
                            handle = process;
                        }
                        if (handle == IntPtr.Zero)
                        {
                            return true;
                        }
                        int milliseconds = (int)Math.Min(30000D, Math.Max(0D, grace.TotalMilliseconds));
                        return BrokerNative.WaitForSingleObject(handle, (uint)milliseconds) == BrokerNative.WaitObject0;
                    });
                }
                return closeTask;
            }
        }

        // Release the process handle after the engine exited.
        public void Release()
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
}
