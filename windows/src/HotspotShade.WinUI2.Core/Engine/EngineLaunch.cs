using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace HotspotShade.WinUI2.Core.Engine
{
    // Why a launch did not produce a connected engine. A launch failure is not
    // a tunnel state. When a launch fails the tunnel stays off and the app says
    // that the tunnel state is unknown.
    public enum EngineLaunchFailure
    {
        None,
        NotConfigured,
        PathInvalid,
        PathNotTrusted,
        PortInvalid,
        HandleInvalid,
        SecretInvalid,
        SecretDisclosed,
        BrokerMissing,
        BrokerRefused,
        AdminRequired,
        LaunchTimeout,
        ConnectFailed,
        EngineLost,
        AlreadyStarted,
        Closed
    }

    // The fixed launch contract for the Windows engine.
    //
    // The engine is the Rust `gui` mode. It listens on loopback only and needs
    // a per-launch bearer secret. The secret travels on an inherited pipe
    // handle that the launcher passes by number. It never appears on a command
    // line, in the environment, in a setting, or in a log. A second inherited
    // pipe handle is the parent-liveness channel: the engine stops and removes
    // what it created when the app closes that handle or exits.
    //
    // A third inherited pipe handle can carry the pairing. The user engine
    // gets the write end with --handoff-fd and writes the pairing there only
    // when the broker asks, right before Turn on. The elevated engine gets
    // the read end with --credentials-fd and reads the newest frame once.
    //
    // The standard-user app never asks Windows for elevation. Only Turn on
    // starts an elevated engine, through the UAC prompt in the broker.
    public enum EnginePairingDescriptor
    {
        None,
        Handoff,
        Credentials
    }

    public static class EngineLaunchRules
    {
        public const string ExecutableName = "hotspotshade.exe";
        public const string Mode = "gui";
        public const string NoOpenSwitch = "--no-open";
        public const string PortSwitch = "--port";
        public const string BearerSwitch = "--token-fd";
        public const string ParentSwitch = "--parent-fd";
        public const string DemoSwitch = "--demo";
        public const string HandoffSwitch = "--handoff-fd";
        public const string CredentialsSwitch = "--credentials-fd";

        // A loopback port that a person or the app selected. Port 0 is refused
        // because the Windows engine reports no chosen port back to the app.
        public const int MinPort = 1024;
        public const int MaxPort = 65535;

        // The engine reads 64 lowercase hex characters and one newline.
        public const int SecretHexLength = 64;
        public const int SecretWriteLength = 65;
        public const byte SecretTerminator = (byte)'\n';

        public static bool IsAbsolutePath(string path)
        {
            if (string.IsNullOrEmpty(path) || path.Length < 3)
            {
                return false;
            }
            bool separator = path[0] == '\\' || path[0] == '/';
            if (separator)
            {
                // A UNC path needs two leading separators, a share name, and a
                // file below it.
                if (path[1] != '\\' && path[1] != '/')
                {
                    return false;
                }
                int share = IndexOfSeparator(path, 2);
                return share > 2 && share < path.Length - 1;
            }
            bool letter = (path[0] >= 'A' && path[0] <= 'Z')
                || (path[0] >= 'a' && path[0] <= 'z');
            return letter
                && path[1] == ':'
                && (path[2] == '\\' || path[2] == '/')
                && path.Length > 3;
        }

        // A path with a dot or dot-dot segment is refused. The app never needs
        // one and a relative segment could move the engine outside its install
        // folder after a text comparison.
        public static bool HasTraversal(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return true;
            }
            int start = 0;
            while (start < path.Length)
            {
                int end = start;
                while (end < path.Length && path[end] != '\\' && path[end] != '/')
                {
                    end++;
                }
                int length = end - start;
                if (length == 1 && path[start] == '.')
                {
                    return true;
                }
                if (length == 2 && path[start] == '.' && path[start + 1] == '.')
                {
                    return true;
                }
                start = end + 1;
            }
            return false;
        }

        public static bool IsExecutableName(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return false;
            }
            int separator = Math.Max(path.LastIndexOf('\\'), path.LastIndexOf('/'));
            string name = separator < 0 ? path : path.Substring(separator + 1);
            return string.Equals(name, ExecutableName, StringComparison.OrdinalIgnoreCase);
        }

        // True only for a file below the root. A shared prefix such as
        // C:\Apps\HotspotShadeEvil is not inside C:\Apps\HotspotShade.
        public static bool IsInside(string candidate, string root)
        {
            if (!IsAbsolutePath(candidate) || !IsAbsolutePath(root))
            {
                return false;
            }
            string inside = Normalize(candidate);
            string prefix = Normalize(root).TrimEnd('\\');
            if (prefix.Length < 2)
            {
                return false;
            }
            if (inside.Length <= prefix.Length + 1)
            {
                return false;
            }
            return inside.StartsWith(prefix + "\\", StringComparison.OrdinalIgnoreCase);
        }

        public static bool IsValidPort(int port)
        {
            return port >= MinPort && port <= MaxPort;
        }

        // An inherited handle value is a positive number. Zero and -1 are not
        // handles, and the bearer channel and the parent channel must not be
        // the same handle.
        public static bool IsValidHandlePair(long bearer, long parent)
        {
            return bearer > 0 && parent > 0 && bearer != parent;
        }

        internal static string Normalize(string path)
        {
            return path.Replace('/', '\\');
        }

        private static int IndexOfSeparator(string path, int start)
        {
            for (int index = start; index < path.Length; index++)
            {
                if (path[index] == '\\' || path[index] == '/')
                {
                    return index;
                }
            }
            return -1;
        }
    }

    // One per-launch bearer secret. It is 64 lowercase hex characters in
    // memory and on the pipe. It is never the source device token, it is never
    // written to settings or disk, and it is cleared as soon as the engine has
    // read it. ToString never returns the value.
    public sealed class EngineLaunchSecret : IDisposable
    {
        private const string Digits = "0123456789abcdef";
        private byte[] hex;

        private EngineLaunchSecret(byte[] hex)
        {
            this.hex = hex;
        }

        public bool IsCleared
        {
            get { return hex == null; }
        }

        public static EngineLaunchSecret CreateRandom()
        {
            byte[] random = new byte[EngineLaunchRules.SecretHexLength / 2];
            try
            {
                using (RandomNumberGenerator generator = RandomNumberGenerator.Create())
                {
                    generator.GetBytes(random);
                }
                byte[] text = new byte[EngineLaunchRules.SecretHexLength];
                for (int index = 0; index < random.Length; index++)
                {
                    text[index * 2] = (byte)Digits[random[index] >> 4];
                    text[index * 2 + 1] = (byte)Digits[random[index] & 0x0F];
                }
                return new EngineLaunchSecret(text);
            }
            finally
            {
                Array.Clear(random, 0, random.Length);
            }
        }

        public static bool TryParse(string value, out EngineLaunchSecret secret)
        {
            secret = null;
            if (value == null || value.Length != EngineLaunchRules.SecretHexLength)
            {
                return false;
            }
            byte[] text = new byte[EngineLaunchRules.SecretHexLength];
            for (int index = 0; index < value.Length; index++)
            {
                char character = value[index];
                bool digit = character >= '0' && character <= '9';
                bool lower = character >= 'a' && character <= 'f';
                if (!digit && !lower)
                {
                    Array.Clear(text, 0, text.Length);
                    return false;
                }
                text[index] = (byte)character;
            }
            secret = new EngineLaunchSecret(text);
            return true;
        }

        // True when the secret appears verbatim in the text. The app uses this
        // check before it hands anything to a launcher. A leak is a bug, so the
        // text is not reported and only the answer travels back.
        public bool AppearsIn(string text)
        {
            byte[] value = hex;
            if (value == null || string.IsNullOrEmpty(text))
            {
                return false;
            }
            byte[] haystack = Encoding.UTF8.GetBytes(text);
            bool found = false;
            for (int start = 0; !found && start + value.Length <= haystack.Length; start++)
            {
                int index = 0;
                while (index < value.Length && haystack[start + index] == value[index])
                {
                    index++;
                }
                found = index == value.Length;
            }
            Array.Clear(haystack, 0, haystack.Length);
            return found;
        }

        // Write the 64 characters and the newline that the engine reads. The
        // launcher closes its own copy of the pipe as soon as the engine has
        // read the value.
        public void WriteTo(System.IO.Stream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException("stream");
            }
            byte[] value = hex;
            if (value == null)
            {
                throw new InvalidOperationException("the launch secret is cleared");
            }
            byte[] buffer = new byte[EngineLaunchRules.SecretWriteLength];
            try
            {
                Buffer.BlockCopy(value, 0, buffer, 0, value.Length);
                buffer[EngineLaunchRules.SecretHexLength] = EngineLaunchRules.SecretTerminator;
                stream.Write(buffer, 0, buffer.Length);
            }
            finally
            {
                Array.Clear(buffer, 0, buffer.Length);
            }
        }

        public void Clear()
        {
            byte[] value = hex;
            hex = null;
            if (value != null)
            {
                Array.Clear(value, 0, value.Length);
            }
        }

        public void Dispose()
        {
            Clear();
        }

        public override string ToString()
        {
            return "Engine launch secret (private).";
        }
    }

    // The fixed launch request for the engine. Every argument is built here.
    // A caller can select the executable path, the port, and the two inherited
    // handle values; it cannot append an argument, a switch, or a secret.
    public sealed class EngineLaunchPlan
    {
        private readonly string[] arguments;
        private readonly IReadOnlyList<string> readOnlyArguments;

        private EngineLaunchPlan(
            string executablePath,
            int port,
            long bearerHandle,
            long parentHandle,
            string[] arguments)
        {
            ExecutablePath = executablePath;
            Port = port;
            BearerHandle = bearerHandle;
            ParentHandle = parentHandle;
            PairingKind = EnginePairingDescriptor.None;
            this.arguments = arguments;
            readOnlyArguments = Array.AsReadOnly(arguments);
        }

        public string ExecutablePath { get; private set; }

        public int Port { get; private set; }

        // The inherited handle that carries the bearer secret. The engine reads
        // it once and the app closes its own copy.
        public long BearerHandle { get; private set; }

        // The inherited pipe handle that carries parent liveness. The app holds
        // it open for its whole life and closes it to stop the engine.
        public long ParentHandle { get; private set; }

        // The optional pairing pipe handle and its direction.
        public EnginePairingDescriptor PairingKind { get; private set; }

        public long PairingHandle { get; private set; }

        // The argument list, without any secret. The launcher passes these
        // values separately. It never joins them into a shell command.
        public IReadOnlyList<string> Arguments
        {
            get { return readOnlyArguments; }
        }

        // True for the same engine, port, and handle pair. A launch that
        // already ran cannot move to a different plan without an app restart.
        public bool IsSameAs(EngineLaunchPlan other)
        {
            if (other == null)
            {
                return false;
            }
            return Port == other.Port
                && BearerHandle == other.BearerHandle
                && ParentHandle == other.ParentHandle
                && PairingKind == other.PairingKind
                && PairingHandle == other.PairingHandle
                && string.Equals(
                    EngineLaunchRules.Normalize(ExecutablePath),
                    EngineLaunchRules.Normalize(other.ExecutablePath),
                    StringComparison.OrdinalIgnoreCase);
        }

        public static bool TryCreate(
            string executablePath,
            int port,
            long bearerHandle,
            long parentHandle,
            out EngineLaunchPlan plan,
            out EngineLaunchFailure failure)
        {
            return TryCreate(executablePath, null, port, bearerHandle, parentHandle, out plan, out failure);
        }

        // A packaged app must run the engine from its own install folder. A
        // path in a user-writable directory is refused.
        public static bool TryCreateTrusted(
            string executablePath,
            string trustedRoot,
            int port,
            long bearerHandle,
            long parentHandle,
            out EngineLaunchPlan plan,
            out EngineLaunchFailure failure)
        {
            return TryCreate(executablePath, trustedRoot, port, bearerHandle, parentHandle, out plan, out failure);
        }

        // The same trusted plan with one pairing pipe handle. The handle must
        // differ from the bearer and the parent handles, because the engine
        // closes the bearer handle after its read and treats a parent hang-up
        // as a stop.
        public static bool TryCreateTrustedWithPairing(
            string executablePath,
            string trustedRoot,
            int port,
            long bearerHandle,
            long parentHandle,
            EnginePairingDescriptor pairingKind,
            long pairingHandle,
            out EngineLaunchPlan plan,
            out EngineLaunchFailure failure)
        {
            if (pairingKind == EnginePairingDescriptor.None)
            {
                return TryCreate(executablePath, trustedRoot, port, bearerHandle, parentHandle, out plan, out failure);
            }
            plan = null;
            if (pairingHandle <= 0 || pairingHandle == bearerHandle || pairingHandle == parentHandle)
            {
                failure = EngineLaunchFailure.HandleInvalid;
                return false;
            }
            EngineLaunchPlan basePlan;
            if (!TryCreate(executablePath, trustedRoot, port, bearerHandle, parentHandle, out basePlan, out failure))
            {
                return false;
            }
            string[] arguments = new string[basePlan.arguments.Length + 2];
            Array.Copy(basePlan.arguments, arguments, basePlan.arguments.Length);
            arguments[basePlan.arguments.Length] = pairingKind == EnginePairingDescriptor.Handoff
                ? EngineLaunchRules.HandoffSwitch
                : EngineLaunchRules.CredentialsSwitch;
            arguments[basePlan.arguments.Length + 1] = pairingHandle.ToString(CultureInfo.InvariantCulture);
            plan = new EngineLaunchPlan(executablePath, port, bearerHandle, parentHandle, arguments);
            plan.PairingKind = pairingKind;
            plan.PairingHandle = pairingHandle;
            failure = EngineLaunchFailure.None;
            return true;
        }

        private static bool TryCreate(
            string executablePath,
            string trustedRoot,
            int port,
            long bearerHandle,
            long parentHandle,
            out EngineLaunchPlan plan,
            out EngineLaunchFailure failure)
        {
            plan = null;
            if (!EngineLaunchRules.IsAbsolutePath(executablePath)
                || EngineLaunchRules.HasTraversal(executablePath)
                || !EngineLaunchRules.IsExecutableName(executablePath))
            {
                failure = EngineLaunchFailure.PathInvalid;
                return false;
            }
            if (trustedRoot != null)
            {
                if (!EngineLaunchRules.IsAbsolutePath(trustedRoot)
                    || EngineLaunchRules.HasTraversal(trustedRoot)
                    || !EngineLaunchRules.IsInside(executablePath, trustedRoot))
                {
                    failure = EngineLaunchFailure.PathNotTrusted;
                    return false;
                }
            }
            if (!EngineLaunchRules.IsValidPort(port))
            {
                failure = EngineLaunchFailure.PortInvalid;
                return false;
            }
            if (!EngineLaunchRules.IsValidHandlePair(bearerHandle, parentHandle))
            {
                failure = EngineLaunchFailure.HandleInvalid;
                return false;
            }

            string[] arguments =
            {
                EngineLaunchRules.Mode,
                EngineLaunchRules.NoOpenSwitch,
                EngineLaunchRules.PortSwitch,
                port.ToString(CultureInfo.InvariantCulture),
                EngineLaunchRules.BearerSwitch,
                bearerHandle.ToString(CultureInfo.InvariantCulture),
                EngineLaunchRules.ParentSwitch,
                parentHandle.ToString(CultureInfo.InvariantCulture)
            };
            plan = new EngineLaunchPlan(executablePath, port, bearerHandle, parentHandle, arguments);
            failure = EngineLaunchFailure.None;
            return true;
        }

        // The plan is built before a secret exists. This check covers a caller
        // that reuses a plan for a later launch. A real launch must answer
        // false, so a random secret and a fixed path stay separate.
        public bool DisclosesSecret(EngineLaunchSecret secret)
        {
            if (secret == null || secret.IsCleared)
            {
                return false;
            }
            if (secret.AppearsIn(ExecutablePath))
            {
                return true;
            }
            for (int index = 0; index < arguments.Length; index++)
            {
                if (secret.AppearsIn(arguments[index]))
                {
                    return true;
                }
            }
            return false;
        }

        // The argument list for a failure report. It holds no path and no
        // secret.
        public string Describe()
        {
            return string.Join(" ", arguments);
        }
    }

    // One launch. The secret is owned by the caller and cleared as soon as the
    // launch call returns.
    public sealed class EngineLaunchRequest
    {
        public EngineLaunchRequest(EngineLaunchPlan plan, EngineLaunchSecret secret)
        {
            if (plan == null)
            {
                throw new ArgumentNullException("plan");
            }
            if (secret == null)
            {
                throw new ArgumentNullException("secret");
            }
            if (secret.IsCleared)
            {
                throw new ArgumentException("the launch secret is cleared", "secret");
            }
            if (plan.DisclosesSecret(secret))
            {
                throw new ArgumentException("the launch secret must not appear in a launch argument", "secret");
            }
            Plan = plan;
            Secret = secret;
        }

        public EngineLaunchPlan Plan { get; private set; }

        public EngineLaunchSecret Secret { get; private set; }
    }

    // The result of one launch attempt. A failed launch carries one fixed
    // reason and no detail text from the host.
    public sealed class EngineLaunchOutcome
    {
        private EngineLaunchOutcome(bool launched, EngineLaunchFailure failure)
        {
            Launched = launched;
            Failure = failure;
        }

        public bool Launched { get; private set; }

        public EngineLaunchFailure Failure { get; private set; }

        public static EngineLaunchOutcome Success()
        {
            return new EngineLaunchOutcome(true, EngineLaunchFailure.None);
        }

        public static EngineLaunchOutcome Failed(EngineLaunchFailure failure)
        {
            if (failure == EngineLaunchFailure.None || failure == EngineLaunchFailure.ConnectFailed)
            {
                failure = EngineLaunchFailure.BrokerRefused;
            }
            return new EngineLaunchOutcome(false, failure);
        }
    }

    // What happened to the parent-liveness channel and the engine process when
    // the app closed them.
    public enum EngineHostCloseState
    {
        None,
        Exited,
        NotExited,
        TimedOut
    }

    // The host seam. The full-trust launcher owns the pipes, the handle values,
    // and the engine process. The app layer implements this interface outside
    // this library. A test fake implements it in the test project.
    //
    // Placement: the implementation runs in the process that owns the engine,
    // which is the full-trust broker. The UWP window cannot create an
    // inheritable handle, so it must not implement this seam.
    //
    // Rules for an implementation:
    // - Create two pipes. The engine receives the read end of each one. Pass
    //   those two handle values and only those numbers.
    // - Copy the secret before LaunchAsync returns. The app clears its copy
    //   when the call returns or times out, so a later read would see a
    //   cleared buffer.
    // - Write the secret and the newline to the bearer write end, then close
    //   the app copy at once. The engine reads the value and then sees the end
    //   of the pipe.
    // - Keep the parent-liveness write end open until the app stops the engine
    //   or exits, and never write a byte to it. The engine stops when it reads
    //   the end of the pipe.
    // - Never ask Windows for elevation. Report AdminRequired instead.
    // - CloseAsync is idempotent. It closes the parent channel, waits at most
    //   the given grace for the engine to exit, and returns true only when the
    //   process is gone. It never forces a process termination, because the
    //   engine removes routes and devices on its own exit path.
    public interface IEngineHost
    {
        System.Threading.Tasks.Task<EngineLaunchOutcome> LaunchAsync(
            EngineLaunchRequest request,
            System.Threading.CancellationToken cancellationToken);

        System.Threading.Tasks.Task<bool> CloseAsync(TimeSpan grace);
    }

    // The honest default for this build. The package has no full-trust helper,
    // so a real start fails closed and the app does not invent one.
    public sealed class UnavailableEngineHost : IEngineHost
    {
        public System.Threading.Tasks.Task<EngineLaunchOutcome> LaunchAsync(
            EngineLaunchRequest request,
            System.Threading.CancellationToken cancellationToken)
        {
            return System.Threading.Tasks.Task.FromResult(
                EngineLaunchOutcome.Failed(EngineLaunchFailure.BrokerMissing));
        }

        public System.Threading.Tasks.Task<bool> CloseAsync(TimeSpan grace)
        {
            return System.Threading.Tasks.Task.FromResult(true);
        }
    }

    // Fixed bounds for the launch and for the stop path. The launch bound
    // covers a slow app service handoff. The close bound matches the engine's
    // own stop budget, so a person never waits without a limit.
    public static class EngineLaunchTiming
    {
        public static readonly TimeSpan Launch = TimeSpan.FromSeconds(20);
        public static readonly TimeSpan HostClose = TimeSpan.FromSeconds(8);
    }

    // One fixed sentence per launch failure. The text never holds a path, a
    // handle value, a port, or a secret.
    public static class EngineLaunchText
    {
        public static string Reason(EngineLaunchFailure failure)
        {
            switch (failure)
            {
                case EngineLaunchFailure.NotConfigured:
                    return "This build has no engine launcher. The app cannot start a tunnel.";
                case EngineLaunchFailure.PathInvalid:
                    return "The engine path must be an absolute path to hotspotshade.exe.";
                case EngineLaunchFailure.PathNotTrusted:
                    return "The engine must run from the app install folder.";
                case EngineLaunchFailure.PortInvalid:
                    return "The engine port must be a number from 1024 to 65535.";
                case EngineLaunchFailure.HandleInvalid:
                    return "The engine launcher needs two separate inherited handles.";
                case EngineLaunchFailure.SecretInvalid:
                    return "The launch secret is not valid.";
                case EngineLaunchFailure.SecretDisclosed:
                    return "The launch secret must not appear in a launch argument.";
                case EngineLaunchFailure.BrokerMissing:
                    return "The engine is not installed. This build has no tunnel.";
                case EngineLaunchFailure.BrokerRefused:
                    return "The engine refused to start. The tunnel stays off.";
                case EngineLaunchFailure.AdminRequired:
                    return "The engine needs an administrator-approved broker. This app does not elevate. Install the protected broker, then start again.";
                case EngineLaunchFailure.LaunchTimeout:
                    return "The engine did not start in time. The tunnel stays off.";
                case EngineLaunchFailure.ConnectFailed:
                    return "The app could not connect to the engine. The tunnel state is unknown.";
                case EngineLaunchFailure.EngineLost:
                    return "The engine stopped. The tunnel state is unknown.";
                case EngineLaunchFailure.AlreadyStarted:
                    return "The engine is already started. Restart the app to change its settings.";
                case EngineLaunchFailure.Closed:
                    return "The engine connection is closed.";
                default:
                    return "";
            }
        }

        // A launch failure is shown through the same status text as a broker
        // error. These are the existing codes; a launch never adds a code to
        // the broker contract.
        public static string WireCode(EngineLaunchFailure failure)
        {
            switch (failure)
            {
                case EngineLaunchFailure.BrokerMissing:
                    return EngineProtocol.ErrorCodes.HelperMissing;
                case EngineLaunchFailure.BrokerRefused:
                case EngineLaunchFailure.AdminRequired:
                case EngineLaunchFailure.LaunchTimeout:
                case EngineLaunchFailure.ConnectFailed:
                case EngineLaunchFailure.EngineLost:
                    return EngineProtocol.ErrorCodes.EngineUnavailable;
                case EngineLaunchFailure.AlreadyStarted:
                    return EngineProtocol.ErrorCodes.AlreadyRunning;
                case EngineLaunchFailure.Closed:
                    return EngineProtocol.ErrorCodes.Closed;
                case EngineLaunchFailure.NotConfigured:
                case EngineLaunchFailure.PathInvalid:
                case EngineLaunchFailure.PathNotTrusted:
                case EngineLaunchFailure.PortInvalid:
                case EngineLaunchFailure.HandleInvalid:
                case EngineLaunchFailure.SecretInvalid:
                case EngineLaunchFailure.SecretDisclosed:
                    return EngineProtocol.ErrorCodes.Internal;
                default:
                    return EngineProtocol.ErrorCodes.EngineUnavailable;
            }
        }

        // One fixed sentence for the stop path. A stop that did not finish asks
        // a person to check the adapter and the routes before a new start.
        public static string CloseText(EngineHostCloseState close)
        {
            switch (close)
            {
                case EngineHostCloseState.Exited:
                    return "The engine stopped.";
                case EngineHostCloseState.NotExited:
                    return "The engine did not stop. Check the tunnel adapter and routes before you start again.";
                case EngineHostCloseState.TimedOut:
                    return "The engine did not stop in time. Check the tunnel adapter and routes before you start again.";
                default:
                    return "The stop path did not run.";
            }
        }

        public static string StateWord(EngineStartupState state)
        {
            switch (state)
            {
                case EngineStartupState.Idle:
                    return "not started";
                case EngineStartupState.Launching:
                    return "launching";
                case EngineStartupState.Connecting:
                    return "connecting";
                case EngineStartupState.Connected:
                    return "connected";
                case EngineStartupState.Failed:
                    return "failed";
                default:
                    return "closed";
            }
        }

        public static string FailureWord(EngineLaunchFailure failure)
        {
            switch (failure)
            {
                case EngineLaunchFailure.None:
                    return "none";
                case EngineLaunchFailure.NotConfigured:
                    return "not configured";
                case EngineLaunchFailure.PathInvalid:
                    return "path invalid";
                case EngineLaunchFailure.PathNotTrusted:
                    return "path not trusted";
                case EngineLaunchFailure.PortInvalid:
                    return "port invalid";
                case EngineLaunchFailure.HandleInvalid:
                    return "handle invalid";
                case EngineLaunchFailure.SecretInvalid:
                    return "secret invalid";
                case EngineLaunchFailure.SecretDisclosed:
                    return "secret disclosed";
                case EngineLaunchFailure.BrokerMissing:
                    return "engine missing";
                case EngineLaunchFailure.BrokerRefused:
                    return "engine refused";
                case EngineLaunchFailure.AdminRequired:
                    return "administrator required";
                case EngineLaunchFailure.LaunchTimeout:
                    return "launch timeout";
                case EngineLaunchFailure.ConnectFailed:
                    return "connect failed";
                case EngineLaunchFailure.EngineLost:
                    return "engine lost";
                case EngineLaunchFailure.AlreadyStarted:
                    return "already started";
                default:
                    return "closed";
            }
        }

        public static string CloseWord(EngineHostCloseState close)
        {
            switch (close)
            {
                case EngineHostCloseState.Exited:
                    return "the engine exited";
                case EngineHostCloseState.NotExited:
                    return "the engine did not exit";
                case EngineHostCloseState.TimedOut:
                    return "the stop timed out";
                default:
                    return "not closed";
            }
        }
    }
}
