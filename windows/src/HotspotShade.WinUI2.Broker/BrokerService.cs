using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.App;
using HotspotShade.WinUI2.Core.Engine;

namespace HotspotShade.WinUI2.Broker
{
    // The broker state and the fixed operation table.
    //
    // The standard-user engine starts with the broker and serves every
    // operation except a live tunnel. Turn on is the only operation that
    // starts the elevated engine (ElevationPolicy). While the elevated engine
    // exists it answers status, diagnostics, failures, logs, and probes, and
    // pairing and Forget are refused. A confirmed stop returns to the user
    // engine, which kept the pairing.
    internal sealed class BrokerService
    {
        private const int StatusTimeout = 5000;
        private const int ActionTimeout = 10000;
        private const int StartTimeout = 90000;
        private const int StopTimeout = 60000;
        private const int MaxUserRestarts = 3;
        private const int ShutdownStopTimeout = 30000;
        private static readonly TimeSpan ShutdownActionWait = TimeSpan.FromSeconds(45);

        private static readonly byte[] EmptyObject = Encoding.ASCII.GetBytes("{}");

        private readonly string root;
        private readonly object state = new object();
        private readonly SemaphoreSlim actions = new SemaphoreSlim(1, 1);

        private UserEngine user;
        private string userFailure = BrokerCodes.EngineStarting;
        private bool userStarting;
        private int userRestarts;
        private DateTime lastRestartUtc = DateTime.MinValue;
        private ElevatedEngine elevated;
        private ElevatedEngine retiring;
        private DateTime retiringSinceUtc;
        private string phase = BrokerPhases.Idle;
        private bool shuttingDown;
        // True once /api/start went to the elevated engine. Before that the
        // engine changed no route, so its exit is a failed start, not a lost
        // tunnel.
        private bool elevatedStartSent;
        // The last stop that the elevated engine reported before the broker
        // retired it. The user engine does not know it, so status answers
        // carry it until the next Turn on.
        private JsonNode lastElevatedStop;
        private JsonNode lastElevatedStopMessage;

        public BrokerService(string root)
        {
            this.root = root;
        }

        // Start the user engine. The window can connect before this ends;
        // it sees the starting screen until the first status answer.
        public void StartUserEngine()
        {
            lock (state)
            {
                if (user != null || userStarting || shuttingDown)
                {
                    return;
                }
                userStarting = true;
                userFailure = BrokerCodes.EngineStarting;
            }
            string code;
            UserEngine started = null;
            try
            {
                started = UserEngine.Start(root, out code);
            }
            catch (Exception)
            {
                code = BrokerCodes.EngineUnavailable;
            }
            bool close = false;
            lock (state)
            {
                userStarting = false;
                if (shuttingDown)
                {
                    close = started != null;
                }
                else
                {
                    user = started;
                    userFailure = started == null ? code : BrokerCodes.None;
                }
            }
            if (close)
            {
                started.CloseAsync(EngineLaunchTiming.HostClose).GetAwaiter().GetResult();
            }
        }

        public Task<BrokerReply> HandleAsync(BrokerRequest request)
        {
            return Task.Run(delegate
            {
                try
                {
                    return Handle(request);
                }
                catch (Exception)
                {
                    return Reply(false, 0, BrokerCodes.EngineUnavailable, "");
                }
            });
        }

        private BrokerReply Handle(BrokerRequest request)
        {
            switch (request.Op)
            {
                case BrokerOps.Status:
                    return ReadOnly("GET", "/api/status", StatusTimeout, true, BodyKind.Status);
                case BrokerOps.PairStatus:
                    return ReadOnly("GET", "/api/phone/pair", StatusTimeout, false, BodyKind.Plain);
                case BrokerOps.Probe:
                    return Post(Current(), "/api/phone/probe", ActionTimeout);
                case BrokerOps.Logs:
                    return ReadOnly("GET", "/api/logs?since=" + BrokerProtocol.FormatSince(request.Since), StatusTimeout, true, BodyKind.Logs);
                case BrokerOps.Diagnostics:
                    return ReadOnly("GET", "/api/diagnostics", StatusTimeout, true, BodyKind.Plain);
                case BrokerOps.Failures:
                    return ReadOnly("GET", "/api/failures", StatusTimeout, true, BodyKind.Plain);
                case BrokerOps.Pair:
                    return UserAction("/api/phone/pair");
                case BrokerOps.PairCancel:
                    return UserAction("/api/phone/pair/cancel");
                case BrokerOps.Forget:
                    return UserAction("/api/phone/forget");
                case BrokerOps.TurnOn:
                    // ElevationPolicy.RequiresElevation is true for this
                    // operation only. No other path reaches the launcher.
                    try
                    {
                        return TurnOn(request.Ping, new IntPtr(request.OwnerWindow));
                    }
                    catch (Exception)
                    {
                        // An unexpected failure must not leave the phase at
                        // Starting. An elevated engine that exists stays the
                        // status source, so the window shows what it reports.
                        lock (state)
                        {
                            if (phase == BrokerPhases.Starting)
                            {
                                phase = elevated != null ? BrokerPhases.Elevated : BrokerPhases.Idle;
                            }
                        }
                        return Reply(false, 0, BrokerCodes.ElevationFailed, "");
                    }
                case BrokerOps.TurnOff:
                    return TurnOff();
                default:
                    return Reply(false, 0, BrokerCodes.UnknownOp, "");
            }
        }

        private enum BodyKind
        {
            Plain,
            Status,
            Logs
        }

        // The engine that answers status now. A lost elevated engine is
        // noticed here: it exited without a stop that the broker asked for.
        private IEngineEndpoint Current()
        {
            bool restart = false;
            IEngineEndpoint result;
            lock (state)
            {
                Reconcile();
                result = elevated != null ? (IEngineEndpoint)elevated : user;
                int exitCode;
                if (elevated == null && user != null && user.HasExited(out exitCode) && !shuttingDown
                    && phase != BrokerPhases.Starting)
                {
                    restart = userRestarts < MaxUserRestarts
                        && DateTime.UtcNow - lastRestartUtc > TimeSpan.FromSeconds(5);
                    if (restart)
                    {
                        userRestarts++;
                        lastRestartUtc = DateTime.UtcNow;
                        UserEngine old = user;
                        user = null;
                        userFailure = BrokerCodes.EngineStarting;
                        old.CloseAsync(TimeSpan.FromSeconds(2));
                        result = null;
                    }
                }
            }
            if (restart)
            {
                // A user engine that stopped is started again. It holds no
                // tunnel, so a restart cannot leave routes behind.
                Task.Run(delegate { StartUserEngine(); });
            }
            return result;
        }

        // Called with the state lock held.
        private void Reconcile()
        {
            int exitCode;
            if (elevated != null && !elevated.Closing && elevated.HasExited(out exitCode))
            {
                elevated.Release();
                elevated = null;
                if (elevatedStartSent)
                {
                    phase = BrokerPhases.ElevatedLost;
                }
            }
            if (retiring != null && retiring.CloseFinished && retiring.HasExited(out exitCode))
            {
                retiring.Release();
                retiring = null;
            }
        }

        private BrokerReply ReadOnly(string method, string path, int timeout, bool current, BodyKind kind)
        {
            IEngineEndpoint engine = current ? Current() : CurrentUser();
            if (engine == null)
            {
                return Reply(false, 0, UserFailure(), "");
            }
            EngineAnswer answer = engine.Request(method, path, null, timeout);
            if (!answer.Reached)
            {
                return Reply(false, 0, answer.Code, "");
            }
            string body;
            string code;
            if (!Trim(answer.Body, kind, out body, out code))
            {
                return Reply(false, answer.Status, code, "");
            }
            if (kind == BodyKind.Status && answer.IsOk)
            {
                ElevatedEngine elevatedEngine = engine as ElevatedEngine;
                if (elevatedEngine != null)
                {
                    RetireIfStopped(elevatedEngine, body);
                }
                else
                {
                    body = WithLastElevatedStop(body);
                }
            }
            return Reply(answer.IsOk, answer.Status, BrokerCodes.None, body);
        }

        // The tunnel of a running elevated engine ended on its own, for
        // example after a gateway check refusal or source device silence.
        // The engine reports running false with a normal state. That is a
        // confirmed stop: the broker closes the engine and returns to the
        // user engine, so Turn on works again. The stop reason stays visible.
        private void RetireIfStopped(ElevatedEngine engine, string body)
        {
            EngineStatusSnapshot snapshot;
            if (!EngineStatusSnapshot.TryParse(body, out snapshot)
                || snapshot.Running != false
                || snapshot.Health != EngineHealth.Normal)
            {
                return;
            }
            if (!actions.Wait(0))
            {
                return;
            }
            try
            {
                lock (state)
                {
                    if (elevated != engine || phase != BrokerPhases.Elevated || shuttingDown)
                    {
                        return;
                    }
                    JsonObject root = JsonNode.Parse(body) as JsonObject;
                    if (root != null)
                    {
                        lastElevatedStop = root["last_stop"] == null ? null : root["last_stop"].DeepClone();
                        lastElevatedStopMessage = root["last_stop_message"] == null ? null : root["last_stop_message"].DeepClone();
                    }
                    elevated = null;
                    retiring = engine;
                    retiringSinceUtc = DateTime.UtcNow;
                    phase = BrokerPhases.Idle;
                }
                engine.CloseAsync(TimeSpan.FromSeconds(15));
            }
            catch (Exception)
            {
            }
            finally
            {
                actions.Release();
            }
        }

        // Add the elevated engine's last stop to a user engine status that has
        // none, so the window can say why the tunnel turned off.
        private string WithLastElevatedStop(string body)
        {
            JsonNode stop;
            JsonNode message;
            lock (state)
            {
                stop = lastElevatedStop;
                message = lastElevatedStopMessage;
            }
            if (stop == null)
            {
                return body;
            }
            try
            {
                JsonObject root = JsonNode.Parse(body) as JsonObject;
                if (root == null)
                {
                    return body;
                }
                JsonObject current = root["last_stop"] as JsonObject;
                bool empty = current == null || current["reason"] == null;
                if (!empty)
                {
                    return body;
                }
                root["last_stop"] = stop.DeepClone();
                root["last_stop_message"] = message == null ? null : message.DeepClone();
                string result = root.ToJsonString();
                return result.Length > BrokerProtocol.MaxBodyChars ? body : result;
            }
            catch (JsonException)
            {
                return body;
            }
        }

        private IEngineEndpoint CurrentUser()
        {
            Current();
            lock (state)
            {
                return user;
            }
        }

        private BrokerReply Post(IEngineEndpoint engine, string path, int timeout)
        {
            if (engine == null)
            {
                return Reply(false, 0, UserFailure(), "");
            }
            EngineAnswer answer = engine.Request("POST", path, EmptyObject, timeout);
            if (!answer.Reached)
            {
                return Reply(false, 0, answer.Code, "");
            }
            string body;
            string code;
            if (!Trim(answer.Body, BodyKind.Plain, out body, out code))
            {
                return Reply(false, answer.Status, code, "");
            }
            return Reply(answer.IsOk, answer.Status, BrokerCodes.None, body);
        }

        // Pair, cancel, and Forget go to the user engine only. They are
        // refused while an elevated engine exists or a start or stop runs, so
        // the pairing cannot change under a live tunnel.
        private BrokerReply UserAction(string path)
        {
            if (!actions.Wait(0))
            {
                return Reply(false, 0, BrokerCodes.Busy, "");
            }
            try
            {
                if (IsShuttingDown())
                {
                    return Reply(false, 0, BrokerCodes.Closed, "");
                }
                IEngineEndpoint engine = CurrentUser();
                lock (state)
                {
                    if (elevated != null || retiring != null
                        || phase == BrokerPhases.Starting || phase == BrokerPhases.Stopping
                        || phase == BrokerPhases.StopUnconfirmed)
                    {
                        return Reply(false, 0, BrokerCodes.ElevatedActive, "");
                    }
                }
                return Post(engine, path, ActionTimeout);
            }
            finally
            {
                actions.Release();
            }
        }

        private BrokerReply TurnOn(bool ping, IntPtr ownerWindow)
        {
            if (!actions.Wait(0))
            {
                return Reply(false, 0, BrokerCodes.Busy, "");
            }
            try
            {
                if (IsShuttingDown())
                {
                    return Reply(false, 0, BrokerCodes.Closed, "");
                }
                UserEngine engine = CurrentUser() as UserEngine;
                lock (state)
                {
                    if (elevated != null)
                    {
                        return Reply(false, 0, BrokerCodes.TunnelRunning, "");
                    }
                    if (retiring != null)
                    {
                        // An engine that never exits after a confirmed stop
                        // is named after a bound instead of a bare Busy.
                        bool overdue = DateTime.UtcNow - retiringSinceUtc > TimeSpan.FromSeconds(60);
                        return Reply(false, 0, overdue ? BrokerCodes.StopUnconfirmed : BrokerCodes.Busy, "");
                    }
                    if (phase == BrokerPhases.ElevatedLost || phase == BrokerPhases.StopUnconfirmed)
                    {
                        return Reply(false, 0, phase == BrokerPhases.ElevatedLost ? BrokerCodes.ElevatedLost : BrokerCodes.StopUnconfirmed, "");
                    }
                }
                if (engine == null)
                {
                    return Reply(false, 0, UserFailure(), "");
                }
                string availability = TurnOnAvailability();
                if (availability != BrokerTurnOn.Available)
                {
                    return Reply(false, 0, availability, "");
                }

                // The user engine must hold a pairing and no tunnel.
                EngineAnswer status = engine.Request("GET", "/api/status", null, StatusTimeout);
                if (!status.IsOk)
                {
                    return Reply(false, status.Status, status.Reached ? BrokerCodes.BadResponse : status.Code, "");
                }
                EngineStatusSnapshot snapshot;
                if (!EngineStatusSnapshot.TryParse(status.Body, out snapshot) || snapshot.Demo)
                {
                    return Reply(false, 0, BrokerCodes.BadResponse, "");
                }
                if (!snapshot.Paired)
                {
                    return Reply(false, 0, BrokerCodes.NotPaired, "");
                }
                if (snapshot.IsRunning || snapshot.Health != EngineHealth.Normal)
                {
                    return Reply(false, 0, BrokerCodes.TunnelRunning, "");
                }

                lock (state)
                {
                    if (shuttingDown)
                    {
                        return Reply(false, 0, BrokerCodes.Closed, "");
                    }
                    phase = BrokerPhases.Starting;
                    elevatedStartSent = false;
                    lastElevatedStop = null;
                    lastElevatedStopMessage = null;
                }
                int port = EngineBrokerRules.PickPort();
                for (int attempt = 0; attempt < 8 && port == engine.Port; attempt++)
                {
                    port = EngineBrokerRules.PickPort();
                }
                ElevatedLaunchResult launched = ElevatedEngineLauncher.Launch(
                    root,
                    engine.HandoffReadHandle,
                    port,
                    ownerWindow,
                    delegate
                    {
                        return engine.Request("POST", "/api/pairing/handoff", EmptyObject, ActionTimeout).IsOk;
                    });
                if (launched.Engine == null)
                {
                    lock (state)
                    {
                        phase = BrokerPhases.Idle;
                    }
                    return Reply(false, 0, launched.Code, "");
                }

                ElevatedEngine started = launched.Engine;
                bool closing;
                lock (state)
                {
                    closing = shuttingDown;
                    if (!closing)
                    {
                        elevated = started;
                    }
                }
                if (closing)
                {
                    // The window closed during the prompt. The engine has no
                    // route yet; close it and report nothing started.
                    started.CloseAsync(TimeSpan.FromSeconds(15)).GetAwaiter().GetResult();
                    started.Release();
                    return Reply(false, 0, BrokerCodes.Closed, "");
                }
                if (!WaitForListener(started, TimeSpan.FromSeconds(15)))
                {
                    return AbortStart(started, BrokerCodes.ElevatedEngineFailed, 0, "", false);
                }
                lock (state)
                {
                    if (shuttingDown)
                    {
                        closing = true;
                    }
                    else
                    {
                        elevatedStartSent = true;
                    }
                }
                if (closing)
                {
                    return AbortStart(started, BrokerCodes.Closed, 0, "", false);
                }

                byte[] body = Encoding.ASCII.GetBytes(
                    "{\"mode\":\"phone\",\"options\":{\"experimental_icmp\":" + (ping ? "true" : "false") + "}}");
                EngineAnswer answer = started.Request("POST", "/api/start", body, StartTimeout);
                if (answer.IsOk)
                {
                    lock (state)
                    {
                        if (elevated == started)
                        {
                            phase = BrokerPhases.Elevated;
                        }
                    }
                    string trimmed;
                    string code;
                    Trim(answer.Body, BodyKind.Status, out trimmed, out code);
                    return Reply(true, answer.Status, BrokerCodes.None, trimmed ?? "");
                }
                string refusal;
                string ignored;
                if (!answer.Reached || !Trim(answer.Body, BodyKind.Plain, out refusal, out ignored))
                {
                    refusal = "";
                }
                return AbortStart(
                    started,
                    answer.Reached ? BrokerCodes.StartRefused : answer.Code,
                    answer.Status,
                    refusal,
                    true);
            }
            finally
            {
                actions.Release();
            }
        }

        // A refused or broken start. The elevated engine is asked to stop and
        // its exit is awaited. A status that shows a tunnel or a cleanup block
        // keeps the elevated engine as the status source, so the window shows
        // what the engine reports instead of a clean Off.
        private BrokerReply AbortStart(ElevatedEngine started, string code, int http, string body, bool startSent)
        {
            EngineAnswer status = started.Request("GET", "/api/status", null, StatusTimeout);
            EngineStatusSnapshot snapshot;
            bool clean = status.IsOk
                && EngineStatusSnapshot.TryParse(status.Body, out snapshot)
                && snapshot.Running == false
                && snapshot.Health == EngineHealth.Normal;
            if (!clean && status.Reached)
            {
                // The engine answers but reports a tunnel or an abnormal
                // state. It stays the status source, and Turn off stays
                // available to retry the stop.
                lock (state)
                {
                    phase = BrokerPhases.StopUnconfirmed;
                }
                return Reply(false, http, code, body);
            }
            bool exited = started.CloseAsync(TimeSpan.FromSeconds(15)).GetAwaiter().GetResult();
            lock (state)
            {
                if (elevated == started)
                {
                    elevated = null;
                }
                if (exited)
                {
                    started.Release();
                }
                else
                {
                    retiring = started;
                    retiringSinceUtc = DateTime.UtcNow;
                }
                // Before /api/start the engine changed no route. After it, an
                // engine that cannot be reached is a lost tunnel.
                phase = clean || !startSent ? BrokerPhases.Idle : BrokerPhases.ElevatedLost;
            }
            return Reply(false, http, code, body);
        }

        private static bool WaitForListener(ElevatedEngine engine, TimeSpan budget)
        {
            DateTime deadline = DateTime.UtcNow + budget;
            while (DateTime.UtcNow < deadline)
            {
                EngineAnswer answer = engine.Request("GET", "/api/status", null, StatusTimeout);
                if (answer.Reached)
                {
                    return answer.IsOk;
                }
                if (answer.Code != BrokerCodes.EngineStarting)
                {
                    return false;
                }
                Thread.Sleep(150);
            }
            return false;
        }

        // Stop the elevated tunnel. The stop is confirmed only when the
        // engine answers the stop, then reports running false with a normal
        // service state and no cleanup block. The broker then closes the
        // parent pipe and waits for the engine to exit. Anything else keeps
        // the elevated engine as the status source and reports an
        // unconfirmed stop.
        private BrokerReply TurnOff()
        {
            if (!actions.Wait(0))
            {
                return Reply(false, 0, BrokerCodes.Busy, "");
            }
            try
            {
                if (IsShuttingDown())
                {
                    return Reply(false, 0, BrokerCodes.Closed, "");
                }
                ElevatedEngine engine;
                lock (state)
                {
                    Reconcile();
                    engine = elevated;
                    if (engine == null)
                    {
                        if (phase == BrokerPhases.ElevatedLost)
                        {
                            return Reply(false, 0, BrokerCodes.ElevatedLost, "");
                        }
                        phase = BrokerPhases.Idle;
                        return Reply(true, 200, BrokerCodes.None, "{\"ok\":true}");
                    }
                    phase = BrokerPhases.Stopping;
                }
                EngineAnswer stop = engine.Request("POST", "/api/stop", EmptyObject, StopTimeout);
                EngineAnswer status = engine.Request("GET", "/api/status", null, StatusTimeout);
                EngineStatusSnapshot snapshot;
                bool confirmed = stop.IsOk
                    && status.IsOk
                    && EngineStatusSnapshot.TryParse(status.Body, out snapshot)
                    && snapshot.Running == false
                    && snapshot.Health == EngineHealth.Normal;
                if (!confirmed)
                {
                    lock (state)
                    {
                        Reconcile();
                        if (elevated != null)
                        {
                            phase = BrokerPhases.StopUnconfirmed;
                        }
                    }
                    return Reply(false, stop.Status, BrokerCodes.StopUnconfirmed, "");
                }
                bool exited = engine.CloseAsync(TimeSpan.FromSeconds(15)).GetAwaiter().GetResult();
                lock (state)
                {
                    elevated = null;
                    if (exited)
                    {
                        engine.Release();
                    }
                    else
                    {
                        // The tunnel is confirmed off. The process is still
                        // ending. Turn on waits until it exits.
                        retiring = engine;
                        retiringSinceUtc = DateTime.UtcNow;
                    }
                    phase = BrokerPhases.Idle;
                }
                return Reply(true, 200, BrokerCodes.None, "{\"ok\":true}");
            }
            finally
            {
                actions.Release();
            }
        }

        // Stop everything before the broker exits: the elevated tunnel first,
        // then the user engine. The broker never terminates an engine; each
        // one runs its own stop path when its parent pipe closes.
        //
        // The shuttingDown flag is set first, so an action that is still
        // running refuses its next engine call. Shutdown then waits a bounded
        // time for the action lock before it takes the engines. An action
        // that is past that bound still checks the flag under the state lock
        // before it keeps an engine, so no engine is started after this point.
        public void Shutdown()
        {
            lock (state)
            {
                shuttingDown = true;
            }
            bool owned = false;
            try
            {
                owned = actions.Wait(ShutdownActionWait);
            }
            catch (Exception)
            {
            }
            try
            {
                ElevatedEngine engine;
                ElevatedEngine old;
                UserEngine standard;
                lock (state)
                {
                    engine = elevated;
                    old = retiring;
                    standard = user;
                    elevated = null;
                    retiring = null;
                    user = null;
                }
                if (engine != null)
                {
                    StopElevatedForExit(engine);
                }
                if (old != null)
                {
                    old.CloseAsync(TimeSpan.FromSeconds(15)).GetAwaiter().GetResult();
                    old.Release();
                }
                if (standard != null)
                {
                    standard.CloseAsync(EngineLaunchTiming.HostClose).GetAwaiter().GetResult();
                    standard.Release();
                }
            }
            finally
            {
                if (owned)
                {
                    actions.Release();
                }
            }
        }

        // The confirmed-stop path for quit: ask the engine to stop and read
        // its status, then close the parent pipe and wait for the exit. An
        // unconfirmed stop still closes the pipe, which makes the engine run
        // its own stop path, and the wait is longer.
        private static void StopElevatedForExit(ElevatedEngine engine)
        {
            bool confirmed = false;
            try
            {
                EngineAnswer stop = engine.Request("POST", "/api/stop", EmptyObject, ShutdownStopTimeout);
                EngineAnswer status = engine.Request("GET", "/api/status", null, StatusTimeout);
                EngineStatusSnapshot snapshot;
                confirmed = stop.IsOk
                    && status.IsOk
                    && EngineStatusSnapshot.TryParse(status.Body, out snapshot)
                    && snapshot.Running == false
                    && snapshot.Health == EngineHealth.Normal;
            }
            catch (Exception)
            {
            }
            bool exited = engine.CloseAsync(TimeSpan.FromSeconds(confirmed ? 15 : 30)).GetAwaiter().GetResult();
            if (exited)
            {
                engine.Release();
            }
        }

        private bool IsShuttingDown()
        {
            lock (state)
            {
                return shuttingDown;
            }
        }

        private string UserFailure()
        {
            lock (state)
            {
                return userFailure.Length == 0 ? BrokerCodes.EngineUnavailable : userFailure;
            }
        }

        // Whether Turn on can work with this install. It never starts an
        // elevated process; it only checks the files and the engine build.
        private string TurnOnAvailability()
        {
            UserEngine engine;
            lock (state)
            {
                engine = user;
            }
            if (engine == null)
            {
                return UserFailure();
            }
            if (!File.Exists(Path.Combine(root, "Elevate", ElevationProtocol.StarterFileName))
                || !File.Exists(Path.Combine(root, "Engine", EngineLaunchRules.ExecutableName)))
            {
                return BrokerCodes.EngineMissing;
            }
            if (!File.Exists(Path.Combine(root, "Engine", "wintun.dll")))
            {
                return BrokerCodes.AdapterDllMissing;
            }
            // A text pre-filter only. The elevated starter verifies the final
            // path, owner, and DACL of the install before it trusts it.
            if (!InstallRules.IsPackageStorePath(root, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)))
            {
                return BrokerCodes.InstallUntrusted;
            }
            if (!engine.SupportsHandoff)
            {
                return BrokerCodes.HandoffUnsupported;
            }
            return BrokerTurnOn.Available;
        }

        private BrokerReply Reply(bool ok, int http, string code, string body)
        {
            string source;
            string current;
            lock (state)
            {
                Reconcile();
                source = elevated != null ? BrokerSources.Elevated : (user != null ? BrokerSources.User : BrokerSources.None);
                current = phase;
            }
            string turnOn = TurnOnAvailability();
            return new BrokerReply(ok, http, code, body, source, current, turnOn);
        }

        // Keep each reply inside the app-service message budget. The status
        // drops its log copy (the Activity page reads /api/logs). The logs
        // keep the newest lines. Every body must be one JSON object.
        private static bool Trim(string text, BodyKind kind, out string body, out string code)
        {
            body = null;
            code = BrokerCodes.None;
            JsonObject root;
            try
            {
                root = JsonNode.Parse(text) as JsonObject;
            }
            catch (JsonException)
            {
                root = null;
            }
            if (root == null)
            {
                code = BrokerCodes.BadResponse;
                return false;
            }
            if (kind == BodyKind.Status)
            {
                root.Remove("logs");
            }
            if (kind == BodyKind.Logs)
            {
                JsonArray logs = root["logs"] as JsonArray;
                if (logs != null)
                {
                    while (logs.Count > BrokerProtocol.MaxLogLines)
                    {
                        logs.RemoveAt(0);
                    }
                    string candidate = root.ToJsonString();
                    while (candidate.Length > BrokerProtocol.MaxBodyChars && logs.Count > 0)
                    {
                        logs.RemoveAt(0);
                        candidate = root.ToJsonString();
                    }
                }
            }
            string result = root.ToJsonString();
            if (result.Length > BrokerProtocol.MaxBodyChars)
            {
                code = BrokerCodes.ReplyTooLarge;
                return false;
            }
            body = result;
            return true;
        }
    }
}
