using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost.Tests
{
    internal sealed class ServiceHostFakeClock : IEngineClock
    {
        public ServiceHostFakeClock(DateTimeOffset now)
        {
            Now = now;
        }

        public DateTimeOffset Now { get; set; }
    }

    internal sealed class ServiceHostFakeEvents : IEngineServiceEventSink
    {
        public List<string> Records = new List<string>();
        public List<int> ThreadIds = new List<int>();
        public List<bool> ThreadPoolFlags = new List<bool>();

        public void Record(string eventCode)
        {
            Records.Add(eventCode ?? "");
            ThreadIds.Add(Thread.CurrentThread.ManagedThreadId);
            ThreadPoolFlags.Add(Thread.CurrentThread.IsThreadPoolThread);
        }

        public bool Contains(string eventCode)
        {
            return Records.Contains(eventCode);
        }

        public string Last
        {
            get { return Records.Count == 0 ? "" : Records[Records.Count - 1]; }
        }

        public int LastThreadId
        {
            get { return ThreadIds.Count == 0 ? 0 : ThreadIds[ThreadIds.Count - 1]; }
        }

        public bool LastThreadPool
        {
            get { return ThreadPoolFlags.Count != 0 && ThreadPoolFlags[ThreadPoolFlags.Count - 1]; }
        }

        public int ThreadIdOf(string eventCode)
        {
            for (int index = 0; index < Records.Count; index++)
            {
                if (string.Equals(Records[index], eventCode, StringComparison.Ordinal))
                {
                    return ThreadIds[index];
                }
            }
            return 0;
        }
    }

    internal sealed class ServiceHostFakeDispatcher : IEngineServiceStopDispatcher
    {
        public int Calls;
        public Action LastAction;

        public Task DispatchAsync(Action stopAction, CancellationToken cancellationToken)
        {
            Calls++;
            LastAction = stopAction;
            stopAction();
            return Task.CompletedTask;
        }
    }

    internal sealed class ServiceHostBlockingCleanThreadRunner : IEngineServiceCleanThreadRunner
    {
        public int Calls;

        public Task<T> RunAsync<T>(Func<T> action, CancellationToken cancellationToken)
        {
            Calls++;
            TaskCompletionSource<T> completion =
                new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
            return completion.Task;
        }
    }

    // A test seam that starts the probe action on a separate thread and then
    // throws before it can return the completion task. The handshake cannot
    // prove whether the probe thread still runs, so it must fail closed and
    // keep the pipe open.
    internal sealed class ServiceHostThrowingCleanThreadRunner : IEngineServiceCleanThreadRunner
    {
        public readonly ManualResetEventSlim Started = new ManualResetEventSlim(false);
        public readonly ManualResetEventSlim Release = new ManualResetEventSlim(false);
        public int Calls;

        public Task<T> RunAsync<T>(Func<T> action, CancellationToken cancellationToken)
        {
            Calls++;
            Thread thread = new Thread(new ThreadStart(delegate
            {
                Started.Set();
                Release.Wait(5000);
                try
                {
                    action();
                }
                catch (Exception)
                {
                    // The test only needs the action to reach its checked
                    // revert. A probe result cannot be delivered without a
                    // task handle.
                }
            }));
            thread.IsBackground = true;
            thread.Start();
            if (!Started.Wait(2000))
            {
                throw new InvalidOperationException("the probe thread did not start");
            }
            throw new InvalidOperationException("the clean-thread runner lost the probe handle");
        }
    }

    // A monotonic clock seam for the host budgets. Production uses Stopwatch.
    // The fake can jump past a deadline and run one callback on a read so a
    // final completion recheck is deterministic.
    internal sealed class ServiceHostFakeMonotonicClock : IEngineServiceHostMonotonicClock
    {
        public long Now;
        public long TickFrequency = 1000;
        public Action OnRead;
        public long Reads;

        public long Timestamp
        {
            get
            {
                Reads++;
                Action action = OnRead;
                if (action != null)
                {
                    action();
                }
                return Now;
            }
        }

        public long Frequency
        {
            get { return TickFrequency; }
        }
    }

    // A test seam that holds the probe thread until the test releases it, then
    // runs the real probe action on a separate thread. It is a fake: it does
    // not impersonate, and the probe action still runs its checked revert.
    internal sealed class ServiceHostReleasableCleanThreadRunner : IEngineServiceCleanThreadRunner
    {
        public readonly ManualResetEventSlim Started = new ManualResetEventSlim(false);
        public readonly ManualResetEventSlim Release = new ManualResetEventSlim(false);
        public int Calls;

        public Task<T> RunAsync<T>(Func<T> action, CancellationToken cancellationToken)
        {
            Calls++;
            TaskCompletionSource<T> completion =
                new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
            Task.Run(delegate
            {
                Started.Set();
                Release.Wait(5000);
                try
                {
                    completion.TrySetResult(action());
                }
                catch (Exception error)
                {
                    completion.TrySetException(error);
                }
            });
            return completion.Task;
        }
    }

    internal sealed class ServiceHostFakeFatalBoundary : IEngineServiceFatalBoundary
    {
        public int Calls;
        public bool Result = true;
        public bool Throw;
        public int ThreadId;
        public bool ThreadPool;
        public string Code = "";

        public bool TryTerminateOrDisable(out string code)
        {
            Calls++;
            ThreadId = Thread.CurrentThread.ManagedThreadId;
            ThreadPool = Thread.CurrentThread.IsThreadPoolThread;
            if (Throw)
            {
                throw new InvalidOperationException("fatal boundary failed");
            }
            code = Code;
            return Result;
        }
    }

    internal sealed class ServiceHostFakeCallerToken : IEngineServiceCallerToken
    {
        public EngineServiceCallerIdentity Identity;
        public bool Fail;
        public string Code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
        public bool Disposed;
        public int Reads;

        public bool TryRead(out EngineServiceCallerIdentity identity, out string code)
        {
            Reads++;
            if (Fail || Identity == null)
            {
                identity = null;
                code = Code;
                return false;
            }
            identity = Identity;
            code = "";
            return true;
        }

        public void Dispose()
        {
            Disposed = true;
        }
    }

    internal sealed class ServiceHostFakeProcessProof : IEngineServiceProcessIdentityProof
    {
        public bool Gone = true;
        public bool Throw;
        public int Calls;
        public int LastProcessId;
        public long LastCreated100ns;

        public bool TryProveGone(int processId, long created100ns, out string code)
        {
            Calls++;
            LastProcessId = processId;
            LastCreated100ns = created100ns;
            if (Throw)
            {
                throw new InvalidOperationException("process proof failed");
            }
            code = Gone ? "" : EngineProtocol.ErrorCodes.CleanupUnknown;
            return Gone;
        }
    }

    internal sealed class ServiceHostFakeRecordedProcessProof : IEngineServiceRecordedProcessProof
    {
        public EngineServiceRecordedProcessState State = EngineServiceRecordedProcessState.Gone;
        public int Calls;
        public int LastProcessId;
        public long LastCreated100ns;

        public EngineServiceRecordedProcessState Check(
            int processId,
            long created100ns,
            out string code)
        {
            Calls++;
            LastProcessId = processId;
            LastCreated100ns = created100ns;
            code = State == EngineServiceRecordedProcessState.Gone
                ? ""
                : EngineProtocol.ErrorCodes.CleanupUnknown;
            return State;
        }
    }

    internal sealed class ServiceHostFakeBackend : IEngineServiceBackend, IEngineServiceCancellableBackend, IEngineServiceStopBoundary
    {
        public EngineServiceStatus Status;
        public int Starts;
        public int Stops;
        public EngineServiceStopReason LastStop = EngineServiceStopReason.None;
        public bool StartOk = true;
        public bool StopOk = true;
        public bool BlockStart;
        public bool BlockStop;
        public bool MarkStopThrows;
        // Optional shared ordering record. A check that cares about the stop
        // and pipe-dispose order supplies one list to both fakes. A null list
        // records nothing.
        public List<string> Order;
        public TaskCompletionSource<bool> StartEntered =
            new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<bool> ReleaseStart =
            new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<bool> StopEntered =
            new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<bool> ReleaseStop =
            new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        private int stopRequested;

        public ServiceHostFakeBackend(EngineServiceStatus status)
        {
            Status = status;
        }

        public EngineServiceStatus ReadStatus()
        {
            return Status;
        }

        public EngineServiceResult Start(bool ping)
        {
            Starts++;
            if (Volatile.Read(ref stopRequested) != 0)
            {
                return EngineServiceResult.Failure(EngineProtocol.ErrorCodes.Closed);
            }
            if (BlockStart)
            {
                StartEntered.TrySetResult(true);
                ReleaseStart.Task.Wait(3000);
            }
            if (Volatile.Read(ref stopRequested) != 0)
            {
                return EngineServiceResult.Failure(EngineProtocol.ErrorCodes.Closed);
            }
            return StartOk
                ? EngineServiceResult.Success()
                : EngineServiceResult.Failure(EngineProtocol.ErrorCodes.Unsupported);
        }

        public EngineServiceResult Start(bool ping, CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return EngineServiceResult.CleanupUnknown();
            }
            return Start(ping);
        }

        public EngineServiceResult Stop(EngineServiceStopReason reason)
        {
            Stops++;
            LastStop = reason;
            RecordOrder("backend_stop");
            if (BlockStop)
            {
                StopEntered.TrySetResult(true);
                ReleaseStop.Task.Wait(3000);
            }
            return StopOk
                ? EngineServiceResult.Success()
                : EngineServiceResult.Failure(EngineProtocol.ErrorCodes.EngineStopTimeout);
        }

        public EngineServiceResult Stop(
            EngineServiceStopReason reason,
            CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return EngineServiceResult.CleanupUnknown();
            }
            return Stop(reason);
        }

        public void MarkStopRequested()
        {
            if (MarkStopThrows)
            {
                throw new InvalidOperationException("stop boundary failed");
            }
            Interlocked.Exchange(ref stopRequested, 1);
        }

        private void RecordOrder(string step)
        {
            List<string> order = Order;
            if (order == null)
            {
                return;
            }
            lock (order)
            {
                order.Add(step);
            }
        }
    }

    internal sealed class ServiceHostFakePipe : IEngineServicePipeConnection
    {
        public Queue<byte[]> Inbound = new Queue<byte[]>();
        public List<byte[]> Written = new List<byte[]>();
        public List<string> Calls = new List<string>();
        public ServiceHostFakeCallerToken Token = new ServiceHostFakeCallerToken();
        public bool ConnectOk = true;
        public bool ImpersonateOk = true;
        public bool OpenTokenOk = true;
        public bool RevertOk = true;
        public bool RevertThrows;
        public bool WriteOk = true;
        public bool ClientProcessIdOk = true;
        public bool BlockReadUntilCancelled;
        public Action<EngineServiceReadDeadline> OnReadDeadline;
        public Action OnWrite;
        public Action OnClientProcessId;
        public string ReadCode = EngineProtocol.ErrorCodes.Timeout;
        public EngineServiceFrameReadOutcome ReadOutcome = EngineServiceFrameReadOutcome.Failed;
        public int ImpersonateThreadId;
        public int RevertThreadId;
        public bool ImpersonateThreadPool;
        public bool RevertThreadPool;
        public int DisconnectCalls;
        public int DisposeCalls;
        // Optional shared ordering record, set by a check that also sets it on
        // the fake backend.
        public List<string> Order;
        private int writtenCount;

        public int WrittenCount
        {
            get { return Volatile.Read(ref writtenCount); }
        }

        public bool TryConnect(CancellationToken cancellationToken, out string code)
        {
            Calls.Add("connect");
            code = ConnectOk ? "" : EngineProtocol.ErrorCodes.EngineUnavailable;
            return ConnectOk;
        }

        public bool TryReadFrame(
            EngineServiceReadDeadline deadline,
            CancellationToken cancellationToken,
            out byte[] frame,
            out EngineServiceFrameReadOutcome outcome,
            out string code)
        {
            Calls.Add("read");
            if (OnReadDeadline != null) { OnReadDeadline(deadline); }
            if (BlockReadUntilCancelled && Inbound.Count == 0)
            {
                cancellationToken.WaitHandle.WaitOne(2000);
                frame = null;
                outcome = EngineServiceFrameReadOutcome.Unknown;
                code = EngineProtocol.ErrorCodes.Timeout;
                return false;
            }
            if (Inbound.Count > 0)
            {
                frame = Inbound.Dequeue();
                outcome = EngineServiceFrameReadOutcome.Frame;
                code = "";
                return true;
            }
            frame = null;
            outcome = ReadOutcome;
            code = ReadCode;
            return false;
        }

        public bool TryWriteFrame(
            byte[] frame,
            CancellationToken cancellationToken,
            out string code)
        {
            Calls.Add("write");
            if (OnWrite != null) { OnWrite(); }
            if (WriteOk)
            {
                Written.Add((byte[])frame.Clone());
                Interlocked.Increment(ref writtenCount);
                code = "";
                return true;
            }
            code = EngineProtocol.ErrorCodes.EngineUnavailable;
            return false;
        }

        public bool TryImpersonateClient(out string code)
        {
            Calls.Add("impersonate");
            ImpersonateThreadId = Thread.CurrentThread.ManagedThreadId;
            ImpersonateThreadPool = Thread.CurrentThread.IsThreadPoolThread;
            code = ImpersonateOk ? "" : EngineProtocol.ErrorCodes.BoundaryAuthFailed;
            return ImpersonateOk;
        }

        public bool TryOpenThreadToken(out IEngineServiceCallerToken token, out string code)
        {
            Calls.Add("open_token");
            token = OpenTokenOk ? Token : null;
            code = OpenTokenOk ? "" : EngineProtocol.ErrorCodes.BoundaryAuthFailed;
            return OpenTokenOk;
        }

        public bool TryRevertToSelfAndVerify(out string code)
        {
            Calls.Add("revert");
            RevertThreadId = Thread.CurrentThread.ManagedThreadId;
            RevertThreadPool = Thread.CurrentThread.IsThreadPoolThread;
            if (RevertThrows)
            {
                throw new InvalidOperationException("revert failed");
            }
            code = RevertOk ? "" : EngineProtocol.ErrorCodes.EngineUnavailable;
            return RevertOk;
        }

        public bool TryGetClientProcessId(out int processId)
        {
            Calls.Add("client_pid");
            if (OnClientProcessId != null) { OnClientProcessId(); }
            processId = ClientProcessIdOk ? 4242 : 0;
            return ClientProcessIdOk;
        }

        public void Disconnect()
        {
            DisconnectCalls++;
        }

        public void Dispose()
        {
            DisposeCalls++;
            List<string> order = Order;
            if (order != null)
            {
                lock (order)
                {
                    order.Add("pipe_dispose");
                }
            }
        }
    }

    internal sealed class ServiceHostFakePipeFactory : IEngineServicePipeFactory
    {
        public IEngineServicePipeConnection Pipe;
        public bool CreateOk = true;
        public string Code = EngineProtocol.ErrorCodes.EngineUnavailable;
        public int Calls;

        public bool TryCreateFirstInstance(
            out IEngineServicePipeConnection pipe,
            out string code)
        {
            Calls++;
            pipe = CreateOk ? Pipe : null;
            code = CreateOk ? "" : Code;
            return CreateOk && pipe != null;
        }
    }

    internal sealed class ServiceHostFakeAccountInspector : IEngineServiceAccountTypeInspector
    {
        public EngineServiceAccountType Type = EngineServiceAccountType.User;
        public bool Fail;
        public bool WaitForCancellation;
        public int Calls;
        public Action OnInspect;

        public Task<EngineServiceAccountTypeResult> InspectAsync(
            string sid,
            CancellationToken cancellationToken)
        {
            Calls++;
            if (OnInspect != null) { OnInspect(); }
            if (WaitForCancellation)
            {
                return new TaskCompletionSource<EngineServiceAccountTypeResult>().Task;
            }
            if (Fail)
            {
                return Task.FromResult(EngineServiceAccountTypeResult.Failure(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed));
            }
            return Task.FromResult(EngineServiceAccountTypeResult.Success(Type));
        }
    }

    internal sealed class ServiceHostFakeScmInspector : IEngineServiceScmInspector
    {
        public EngineServiceScmState State;
        public Queue<EngineServiceScmState> States = new Queue<EngineServiceScmState>();
        public bool Ok = true;
        public string Code = EngineProtocol.ErrorCodes.EngineUnavailable;
        public int Calls;

        public bool TryQuery(out EngineServiceScmState state, out string code)
        {
            Calls++;
            if (Ok && States.Count > 0)
            {
                State = States.Dequeue();
            }
            state = Ok ? State : null;
            code = Ok ? "" : Code;
            return Ok && state != null;
        }
    }

    internal sealed class ServiceHostFakeClientPipe :
        IEngineServiceClientPipe,
        IEngineServiceClientPipeWriteEvidence
    {
        public Queue<byte[]> Responses = new Queue<byte[]>();
        public List<byte[]> Writes = new List<byte[]>();
        public List<string> Calls = new List<string>();
        public int ServerProcessId = 700;
        public string OwnerSid = EngineServiceBoundary.SystemSid;
        public bool ReadOk = true;
        public bool WriteOk = true;
        public bool DisposeCalled;
        public EngineServiceFrameReadOutcome ReadOutcome =
            EngineServiceFrameReadOutcome.Failed;
        public EngineServiceRequestWriteProof WriteProof =
            EngineServiceRequestWriteProof.Unproven;
        public string ReadCode = EngineProtocol.ErrorCodes.EngineUnavailable;
        public string WriteCode = EngineProtocol.ErrorCodes.EngineUnavailable;
        public TimeSpan LastReadBudget;
        public TimeSpan LastWriteBudget;
        public bool ReadWaitsForCancellation;
        public ManualResetEventSlim ReadEntered;
        public ManualResetEventSlim ReadGate;
        public Action OnRead;
        public Action OnWrite;

        public bool TryReadFrame(
            TimeSpan budget,
            CancellationToken cancellationToken,
            out byte[] frame,
            out EngineServiceFrameReadOutcome outcome,
            out string code)
        {
            Calls.Add("read");
            LastReadBudget = budget;
            Action onRead = OnRead;
            if (onRead != null)
            {
                onRead();
            }
            ManualResetEventSlim entered = ReadEntered;
            if (entered != null)
            {
                entered.Set();
            }
            ManualResetEventSlim gate = ReadGate;
            if (gate != null)
            {
                gate.Wait(5000);
            }
            if (budget <= TimeSpan.Zero)
            {
                frame = null;
                outcome = EngineServiceFrameReadOutcome.Failed;
                code = EngineProtocol.ErrorCodes.Timeout;
                return false;
            }
            if (ReadWaitsForCancellation)
            {
                cancellationToken.WaitHandle.WaitOne(2000);
                frame = null;
                outcome = EngineServiceFrameReadOutcome.Unknown;
                code = EngineProtocol.ErrorCodes.Timeout;
                return false;
            }
            if (ReadOk && Responses.Count > 0)
            {
                frame = Responses.Dequeue();
                outcome = EngineServiceFrameReadOutcome.Frame;
                code = "";
                return true;
            }
            frame = null;
            outcome = ReadOutcome;
            code = ReadCode;
            return false;
        }

        public bool TryWriteFrame(
            byte[] frame,
            TimeSpan budget,
            CancellationToken cancellationToken,
            out string code)
        {
            EngineServiceRequestWriteProof ignoredProof;
            return TryWriteFrame(
                frame,
                budget,
                cancellationToken,
                out ignoredProof,
                out code);
        }

        public bool TryWriteFrame(
            byte[] frame,
            TimeSpan budget,
            CancellationToken cancellationToken,
            out EngineServiceRequestWriteProof proof,
            out string code)
        {
            Calls.Add("write");
            LastWriteBudget = budget;
            Action onWrite = OnWrite;
            if (onWrite != null)
            {
                onWrite();
            }
            if (budget <= TimeSpan.Zero)
            {
                proof = EngineServiceRequestWriteProof.NotStarted;
                code = EngineProtocol.ErrorCodes.Timeout;
                return false;
            }
            if (WriteOk)
            {
                Writes.Add(frame);
                proof = EngineServiceRequestWriteProof.Delivered;
                code = "";
                return true;
            }
            proof = WriteProof;
            code = WriteCode;
            return false;
        }

        public bool TryGetServerProcessId(out int processId)
        {
            Calls.Add("server_pid");
            processId = ServerProcessId;
            return ServerProcessId > 0;
        }

        public bool TryGetOwnerSid(out string sid)
        {
            Calls.Add("owner_sid");
            sid = OwnerSid;
            return !string.IsNullOrEmpty(OwnerSid);
        }

        public void Dispose()
        {
            DisposeCalled = true;
        }
    }

    internal sealed class ServiceHostFakeClientPipeFactory : IEngineServiceClientPipeFactory
    {
        public IEngineServiceClientPipe Pipe;
        public bool OpenOk = true;
        public string Code = EngineProtocol.ErrorCodes.EngineUnavailable;
        public int Calls;

        public bool TryOpen(out IEngineServiceClientPipe pipe, out string code)
        {
            Calls++;
            pipe = OpenOk ? Pipe : null;
            code = OpenOk ? "" : Code;
            return OpenOk && pipe != null;
        }
    }

    internal sealed class ServiceHostFakeStateStore : IEngineServiceDurableStateStore
    {
        public EngineServiceStateGate Gate = EngineServiceStateGate.Missing;
        public bool Ok = true;
        public bool Throw;
        public int Calls;

        public bool TryRead(out EngineServiceStateGate gate, out string code)
        {
            Calls++;
            if (Throw)
            {
                throw new InvalidOperationException("store failed");
            }
            gate = Gate ?? EngineServiceStateGate.Missing;
            code = Ok ? "" : EngineProtocol.ErrorCodes.CleanupUnknown;
            return Ok;
        }
    }

    internal sealed class ServiceHostFakeStatusSource : IEngineServiceStatusSource
    {
        public EngineServiceStatus Status;
        public DateTimeOffset ReadAt = ServiceHostTestData.Now();
        public bool Ok = true;
        public bool Throw;
        public int Calls;

        public bool TryRead(
            DateTimeOffset now,
            out EngineServiceStatus status,
            out DateTimeOffset readAt,
            out string code)
        {
            Calls++;
            if (Throw)
            {
                throw new InvalidOperationException("status failed");
            }
            status = Ok ? Status : null;
            readAt = ReadAt;
            code = Ok ? "" : EngineProtocol.ErrorCodes.EngineUnavailable;
            return Ok && status != null;
        }
    }

    internal sealed class ServiceHostStateReport
    {
        public EngineServiceHostState State;
        public int Checkpoint;
        public TimeSpan WaitHint;
    }

    internal sealed class ServiceHostFakeHostControl : IEngineServiceHostControl
    {
        public List<ServiceHostStateReport> Reports = new List<ServiceHostStateReport>();
        public Action<EngineServiceHostState> Observer;

        public void ReportState(
            EngineServiceHostState state,
            int checkpoint,
            TimeSpan waitHint)
        {
            ServiceHostStateReport report = new ServiceHostStateReport();
            report.State = state;
            report.Checkpoint = checkpoint;
            report.WaitHint = waitHint;
            Reports.Add(report);
            if (Observer != null)
            {
                Observer(state);
            }
        }

        public int Count(EngineServiceHostState state)
        {
            int count = 0;
            for (int index = 0; index < Reports.Count; index++)
            {
                if (Reports[index].State == state)
                {
                    count++;
                }
            }
            return count;
        }
    }

    internal sealed class ServiceHostFakeListener : IEngineServiceListener
    {
        public TaskCompletionSource<EngineServiceListenerResult> Completion =
            new TaskCompletionSource<EngineServiceListenerResult>(
                TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<bool> ReadyCompletion =
            new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool AutoReady = true;
        public bool DisposeCalled;
        public int RunCalls;

        public Task<bool> Ready
        {
            get { return ReadyCompletion.Task; }
        }

        public bool IsReady
        {
            get
            {
                return ReadyCompletion.Task.Status == TaskStatus.RanToCompletion
                    && ReadyCompletion.Task.Result;
            }
        }

        public Task<EngineServiceListenerResult> RunAsync(CancellationToken cancellationToken)
        {
            RunCalls++;
            if (AutoReady)
            {
                ReadyCompletion.TrySetResult(true);
            }
            return Completion.Task;
        }

        public void Complete(EngineServiceListenerResult result)
        {
            Completion.TrySetResult(result);
        }

        public void MarkReady()
        {
            ReadyCompletion.TrySetResult(true);
        }

        public void MarkNeverReady()
        {
            ReadyCompletion.TrySetResult(false);
        }

        public void Dispose()
        {
            DisposeCalled = true;
            ReadyCompletion.TrySetResult(false);
        }
    }

    internal sealed class ServiceHostFakeListenerFactory : IEngineServiceListenerFactory
    {
        public ServiceHostFakeListener Listener;
        public bool CreateOk = true;
        public string Code = EngineProtocol.ErrorCodes.EngineUnavailable;
        public int Calls;

        public bool TryCreate(out IEngineServiceListener listener, out string code)
        {
            Calls++;
            listener = CreateOk ? Listener : null;
            code = CreateOk ? "" : Code;
            return CreateOk && listener != null;
        }
    }

    internal static class ServiceHostTestData
    {
        public const string UserSid = "S-1-5-21-1111111111-2222222222-3333333333-1001";
        public const string GroupSid = "S-1-5-21-1111111111-2222222222-3333333333-512";
        public const string ServiceInstance = "service-0001";
        public const string Session = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        public const string EngineImage = "C:\\Program Files\\HotspotShade\\hotspotshade.exe";
        public const string ServiceImage = "C:\\Program Files\\HotspotShade\\HotspotShadeEngineSvc.exe";
        public const string ServiceCommand = "\"" + ServiceImage + "\" --instance sample";
        public const string AdapterGuid = "00112233-4455-6677-8899-aabbccddeeff";

        public static DateTimeOffset Now()
        {
            return DateTimeOffset.FromUnixTimeSeconds(1762344000);
        }

        public static string Unix(DateTimeOffset value)
        {
            return value.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        }

        public static EngineServiceStatus ReadyStatus(DateTimeOffset now)
        {
            Dictionary<string, string> fields = BaseStatusFields();
            fields[EngineServiceStatusKeys.Engine] = "ready";
            fields[EngineServiceStatusKeys.Running] = "0";
            fields[EngineServiceStatusKeys.Paired] = "1";
            fields[EngineServiceStatusKeys.PairedScope] = "session";
            fields[EngineServiceStatusKeys.Source] = "1";
            fields[EngineServiceStatusKeys.CheckedAt] = Unix(now);
            fields[EngineServiceStatusKeys.Cleanup] = "ok";
            return ParseStatus(fields, now);
        }

        public static EngineServiceStatus RunningStatus(DateTimeOffset now)
        {
            Dictionary<string, string> fields = BaseStatusFields();
            fields[EngineServiceStatusKeys.Engine] = "running";
            fields[EngineServiceStatusKeys.Running] = "1";
            fields[EngineServiceStatusKeys.Paired] = "1";
            fields[EngineServiceStatusKeys.PairedScope] = "identity";
            fields[EngineServiceStatusKeys.Source] = "1";
            fields[EngineServiceStatusKeys.Trusted] = "1";
            fields[EngineServiceStatusKeys.CheckedAt] = Unix(now);
            fields[EngineServiceStatusKeys.PhoneConnections] = "3";
            fields[EngineServiceStatusKeys.PhoneConnectionsKnown] = "1";
            fields[EngineServiceStatusKeys.RelayTcpFlowsActive] = "7";
            fields[EngineServiceStatusKeys.RelayTcpFlowsActiveKnown] = "1";
            fields[EngineServiceStatusKeys.Cleanup] = "unknown";
            return ParseStatus(fields, now);
        }

        public static EngineServiceStatus CleanupFailedStatus(DateTimeOffset now)
        {
            Dictionary<string, string> fields = BaseStatusFields();
            fields[EngineServiceStatusKeys.Engine] = "unavailable";
            fields[EngineServiceStatusKeys.Running] = "0";
            fields[EngineServiceStatusKeys.Cleanup] = "failed";
            fields[EngineServiceStatusKeys.Stop] = "user";
            fields[EngineServiceStatusKeys.StopAt] = Unix(now);
            return ParseStatus(fields, now);
        }

        public static EngineServiceStatus ParseStatus(
            Dictionary<string, string> fields,
            DateTimeOffset now)
        {
            EngineServiceStatus status;
            string code;
            if (!EngineServiceStatus.TryParse(fields, now, out status, out code))
            {
                throw new InvalidOperationException("status fixture failed: " + code);
            }
            return status;
        }

        public static Dictionary<string, string> BaseStatusFields()
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields[EngineServiceStatusKeys.Version] = "1";
            fields[EngineServiceStatusKeys.Instance] = ServiceInstance;
            fields[EngineServiceStatusKeys.Engine] = "ready";
            fields[EngineServiceStatusKeys.Running] = "0";
            fields[EngineServiceStatusKeys.Mode] = "phone";
            fields[EngineServiceStatusKeys.Paired] = "0";
            fields[EngineServiceStatusKeys.PairedScope] = "none";
            fields[EngineServiceStatusKeys.Source] = "0";
            fields[EngineServiceStatusKeys.Trusted] = "0";
            fields[EngineServiceStatusKeys.CheckedAt] = "";
            fields[EngineServiceStatusKeys.Ping] = "1";
            fields[EngineServiceStatusKeys.IcmpEnabled] = "0";
            fields[EngineServiceStatusKeys.PhoneConnections] = "";
            fields[EngineServiceStatusKeys.PhoneConnectionsKnown] = "0";
            fields[EngineServiceStatusKeys.RelayTcpFlowsActive] = "";
            fields[EngineServiceStatusKeys.RelayTcpFlowsActiveKnown] = "0";
            fields[EngineServiceStatusKeys.TtlBad] = "0";
            fields[EngineServiceStatusKeys.Ipv6Dropped] = "0";
            fields[EngineServiceStatusKeys.FragmentsDropped] = "0";
            fields[EngineServiceStatusKeys.Stop] = "none";
            fields[EngineServiceStatusKeys.StopAt] = "";
            fields[EngineServiceStatusKeys.Cleanup] = "ok";
            fields[EngineServiceStatusKeys.Admin] = "0";
            return fields;
        }

        public static EngineServiceStateRecord CleanRecord(DateTimeOffset now)
        {
            return EngineServiceStateRecord.CreateNeverLaunched(now, EngineImage);
        }

        public static EngineServiceStateRecord RunningRecord(DateTimeOffset now)
        {
            return CleanRecord(now)
                .BeginLaunch("intent-0001", new string('a', 64), "HotspotShade-test-1", AdapterGuid, 123, now)
                .MarkLaunched(1234, 5678, now)
                .MarkAdapterReady(42, AdapterGuid, now)
                .MarkRunning(now);
        }

        public static EngineServiceStateRecord CleanStoppedRecord(DateTimeOffset now)
        {
            return RunningRecord(now)
                .BeginStopping(now)
                .MarkStopped(EngineServiceStopReason.User, EngineServiceCleanup.Ok, now);
        }

        public static EngineServiceStateRecord CleanupFailedRecord(DateTimeOffset now)
        {
            return RunningRecord(now)
                .BeginStopping(now)
                .MarkStopped(EngineServiceStopReason.User, EngineServiceCleanup.Failed, now);
        }

        public static EngineServiceStateRecord CleanupUnknownRecord(DateTimeOffset now)
        {
            return RunningRecord(now)
                .BeginStopping(now)
                .MarkStopped(EngineServiceStopReason.User, EngineServiceCleanup.Unknown, now);
        }

        public static EngineServiceStateRecord CleanupPendingRecord(DateTimeOffset now)
        {
            return RunningRecord(now).BeginStopping(now);
        }

        public static Dictionary<string, string> HelloFields()
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields[EngineProtocol.Keys.Version] = "1";
            fields[EngineProtocol.Keys.Operation] = EngineProtocol.Operations.Hello;
            fields[EngineProtocol.Keys.Session] = Session;
            return fields;
        }

        public static Dictionary<string, string> StatusRequestFields()
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields[EngineProtocol.Keys.Version] = "1";
            fields[EngineProtocol.Keys.Operation] = EngineProtocol.Operations.Status;
            fields[EngineProtocol.Keys.Session] = Session;
            return fields;
        }

        public static Dictionary<string, string> StartFields(bool ping)
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields[EngineProtocol.Keys.Version] = "1";
            fields[EngineProtocol.Keys.Operation] = EngineProtocol.Operations.Start;
            fields[EngineProtocol.Keys.Session] = Session;
            fields[EngineProtocol.Keys.Ping] = ping ? "1" : "0";
            return fields;
        }

        public static Dictionary<string, string> StopFields()
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields[EngineProtocol.Keys.Version] = "1";
            fields[EngineProtocol.Keys.Operation] = EngineProtocol.Operations.Stop;
            fields[EngineProtocol.Keys.Session] = Session;
            return fields;
        }

        public static byte[] Encode(IReadOnlyDictionary<string, string> fields)
        {
            byte[] frame;
            string code;
            if (!EngineServiceFrame.TryEncode(fields, out frame, out code))
            {
                throw new InvalidOperationException("frame fixture failed: " + code);
            }
            return frame;
        }

        public static EngineServiceTransportOptions TransportOptions()
        {
            return new EngineServiceTransportOptions(
                ServiceInstance,
                UserSid,
                ServiceImage,
                EngineImage);
        }
    }
}
