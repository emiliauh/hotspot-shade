using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost
{
    // Fixed limits for the Windows app boundary. The frame cap is the Windows
    // control plane cap, not the Unix privileged helper cap. The pipe buffer
    // holds one full frame and its length prefix.
    public static class EngineServiceTransportLimits
    {
        public const int MaxPipeInstances = 1;
        public const uint PipeBufferBytes = 131072;
        public const int MaxFrameBytes = EngineServiceFrame.MaxFrameBytes;
        public const int HandshakeTimeoutMilliseconds = 5000;
        public const int RequestTimeoutMilliseconds = 5000;

        // Boundary reads wait until this absolute monotonic idle deadline.
        // A first byte starts one RequestTimeout frame budget. Cancellation
        // completion proof and the subsequent stop add their own waits.
        public const int IdleTimeoutMilliseconds = 60000;

        // Reserved. Both values are documented design budgets, and neither is
        // enforced today. The guarded backend refuses every start and has no
        // reviewed launch seam, so there is no process wait to bound. The stop
        // path is bounded by StopTimeout on the session gate and by the host
        // StopBudget, not by this value. The remaining integration blocker is
        // an approved engine launch seam with a cancellable wait, plus a
        // process-identity proof for an exited engine. A test pins both as
        // reserved so enabling one is a deliberate, reviewed change.
        public const int StartTimeoutMilliseconds = 25000;
        public const int StopTimeoutMilliseconds = 15000;

        public static bool StartTimeoutEnforced
        {
            get { return false; }
        }

        public static bool StopTimeoutEnforced
        {
            get { return false; }
        }

        public const int ConnectTimeoutMilliseconds = 30000;
        public const int StartReadinessMilliseconds = 30000;
        public const int StatusFreshMilliseconds = 3000;
        public const int StatusMaxAgeMilliseconds = 3000;
        public const int ClockSkewMilliseconds = 2000;
        public const int AccountTypeLookupMilliseconds = 2000;
        public const int MaxEventRecords = 64;
        public const int MaxServicePathLength = 32767;
    }

    public enum EngineServiceHostState
    {
        // The values match the documented Win32 SERVICE_STATE values so a
        // future reviewed SCM adapter can map them without a second table.
        Stopped = 1,
        StartPending = 2,
        StopPending = 3,
        Running = 4,
        PausePending = 5,
        Paused = 6,
        ContinuePending = 7
    }

    public sealed class EngineServiceTransportOptions
    {
        public EngineServiceTransportOptions(
            string serviceInstanceId,
            string installedUserSid,
            string installedServiceBinaryPath,
            string engineImagePath)
        {
            if (!EngineProtocol.IsValidInstanceId(serviceInstanceId))
            {
                throw new ArgumentException("invalid service instance id", "serviceInstanceId");
            }
            if (!EngineServiceSidPolicy.IsUsableInstalledUserSid(installedUserSid))
            {
                throw new ArgumentException("the installed account is not an allowed user SID", "installedUserSid");
            }
            string normalizedServicePath;
            if (!WindowsServicePathPolicy.TryNormalize(installedServiceBinaryPath, out normalizedServicePath))
            {
                throw new ArgumentException("invalid installed service binary path", "installedServiceBinaryPath");
            }
            string normalizedEnginePath;
            if (!WindowsServicePathPolicy.TryNormalize(engineImagePath, out normalizedEnginePath))
            {
                throw new ArgumentException("invalid engine image path", "engineImagePath");
            }
            ServiceInstanceId = serviceInstanceId;
            InstalledUserSid = installedUserSid;
            InstalledServiceBinaryPath = normalizedServicePath;
            EngineImagePath = normalizedEnginePath;
            HandshakeTimeout = TimeSpan.FromMilliseconds(EngineServiceTransportLimits.HandshakeTimeoutMilliseconds);
            RequestTimeout = TimeSpan.FromMilliseconds(EngineServiceTransportLimits.RequestTimeoutMilliseconds);
            IdleTimeout = TimeSpan.FromMilliseconds(EngineServiceTransportLimits.IdleTimeoutMilliseconds);
            StartTimeout = TimeSpan.FromMilliseconds(EngineServiceTransportLimits.StartTimeoutMilliseconds);
            StopTimeout = TimeSpan.FromMilliseconds(EngineServiceTransportLimits.StopTimeoutMilliseconds);
            ConnectTimeout = TimeSpan.FromMilliseconds(EngineServiceTransportLimits.ConnectTimeoutMilliseconds);
            AccountTypeTimeout = TimeSpan.FromMilliseconds(EngineServiceTransportLimits.AccountTypeLookupMilliseconds);
        }

        public string ServiceInstanceId { get; private set; }

        public string InstalledUserSid { get; private set; }

        public string InstalledServiceBinaryPath { get; private set; }

        public string EngineImagePath { get; private set; }

        public TimeSpan HandshakeTimeout { get; set; }

        // Server reply writes and the fixed frame phase after its first byte.
        // A boundary wait uses the remaining IdleTimeout instead.
        public TimeSpan RequestTimeout { get; set; }

        // The absolute monotonic boundary budget credited after a validated
        // request completes processing and a successful reply, including hello.
        // Bytes, a reply alone, failed writes and observed cancellation cannot renew it.
        public TimeSpan IdleTimeout { get; set; }

        public TimeSpan StartTimeout { get; set; }

        public TimeSpan StopTimeout { get; set; }

        public TimeSpan ConnectTimeout { get; set; }

        public TimeSpan AccountTypeTimeout { get; set; }

        public void Validate()
        {
            RequirePositive(HandshakeTimeout, "HandshakeTimeout");
            RequirePositive(RequestTimeout, "RequestTimeout");
            RequirePositive(IdleTimeout, "IdleTimeout");
            RequirePositive(StartTimeout, "StartTimeout");
            RequirePositive(StopTimeout, "StopTimeout");
            RequirePositive(ConnectTimeout, "ConnectTimeout");
            RequirePositive(AccountTypeTimeout, "AccountTypeTimeout");
        }

        private static void RequirePositive(TimeSpan value, string name)
        {
            if (value <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(name);
            }
        }
    }

    // One fixed token for the service event record. A sink must not receive a
    // SID, path, process id, address, error message, or token.
    public interface IEngineServiceEventSink
    {
        void Record(string eventCode);
    }

    // The clean-thread stop seam. A stop action runs on a new thread that has
    // never impersonated. A failed or unverified revert does not use this
    // seam: it uses the fatal boundary and runs no stop on any impersonation
    // thread. A fake runs the action in the test.
    public interface IEngineServiceStopDispatcher
    {
        Task DispatchAsync(Action stopAction, CancellationToken cancellationToken);
    }

    // One caller token read after ImpersonateNamedPipeClient and
    // OpenThreadToken with OpenAsSelf.
    public interface IEngineServiceCallerToken : IDisposable
    {
        bool TryRead(out EngineServiceCallerIdentity identity, out string code);
    }

    // One server pipe instance. A server read uses the supplied monotonic
    // deadline. Every failed read closes the session, including proven Idle.
    // Expiry and transfer evidence are separate: Unknown never proves idle.
    // TryRevertToSelfAndVerify must prove the thread no longer holds a token.
    public interface IEngineServicePipeConnection : IDisposable
    {
        bool TryConnect(CancellationToken cancellationToken, out string code);

        bool TryReadFrame(
            EngineServiceReadDeadline deadline,
            CancellationToken cancellationToken,
            out byte[] frame,
            out EngineServiceFrameReadOutcome outcome,
            out string code);

        bool TryWriteFrame(byte[] frame, CancellationToken cancellationToken, out string code);

        bool TryImpersonateClient(out string code);

        bool TryOpenThreadToken(out IEngineServiceCallerToken token, out string code);

        bool TryRevertToSelfAndVerify(out string code);

        bool TryGetClientProcessId(out int processId);

        void Disconnect();
    }

    // The server pipe factory creates exactly one first instance. It returns
    // pipe_name_in_use and no fallback name when the name already exists.
    public interface IEngineServicePipeFactory
    {
        bool TryCreateFirstInstance(out IEngineServicePipeConnection pipe, out string code);
    }

    // What one request-frame write can prove about delivery.
    //
    // NotStarted means no kernel write operation ran, so no byte of the frame
    // reached the pipe. NotDelivered means every kernel write that ran
    // completed with a proven zero transfer, so no byte of the frame reached
    // the pipe. Unproven means a kernel write ran and may have delivered part
    // or all of the frame. Delivered means the whole frame was written.
    //
    // A caller must never report a clean refusal for Unproven. The request may
    // already have been applied, so the only safe recovery is a later status
    // read.
    public enum EngineServiceRequestWriteProof
    {
        NotStarted = 0,
        NotDelivered = 1,
        Unproven = 2,
        Delivered = 3
    }

    // A client pipe that reports the delivery evidence of one frame write. A
    // pipe that does not implement it gives no evidence, so the channel treats
    // every failed write that may have started as unproven.
    public interface IEngineServiceClientPipeWriteEvidence
    {
        bool TryWriteFrame(
            byte[] frame,
            TimeSpan budget,
            CancellationToken cancellationToken,
            out EngineServiceRequestWriteProof proof,
            out string code);
    }

    // One client pipe handle opened with the exact client mask.
    //
    // TryReadFrame reports the read outcome so a caller can tell a proven
    // zero-byte reply read from a reply read that consumed a byte or could not
    // prove a zero transfer. A caller must close the pipe for Partial,
    // Unknown, and Failed. It must never treat a Partial or Unknown reply read
    // as a clean refusal.
    //
    // TryWriteFrame reports only success. A pipe that can prove what a failed
    // write did implements IEngineServiceClientPipeWriteEvidence as well.
    public interface IEngineServiceClientPipe : IDisposable
    {
        bool TryReadFrame(
            TimeSpan budget,
            CancellationToken cancellationToken,
            out byte[] frame,
            out EngineServiceFrameReadOutcome outcome,
            out string code);

        bool TryWriteFrame(
            byte[] frame,
            TimeSpan budget,
            CancellationToken cancellationToken,
            out string code);

        bool TryGetServerProcessId(out int processId);

        bool TryGetOwnerSid(out string sid);
    }

    public interface IEngineServiceClientPipeFactory
    {
        bool TryOpen(out IEngineServiceClientPipe pipe, out string code);
    }

    public enum EngineServiceAccountType
    {
        Unknown = 0,
        User = 1,
        Group = 2,
        Domain = 3,
        Alias = 4,
        WellKnownGroup = 5,
        DeletedAccount = 6,
        Invalid = 7,
        Computer = 9,
        Label = 10,
        LogonSession = 11
    }

    public sealed class EngineServiceAccountTypeResult
    {
        private EngineServiceAccountTypeResult(bool ok, EngineServiceAccountType type, string code)
        {
            Ok = ok;
            Type = type;
            Code = code ?? "";
        }

        public bool Ok { get; private set; }

        public EngineServiceAccountType Type { get; private set; }

        public string Code { get; private set; }

        public static EngineServiceAccountTypeResult Success(EngineServiceAccountType type)
        {
            return new EngineServiceAccountTypeResult(true, type, "");
        }

        public static EngineServiceAccountTypeResult Failure(string code)
        {
            return new EngineServiceAccountTypeResult(false, EngineServiceAccountType.Unknown, code);
        }
    }

    public interface IEngineServiceAccountTypeInspector
    {
        Task<EngineServiceAccountTypeResult> InspectAsync(
            string sid,
            CancellationToken cancellationToken);
    }

    public sealed class EngineServiceScmState
    {
        public EngineServiceScmState(string serviceName, int processId, uint state, string binaryPath)
        {
            ServiceName = serviceName ?? "";
            ProcessId = processId;
            State = state;
            BinaryPath = binaryPath ?? "";
        }

        public string ServiceName { get; private set; }

        public int ProcessId { get; private set; }

        public uint State { get; private set; }

        public string BinaryPath { get; private set; }
    }

    public interface IEngineServiceScmInspector
    {
        bool TryQuery(out EngineServiceScmState state, out string code);
    }

    public interface IEngineServiceDurableStateStore
    {
        bool TryRead(out EngineServiceStateGate gate, out string code);
    }

    public interface IEngineServiceStatusSource
    {
        bool TryRead(
            DateTimeOffset now,
            out EngineServiceStatus status,
            out DateTimeOffset readAt,
            out string code);
    }

    public sealed class EngineServiceListenerResult
    {
        private EngineServiceListenerResult(
            bool ok,
            string code,
            EngineServiceCleanup cleanup,
            EngineServiceStopReason stopReason,
            int handledRequests,
            bool fatal)
        {
            Ok = ok;
            Code = EngineProtocol.IsKnownErrorCode(code) ? code : (ok ? "" : EngineProtocol.ErrorCodes.Internal);
            Cleanup = cleanup;
            StopReason = stopReason;
            HandledRequests = handledRequests;
            Fatal = fatal;
        }

        public bool Ok { get; private set; }

        public string Code { get; private set; }

        public EngineServiceCleanup Cleanup { get; private set; }

        public EngineServiceStopReason StopReason { get; private set; }

        public int HandledRequests { get; private set; }

        // True only after a failed or unverified caller revert. The host must
        // disable the generation and must not treat this as a clean stop.
        public bool Fatal { get; private set; }

        public static EngineServiceListenerResult Success(
            EngineServiceCleanup cleanup,
            EngineServiceStopReason stopReason,
            int handledRequests)
        {
            return new EngineServiceListenerResult(true, "", cleanup, stopReason, handledRequests, false);
        }

        public static EngineServiceListenerResult Failure(
            string code,
            EngineServiceCleanup cleanup,
            EngineServiceStopReason stopReason)
        {
            return new EngineServiceListenerResult(false, code, cleanup, stopReason, 0, false);
        }

        public static EngineServiceListenerResult FatalFailure(string code)
        {
            return new EngineServiceListenerResult(
                false,
                code,
                EngineServiceCleanup.Unknown,
                EngineServiceStopReason.None,
                0,
                true);
        }
    }

    public interface IEngineServiceListener : IDisposable
    {
        Task<EngineServiceListenerResult> RunAsync(CancellationToken cancellationToken);

        // Completes true only after the first pipe instance exists and the
        // listener can accept a client. The host must not report Running
        // before this task completes true. It completes false when the
        // listener can never become ready.
        Task<bool> Ready { get; }
    }

    public interface IEngineServiceListenerFactory
    {
        bool TryCreate(out IEngineServiceListener listener, out string code);
    }

    public interface IEngineServiceHostControl
    {
        void ReportState(EngineServiceHostState state, int checkpoint, TimeSpan waitHint);
    }

    public sealed class EngineServiceHostOptions
    {
        public EngineServiceHostOptions()
        {
            StartWaitHint = TimeSpan.FromSeconds(3);
            StartBudget = TimeSpan.FromMilliseconds(EngineServiceTransportLimits.StartReadinessMilliseconds);
            StopWaitHint = TimeSpan.FromSeconds(3);
            StopBudget = TimeSpan.FromSeconds(20);
            CheckpointInterval = TimeSpan.FromSeconds(1);
        }

        public TimeSpan StartWaitHint { get; set; }

        // The listener must prove readiness inside this budget. A listener
        // that never becomes ready is stopped and never reported Running.
        public TimeSpan StartBudget { get; set; }

        public TimeSpan StopWaitHint { get; set; }

        public TimeSpan StopBudget { get; set; }

        public TimeSpan CheckpointInterval { get; set; }

        public void Validate()
        {
            RequirePositive(StartWaitHint, "StartWaitHint");
            RequirePositive(StartBudget, "StartBudget");
            RequirePositive(StopWaitHint, "StopWaitHint");
            RequirePositive(StopBudget, "StopBudget");
            RequirePositive(CheckpointInterval, "CheckpointInterval");
        }

        private static void RequirePositive(TimeSpan value, string name)
        {
            if (value <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(name);
            }
        }
    }

    public sealed class EngineServiceHostResult
    {
        private EngineServiceHostResult(
            bool ok,
            string code,
            EngineServiceHostState finalState,
            bool autoRestarted,
            int stateReports,
            bool disabled)
        {
            Ok = ok;
            Code = EngineProtocol.IsKnownErrorCode(code) ? code : (ok ? "" : EngineProtocol.ErrorCodes.Internal);
            FinalState = finalState;
            AutoRestarted = autoRestarted;
            StateReports = stateReports;
            Disabled = disabled;
        }

        public bool Ok { get; private set; }

        public string Code { get; private set; }

        public EngineServiceHostState FinalState { get; private set; }

        // Always false. The host never restarts a listener or an engine.
        public bool AutoRestarted { get; private set; }

        public int StateReports { get; private set; }

        // True when a failed caller revert disabled this host generation. A
        // disabled host refuses every later start.
        public bool Disabled { get; private set; }

        public static EngineServiceHostResult Success(EngineServiceHostState finalState, int stateReports)
        {
            return new EngineServiceHostResult(true, "", finalState, false, stateReports, false);
        }

        public static EngineServiceHostResult Failure(
            string code,
            EngineServiceHostState finalState,
            int stateReports)
        {
            return new EngineServiceHostResult(false, code, finalState, false, stateReports, false);
        }

        public static EngineServiceHostResult DisabledFailure(
            string code,
            EngineServiceHostState finalState,
            int stateReports)
        {
            return new EngineServiceHostResult(false, code, finalState, false, stateReports, true);
        }
    }

    public static class EngineServicePlatform
    {
        public static bool IsWindows
        {
            get
            {
                return System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(
                    System.Runtime.InteropServices.OSPlatform.Windows);
            }
        }

        public static string PlatformEventCode
        {
            get { return IsWindows ? "" : EngineServiceEventCodes.PlatformNotWindows; }
        }
    }
}
