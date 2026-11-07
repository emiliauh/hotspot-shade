using System;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost
{
    // The app-side proof of the service. It requires all of:
    //   - the service is running and the SCM reports a process id,
    //   - the service binary path matches the installed path compiled into
    //     the app,
    //   - the connected pipe server process id equals the SCM process id,
    //   - the pipe owner is SYSTEM,
    //   - a re-query after the exchange still reports the same running service.
    //
    // Any inconclusive step fails closed. No frame is sent after a failure.
    public sealed class EngineServiceServerProof
    {
        private const uint ServiceRunning = 4;

        private readonly IEngineServiceScmInspector scm;
        private readonly IEngineServiceEventSink events;
        private readonly string installedServiceBinaryPath;

        public EngineServiceServerProof(
            IEngineServiceScmInspector scm,
            IEngineServiceEventSink events,
            string installedServiceBinaryPath)
        {
            if (scm == null)
            {
                throw new ArgumentNullException("scm");
            }
            if (events == null)
            {
                throw new ArgumentNullException("events");
            }
            string normalized;
            if (!WindowsServicePathPolicy.TryNormalize(installedServiceBinaryPath, out normalized))
            {
                throw new ArgumentException(
                    "invalid installed service binary path",
                    "installedServiceBinaryPath");
            }
            this.scm = scm;
            this.events = events;
            this.installedServiceBinaryPath = normalized;
        }

        public string InstalledServiceBinaryPath
        {
            get { return installedServiceBinaryPath; }
        }

        public bool TryVerifyBeforeConnect(out int serviceProcessId, out string code)
        {
            serviceProcessId = 0;
            EngineServiceScmState state;
            string queryCode;
            try
            {
                if (!scm.TryQuery(out state, out queryCode))
                {
                    events.Record(EngineServiceEventCodes.ServerQueryFailed);
                    code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                    return false;
                }
            }
            catch (Exception)
            {
                events.Record(EngineServiceEventCodes.ServerQueryFailed);
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }

            if (state == null
                || state.State != ServiceRunning
                || state.ProcessId <= 0
                || !string.Equals(state.ServiceName, EngineServiceBoundary.ServiceName, StringComparison.Ordinal))
            {
                events.Record(EngineServiceEventCodes.ServerNotRunning);
                code = EngineProtocol.ErrorCodes.EngineUnavailable;
                return false;
            }
            string scmExecutable;
            if (!WindowsServicePathPolicy.TryScmExecutable(state.BinaryPath, out scmExecutable)
                || !WindowsServicePathPolicy.EqualsInstalled(scmExecutable, installedServiceBinaryPath))
            {
                events.Record(EngineServiceEventCodes.ServerPathMismatch);
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }

            serviceProcessId = state.ProcessId;
            code = "";
            return true;
        }

        public bool TryVerifyConnectedServer(
            IEngineServiceClientPipe pipe,
            int expectedServiceProcessId,
            out string code)
        {
            if (pipe == null || expectedServiceProcessId <= 0)
            {
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }

            int serverProcessId;
            try
            {
                if (!pipe.TryGetServerProcessId(out serverProcessId)
                    || serverProcessId != expectedServiceProcessId)
                {
                    events.Record(EngineServiceEventCodes.ServerProcessMismatch);
                    code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                    return false;
                }
            }
            catch (Exception)
            {
                events.Record(EngineServiceEventCodes.ServerProcessMismatch);
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }

            string ownerSid;
            try
            {
                if (!pipe.TryGetOwnerSid(out ownerSid)
                    || !string.Equals(
                        ownerSid,
                        EngineServiceBoundary.SystemSid,
                        StringComparison.OrdinalIgnoreCase))
                {
                    events.Record(EngineServiceEventCodes.ServerOwnerMismatch);
                    code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                    return false;
                }
            }
            catch (Exception)
            {
                events.Record(EngineServiceEventCodes.ServerOwnerMismatch);
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }

            code = "";
            return true;
        }

        public bool TryVerifyAfterExchange(int expectedServiceProcessId, out string code)
        {
            EngineServiceScmState state;
            try
            {
                if (!scm.TryQuery(out state, out code))
                {
                    events.Record(EngineServiceEventCodes.ServerRecheckFailed);
                    code = EngineProtocol.ErrorCodes.EngineUnavailable;
                    return false;
                }
            }
            catch (Exception)
            {
                events.Record(EngineServiceEventCodes.ServerRecheckFailed);
                code = EngineProtocol.ErrorCodes.EngineUnavailable;
                return false;
            }

            if (state == null
                || state.State != ServiceRunning
                || state.ProcessId != expectedServiceProcessId
                || !string.Equals(state.ServiceName, EngineServiceBoundary.ServiceName, StringComparison.Ordinal))
            {
                events.Record(EngineServiceEventCodes.ServerRecheckFailed);
                code = EngineProtocol.ErrorCodes.EngineUnavailable;
                return false;
            }
            code = "";
            return true;
        }
    }
}
