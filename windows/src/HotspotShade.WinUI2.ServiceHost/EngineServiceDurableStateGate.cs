using System;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost
{
    // The service start gate for the durable state record. The store is
    // injected and is not in this foundation. The core EngineServiceStateGate
    // is the loader: a missing, unreadable, damaged, or version-mismatched
    // record is cleanup_unknown. It never becomes a never-launched clean
    // record. A fresh install must write a never-launched record and load that
    // written record. This class adds the installed image binding.
    public sealed class EngineServiceDurableStateGate
    {
        private readonly IEngineServiceDurableStateStore store;
        private readonly IEngineServiceEventSink events;
        private readonly string engineImage;
        private readonly IEngineServiceProcessIdentityProof processProof;

        public EngineServiceDurableStateGate(
            IEngineServiceDurableStateStore store,
            IEngineServiceEventSink events,
            string engineImage,
            IEngineServiceProcessIdentityProof processProof)
        {
            if (store == null)
            {
                throw new ArgumentNullException("store");
            }
            if (events == null)
            {
                throw new ArgumentNullException("events");
            }
            string normalized;
            if (!WindowsServicePathPolicy.TryNormalize(engineImage, out normalized))
            {
                throw new ArgumentException("invalid engine image path", "engineImage");
            }
            this.store = store;
            this.events = events;
            this.engineImage = normalized;
            this.processProof = processProof;
        }

        public bool TryRead(out EngineServiceStateRecord record, out string code)
        {
            record = null;
            EngineServiceStateGate loaded;
            string storeCode;
            try
            {
                if (!store.TryRead(out loaded, out storeCode) || loaded == null)
                {
                    events.Record(EngineServiceEventCodes.StateReadFailed);
                    code = EngineProtocol.ErrorCodes.CleanupUnknown;
                    return false;
                }
            }
            catch (Exception)
            {
                events.Record(EngineServiceEventCodes.StateReadFailed);
                code = EngineProtocol.ErrorCodes.CleanupUnknown;
                return false;
            }

            if (!loaded.HasRecord || loaded.Record == null)
            {
                events.Record(EngineServiceEventCodes.StateReadFailed);
                code = EngineProtocol.ErrorCodes.CleanupUnknown;
                return false;
            }

            EngineServiceStateRecord candidate = loaded.Record;
            string validation;
            if (!candidate.Validate(out validation))
            {
                events.Record(EngineServiceEventCodes.StateReadFailed);
                code = EngineProtocol.ErrorCodes.CleanupUnknown;
                return false;
            }

            if (!string.Equals(candidate.EngineImage, engineImage, StringComparison.OrdinalIgnoreCase))
            {
                events.Record(EngineServiceEventCodes.StateImageMismatch);
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }

            string startCode;
            if (!loaded.CanStart(out startCode))
            {
                events.Record(EngineServiceEventCodes.StateStartRefused);
                code = EngineProtocol.IsKnownErrorCode(startCode)
                    ? startCode
                    : EngineProtocol.ErrorCodes.CleanupUnknown;
                return false;
            }

            // A clean stopped record still names the previous process. A pid
            // can be reused, so absence must be proven with the creation time.
            // This foundation has no real proof, so a stopped record fails
            // closed until a reviewed proof is supplied.
            if (candidate.Phase == EngineServicePhase.Stopped)
            {
                if (candidate.Pid <= 0
                    || candidate.Created100ns <= 0
                    || processProof == null)
                {
                    events.Record(EngineServiceEventCodes.StateProcessNotProven);
                    code = EngineProtocol.ErrorCodes.CleanupUnknown;
                    return false;
                }
                try
                {
                    string proofCode;
                    if (!processProof.TryProveGone(
                        candidate.Pid,
                        candidate.Created100ns,
                        out proofCode))
                    {
                        events.Record(EngineServiceEventCodes.StateProcessNotProven);
                        code = EngineProtocol.ErrorCodes.CleanupUnknown;
                        return false;
                    }
                }
                catch (Exception)
                {
                    events.Record(EngineServiceEventCodes.StateProcessNotProven);
                    code = EngineProtocol.ErrorCodes.CleanupUnknown;
                    return false;
                }
            }

            record = candidate;
            code = "";
            return true;
        }
    }
}
