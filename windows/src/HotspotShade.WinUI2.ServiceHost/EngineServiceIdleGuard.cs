using System;

namespace HotspotShade.WinUI2.ServiceHost
{
    // A fully decoded and validated request earns one fresh boundary interval
    // only after its processing and successful reply, with no stop requested.
    // Backend work has no idle credit in progress. Further reads share the
    // resulting absolute deadline; bytes and replies alone cannot renew it.
    internal sealed class EngineServiceIdleGuard
    {
        private readonly IEngineServiceHostMonotonicClock clock;
        private readonly TimeSpan budget;
        private long deadline;

        public EngineServiceIdleGuard(IEngineServiceHostMonotonicClock clock, TimeSpan budget)
        {
            if (clock == null || clock.Frequency <= 0)
            {
                throw new ArgumentException("invalid monotonic clock", "clock");
            }
            if (budget <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException("budget");
            }
            this.clock = clock;
            this.budget = budget;
            // No boundary credit before hello completes. The handshake uses
            // its own fixed budget and never reads this deadline.
            deadline = clock.Timestamp;
        }

        public void MarkRequestCompleted()
        {
            deadline = EngineServiceReadDeadline.CreateDeadline(clock, budget);
        }

        public EngineServiceReadDeadline CreateReadDeadline(TimeSpan frameBudget)
        {
            return new EngineServiceReadDeadline(clock, deadline, frameBudget, false);
        }
    }
}
