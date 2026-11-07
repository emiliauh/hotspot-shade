using System;

namespace HotspotShade.WinUI2.ServiceHost
{
    public enum EngineServiceReadExpiry
    {
        None = 0,
        Boundary = 1,
        Frame = 2,
        Handshake = 3
    }

    // One absolute read deadline. Transfer evidence stays in the frame outcome;
    // expiry says only which budget ended, never how many bytes were consumed.
    public sealed class EngineServiceReadDeadline
    {
        private readonly IEngineServiceHostMonotonicClock clock;
        private readonly TimeSpan frameBudget;
        private readonly bool handshake;
        private long deadline;
        private bool firstByte;

        internal EngineServiceReadDeadline(
            IEngineServiceHostMonotonicClock clock,
            long boundaryDeadline,
            TimeSpan frameBudget,
            bool handshake)
        {
            if (clock == null || clock.Frequency <= 0)
            {
                throw new ArgumentException("invalid monotonic clock", "clock");
            }
            if (frameBudget <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException("frameBudget");
            }
            this.clock = clock;
            this.deadline = boundaryDeadline;
            this.frameBudget = frameBudget;
            this.handshake = handshake;
        }

        public EngineServiceReadExpiry Expiry { get; private set; }

        internal bool HasFirstByte { get { return firstByte; } }

        internal TimeSpan Remaining
        {
            get
            {
                long now = clock.Timestamp;
                return now >= deadline ? TimeSpan.Zero
                    : TimeSpan.FromSeconds(((double)deadline - now) / clock.Frequency);
            }
        }

        internal bool TryExpire()
        {
            if (clock.Timestamp < deadline)
            {
                return false;
            }
            Expiry = handshake ? EngineServiceReadExpiry.Handshake
                : firstByte ? EngineServiceReadExpiry.Frame : EngineServiceReadExpiry.Boundary;
            return true;
        }

        internal void ConsumedFirstByte()
        {
            if (!firstByte)
            {
                firstByte = true;
                if (!handshake)
                {
                    // Starts once. Further prefix or payload bytes cannot
                    // extend this frame's deadline.
                    deadline = CreateDeadline(clock, frameBudget);
                }
            }
        }

        internal static EngineServiceReadDeadline Handshake(
            IEngineServiceHostMonotonicClock clock, TimeSpan budget)
        {
            return new EngineServiceReadDeadline(clock, CreateDeadline(clock, budget), budget, true);
        }

        internal static long CreateDeadline(IEngineServiceHostMonotonicClock clock, TimeSpan budget)
        {
            long now = clock.Timestamp;
            double ticks = Math.Ceiling(budget.TotalSeconds * clock.Frequency);
            return ticks >= (double)long.MaxValue - now ? long.MaxValue : now + (long)ticks;
        }
    }
}
