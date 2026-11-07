using System;

namespace HotspotShade.WinUI2.Core.Engine.Service
{
    // One app-side call budget per operation.
    //
    // The service start path can take the full service start budget, so one
    // short client budget for every operation aborts a start that the service
    // is still completing. A start and a stop therefore get their own budget.
    // Every other operation is answered from the in-memory session state and
    // gets the short budget.
    //
    // The client budgets must exceed the matching service budgets
    // (EngineServiceTransportLimits.StartTimeout and StopTimeout) plus one
    // short budget for the connect, the server proof, and the reply write. A
    // service host check pins that relationship so the two tables cannot
    // drift apart silently.
    //
    // A budget is a bound, not a promise. An operation that reaches the
    // budget is an ambiguous outcome: the request may already be applied. The
    // client reports that through EngineReply.OutcomeUnknown and never
    // reports the operation as applied.
    public sealed class EngineServiceCallBudgets
    {
        public const int ShortMilliseconds = 5000;
        public const int StartMilliseconds = 35000;
        public const int StopMilliseconds = 25000;

        private readonly TimeSpan shortBudget;
        private readonly TimeSpan startBudget;
        private readonly TimeSpan stopBudget;

        private EngineServiceCallBudgets(
            TimeSpan shortBudget,
            TimeSpan startBudget,
            TimeSpan stopBudget)
        {
            RequirePositive(shortBudget, "shortBudget");
            RequirePositive(startBudget, "startBudget");
            RequirePositive(stopBudget, "stopBudget");
            this.shortBudget = shortBudget;
            this.startBudget = startBudget;
            this.stopBudget = stopBudget;
        }

        // The reviewed defaults. A start and a stop outlive the service budget
        // they wait for; every other operation is answered in memory.
        public static EngineServiceCallBudgets Default
        {
            get
            {
                return new EngineServiceCallBudgets(
                    TimeSpan.FromMilliseconds(ShortMilliseconds),
                    TimeSpan.FromMilliseconds(StartMilliseconds),
                    TimeSpan.FromMilliseconds(StopMilliseconds));
            }
        }

        // One explicit table. Every value must be positive. Tests and a later
        // settings surface use it; production uses Default.
        public static EngineServiceCallBudgets Create(
            TimeSpan shortBudget,
            TimeSpan startBudget,
            TimeSpan stopBudget)
        {
            return new EngineServiceCallBudgets(shortBudget, startBudget, stopBudget);
        }

        // One budget for every operation. This is the diagnostic and test
        // form. It is not the reviewed production table.
        public static EngineServiceCallBudgets Uniform(TimeSpan budget)
        {
            return new EngineServiceCallBudgets(budget, budget, budget);
        }

        public TimeSpan ShortBudget
        {
            get { return shortBudget; }
        }

        public TimeSpan StartBudget
        {
            get { return startBudget; }
        }

        public TimeSpan StopBudget
        {
            get { return stopBudget; }
        }

        public TimeSpan For(string operation)
        {
            if (operation == EngineProtocol.Operations.Start)
            {
                return startBudget;
            }
            if (operation == EngineProtocol.Operations.Stop)
            {
                return stopBudget;
            }
            return shortBudget;
        }

        private static void RequirePositive(TimeSpan value, string name)
        {
            if (value <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(name);
            }
        }
    }
}
