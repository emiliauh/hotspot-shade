using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace HotspotShade.WinUI2.Core.Engine.Service
{
    // One transport that carries whole service frames. A named pipe
    // implementation belongs in the future full-trust host. A test fake
    // implements this seam. The seam opens no endpoint by itself.
    //
    // This form carries no outcome evidence. Once handed a request, failure
    // or an invalid reply leaves delivery unknown.
    public interface IEngineServiceChannel
    {
        Task<byte[]> ExchangeAsync(byte[] requestFrame, CancellationToken cancellationToken);

        Task CloseAsync();
    }

    // The proof a channel can make about a failed reply read. It never turns a
    // failed read into a successful exchange. It only decides whether the
    // client may say that no reply byte arrived.
    public enum EngineServiceReplyReadProof
    {
        // No reply read ran, for example because the request was never
        // written.
        NoReplyRead = 0,

        // The read proved a zero-byte transfer. No reply byte arrived.
        Missing = 1,

        // At least one reply byte arrived and the read failed. The rest of the
        // reply is not a frame boundary any more.
        Partial = 2,

        // The read failed and could not prove a zero-byte transfer. A byte may
        // have arrived.
        Unproven = 3
    }

    // One per-call answer from a channel that can report an ambiguous outcome.
    //
    // Frame is the reply when the exchange succeeded. Code is the fixed
    // failure code otherwise. OutcomeUnknown means the request may have
    // reached the service and no valid reply was validated: the caller must
    // re-read status and must not report the operation as applied.
    // Transient means no pipe operation ran and a later exchange may succeed.
    // RequestWritten means the whole request frame reached the transport.
    // ReplyReadProof is the evidence for the failed reply read.
    public sealed class EngineServiceChannelAnswer
    {
        private EngineServiceChannelAnswer(
            byte[] frame,
            string code,
            bool outcomeUnknown,
            bool transient,
            bool requestWritten,
            EngineServiceReplyReadProof replyReadProof)
        {
            Frame = frame;
            Code = EngineProtocol.IsKnownErrorCode(code)
                ? code
                : (frame == null ? EngineProtocol.ErrorCodes.Internal : "");
            OutcomeUnknown = outcomeUnknown;
            Transient = transient;
            RequestWritten = requestWritten;
            ReplyReadProof = replyReadProof;
        }

        public byte[] Frame { get; private set; }

        public string Code { get; private set; }

        public bool OutcomeUnknown { get; private set; }

        public bool Transient { get; private set; }

        public bool RequestWritten { get; private set; }

        public EngineServiceReplyReadProof ReplyReadProof { get; private set; }

        public static EngineServiceChannelAnswer Success(byte[] frame)
        {
            if (frame == null)
            {
                throw new ArgumentNullException("frame");
            }
            return new EngineServiceChannelAnswer(
                frame,
                "",
                false,
                false,
                true,
                EngineServiceReplyReadProof.NoReplyRead);
        }

        // A clean failure. No pipe operation ran, or the failure proves that
        // the request was not delivered.
        public static EngineServiceChannelAnswer Failure(string code, bool transient)
        {
            return new EngineServiceChannelAnswer(
                null,
                code,
                false,
                transient,
                false,
                EngineServiceReplyReadProof.NoReplyRead);
        }

        // A failure before the request was written. No reply byte can exist.
        public static EngineServiceChannelAnswer NotWritten(string code)
        {
            return new EngineServiceChannelAnswer(
                null,
                code,
                false,
                false,
                false,
                EngineServiceReplyReadProof.NoReplyRead);
        }

        // A failure after the request frame reached the transport. The request
        // may have been applied.
        public static EngineServiceChannelAnswer Ambiguous(
            string code,
            EngineServiceReplyReadProof replyReadProof)
        {
            return new EngineServiceChannelAnswer(
                null,
                code,
                true,
                false,
                true,
                replyReadProof);
        }

        // A failure of the request write. The transport may have accepted part
        // of the frame before it failed. mayHaveDelivered must be true for
        // every failed write that started a kernel operation, and false only
        // when no byte can have reached the transport.
        public static EngineServiceChannelAnswer WriteFailed(
            string code,
            bool mayHaveDelivered)
        {
            return new EngineServiceChannelAnswer(
                null,
                code,
                mayHaveDelivered,
                false,
                false,
                EngineServiceReplyReadProof.NoReplyRead);
        }
    }

    // A channel that applies the caller's per-operation budget to its own
    // transport deadline and reports the outcome evidence. A channel that does
    // not implement it keeps its own fixed budget and cannot prove refusal.
    public interface IEngineServiceChannelExchange
    {
        Task<EngineServiceChannelAnswer> ExchangeAsync(
            byte[] requestFrame,
            TimeSpan budget,
            CancellationToken cancellationToken);
    }

    // The app-side client for the authenticated service boundary. It frames
    // one request, reads one framed reply, and applies the strict service
    // reader. It never holds a bearer, a source credential, an install path, or
    // an endpoint. The future named-pipe transport and the future server
    // identity proof implement IEngineServiceChannel outside this class.
    //
    // A missing or malformed channel answer becomes a fixed failure code. The
    // client never turns a request acknowledgement into an On state; the app
    // state machine still requires a fresh status.
    //
    // The budget is chosen per operation. A start waits for the service start
    // budget. A reply that does not arrive inside the budget is reported as an
    // ambiguous outcome when the channel proves the request was written, not
    // as a clean refusal. An exchange channel that throws after the frame was
    // handed to it is also an unknown outcome.
    public sealed class EngineServiceClient : IEngineBroker
    {
        private readonly IEngineServiceChannel channel;
        private readonly EngineServiceCallBudgets budgets;

        public EngineServiceClient(IEngineServiceChannel channel)
            : this(channel, EngineServiceCallBudgets.Default)
        {
        }

        // One budget for every operation. This keeps the diagnostic and test
        // form. Production uses the per-operation table.
        public EngineServiceClient(IEngineServiceChannel channel, TimeSpan callTimeout)
            : this(channel, EngineServiceCallBudgets.Uniform(callTimeout))
        {
        }

        public EngineServiceClient(IEngineServiceChannel channel, EngineServiceCallBudgets budgets)
        {
            if (channel == null)
            {
                throw new ArgumentNullException("channel");
            }
            if (budgets == null)
            {
                throw new ArgumentNullException("budgets");
            }
            this.channel = channel;
            this.budgets = budgets;
        }

        public EngineServiceCallBudgets Budgets
        {
            get { return budgets; }
        }

        public async Task<EngineReply> SendAsync(
            EngineRequest request,
            CancellationToken cancellationToken)
        {
            if (request == null)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.BadRequest);
            }

            byte[] frame;
            string code;
            if (!EngineServiceFrame.TryEncode(request.ToFields(), out frame, out code))
            {
                return EngineReply.Failure(code);
            }

            TimeSpan budget = budgets.For(request.Operation);
            IEngineServiceChannelExchange exchange = channel as IEngineServiceChannelExchange;
            byte[] response;
            using (CancellationTokenSource timeout = new CancellationTokenSource())
            {
                using (CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(
                    cancellationToken,
                    timeout.Token))
                {
                    timeout.CancelAfter(budget);
                    try
                    {
                        if (exchange != null)
                        {
                            EngineServiceChannelAnswer answer =
                                await exchange.ExchangeAsync(frame, budget, linked.Token)
                                    .ConfigureAwait(false);
                            if (answer == null)
                            {
                                // A channel that cannot answer is not proof that
                                // the request was not delivered.
                                return EngineReply.UnknownOutcome(
                                    EngineProtocol.ErrorCodes.EngineUnavailable);
                            }
                            if (answer.Frame == null)
                            {
                                return answer.OutcomeUnknown
                                    ? EngineReply.UnknownOutcome(answer.Code)
                                    : EngineReply.Failure(answer.Code);
                            }
                            response = answer.Frame;
                        }
                        else
                        {
                            response = await channel.ExchangeAsync(frame, linked.Token)
                                .ConfigureAwait(false);
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        // The request frame was handed to the channel. An
                        // A thrown exception supplies no delivery evidence.
                        return EngineReply.UnknownOutcome(EngineProtocol.ErrorCodes.Timeout);
                    }
                    catch (Exception)
                    {
                        return EngineReply.UnknownOutcome(
                            EngineProtocol.ErrorCodes.EngineUnavailable);
                    }
                }
            }

            if (response == null)
            {
                // A channel with outcome evidence never returns a null reply
                // frame as a success. Treat a null frame as unproven.
                return EngineReply.UnknownOutcome(EngineProtocol.ErrorCodes.BadResponse);
            }

            Dictionary<string, string> fields;
            if (!EngineServiceFrame.TryDecode(response, response.Length, out fields, out code))
            {
                // Something arrived but it is not a reply. The request may have
                // been applied, so this is not a clean refusal.
                return EngineReply.UnknownOutcome(code);
            }

            EngineReply reply;
            if (!EngineServiceReply.TryRead(fields, request.Operation, out reply, out code))
            {
                // The reply arrived and failed validation. The operation may
                // still have been applied, so the outcome stays unknown.
                return EngineReply.UnknownOutcome(code);
            }
            return reply;
        }

        public async Task CloseAsync()
        {
            try
            {
                await channel.CloseAsync().ConfigureAwait(false);
            }
            catch (Exception)
            {
                // A close path that throws cannot leave a session claim. The
                // future host still owns the pipe and the engine process.
            }
        }
    }
}
