using System;
using System.Collections.Generic;
using System.Globalization;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.Core.Engine
{
    // One request from the app to the broker. The request holds no token and
    // no source device address. The broker owns the pairing and the token.
    public sealed class EngineRequest
    {
        public EngineRequest(string operation, string sessionId, bool ping)
        {
            if (!EngineProtocol.IsKnownOperation(operation))
            {
                throw new ArgumentException("unknown operation", "operation");
            }
            if (!EngineProtocol.IsValidSessionId(sessionId))
            {
                throw new ArgumentException("invalid session id", "sessionId");
            }
            Operation = operation;
            SessionId = sessionId;
            Ping = ping;
        }

        public string Operation { get; private set; }

        public string SessionId { get; private set; }

        public bool Ping { get; private set; }

        public bool IsStart
        {
            get { return Operation == EngineProtocol.Operations.Start; }
        }

        public Dictionary<string, string> ToFields()
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields[EngineProtocol.Keys.Version] = EngineProtocol.Version.ToString(CultureInfo.InvariantCulture);
            fields[EngineProtocol.Keys.Operation] = Operation;
            fields[EngineProtocol.Keys.Session] = SessionId;
            if (IsStart)
            {
                fields[EngineProtocol.Keys.Ping] = Ping ? "1" : "0";
            }
            return fields;
        }
    }

    // One reply from the broker. A success reply carries non-secret state. A
    // failure reply carries one fixed code and no detail text.
    public sealed class EngineReply
    {
        private readonly Dictionary<string, string> fields;

        internal EngineReply(bool ok, string code, Dictionary<string, string> fields)
        {
            Ok = ok;
            Code = code ?? "";
            this.fields = fields ?? new Dictionary<string, string>(StringComparer.Ordinal);
        }

        public bool Ok { get; private set; }

        public string Code { get; private set; }

        // True when no valid reply arrived and the request may still have
        // reached the service. The caller must not report the operation as
        // applied and must not report it as cleanly refused. A later status
        // read is the only way to learn the result.
        public bool OutcomeUnknown { get; private set; }

        public IReadOnlyDictionary<string, string> Fields
        {
            get { return fields; }
        }

        public static EngineReply Success(IDictionary<string, string> extra)
        {
            Dictionary<string, string> values = new Dictionary<string, string>(StringComparer.Ordinal);
            if (extra != null)
            {
                foreach (KeyValuePair<string, string> pair in extra)
                {
                    if (pair.Key == EngineProtocol.Keys.Version || pair.Key == EngineProtocol.Keys.Ok)
                    {
                        continue;
                    }
                    values[pair.Key] = pair.Value;
                }
            }
            values[EngineProtocol.Keys.Version] = EngineProtocol.Version.ToString(CultureInfo.InvariantCulture);
            values[EngineProtocol.Keys.Ok] = "1";
            return new EngineReply(true, "", values);
        }

        public static EngineReply Failure(string code)
        {
            string fixedCode = EngineProtocol.IsKnownErrorCode(code)
                ? code
                : EngineProtocol.ErrorCodes.Internal;
            Dictionary<string, string> values = new Dictionary<string, string>(StringComparer.Ordinal);
            values[EngineProtocol.Keys.Version] = EngineProtocol.Version.ToString(CultureInfo.InvariantCulture);
            values[EngineProtocol.Keys.Ok] = "0";
            values[EngineProtocol.Keys.Code] = fixedCode;
            return new EngineReply(false, fixedCode, values);
        }

        // A failure whose request may still have been applied. It is never a
        // success, and it is never a clean refusal. The fixed code is kept.
        public static EngineReply UnknownOutcome(string code)
        {
            EngineReply reply = Failure(code);
            reply.OutcomeUnknown = true;
            return reply;
        }

        // Keeps the ambiguous flag on a validated failure. A validated
        // success is never ambiguous and is returned unchanged. A caller that
        // re-reads the wire fields must use this so a broker's unknown outcome
        // is not lost at the second validation.
        internal EngineReply KeepOutcomeUnknown()
        {
            if (!Ok)
            {
                OutcomeUnknown = true;
            }
            return this;
        }
    }

    // Strict validation for the broker boundary. Every value is a short fixed
    // token. A credential key is refused in both directions. The transport
    // adapter maps a ValueSet to this dictionary and back.
    public static class EngineWire
    {
        public static bool TryValidateFields(IReadOnlyDictionary<string, string> fields, out string code)
        {
            code = "";
            if (fields == null || fields.Count < 1 || fields.Count > EngineProtocol.MaxFieldCount)
            {
                code = EngineProtocol.ErrorCodes.BadRequest;
                return false;
            }
            int total = 0;
            foreach (KeyValuePair<string, string> pair in fields)
            {
                if (EngineProtocol.IsCredentialKey(pair.Key))
                {
                    code = EngineProtocol.ErrorCodes.Forbidden;
                    return false;
                }
                if (!EngineProtocol.IsSafeFieldName(pair.Key) || !EngineProtocol.IsSafeFieldValue(pair.Value))
                {
                    code = EngineProtocol.ErrorCodes.BadRequest;
                    return false;
                }
                total += pair.Key.Length + pair.Value.Length;
                if (total > EngineProtocol.MaxTextLength)
                {
                    code = EngineProtocol.ErrorCodes.BadRequest;
                    return false;
                }
            }
            return true;
        }

        public static bool TryReadRequest(
            IReadOnlyDictionary<string, string> fields,
            out EngineRequest request,
            out string code)
        {
            request = null;
            if (!TryValidateFields(fields, out code))
            {
                return false;
            }

            string version;
            if (!fields.TryGetValue(EngineProtocol.Keys.Version, out version)
                || version != EngineProtocol.Version.ToString(CultureInfo.InvariantCulture))
            {
                code = EngineProtocol.ErrorCodes.BadVersion;
                return false;
            }

            string operation;
            if (!fields.TryGetValue(EngineProtocol.Keys.Operation, out operation)
                || !EngineProtocol.IsKnownOperation(operation))
            {
                code = EngineProtocol.ErrorCodes.BadOperation;
                return false;
            }

            string session;
            if (!fields.TryGetValue(EngineProtocol.Keys.Session, out session)
                || !EngineProtocol.IsValidSessionId(session))
            {
                code = EngineProtocol.ErrorCodes.BadRequest;
                return false;
            }

            bool ping = false;
            string pingText;
            if (fields.TryGetValue(EngineProtocol.Keys.Ping, out pingText))
            {
                if (operation != EngineProtocol.Operations.Start || (pingText != "0" && pingText != "1"))
                {
                    code = EngineProtocol.ErrorCodes.BadRequest;
                    return false;
                }
                ping = pingText == "1";
            }
            else if (operation == EngineProtocol.Operations.Start)
            {
                code = EngineProtocol.ErrorCodes.BadRequest;
                return false;
            }

            foreach (string key in fields.Keys)
            {
                bool allowed = key == EngineProtocol.Keys.Version
                    || key == EngineProtocol.Keys.Operation
                    || key == EngineProtocol.Keys.Session
                    || (key == EngineProtocol.Keys.Ping && operation == EngineProtocol.Operations.Start);
                if (!allowed)
                {
                    code = EngineProtocol.ErrorCodes.BadRequest;
                    return false;
                }
            }

            request = new EngineRequest(operation, session, ping);
            code = "";
            return true;
        }

        public static bool TryReadHello(EngineReply reply, out string instance, out string code)
        {
            instance = "";
            code = "";
            if (reply == null || !reply.Ok)
            {
                code = reply != null && !reply.Ok
                    ? reply.Code
                    : EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }

            IReadOnlyDictionary<string, string> fields = reply.Fields;
            string value;
            if (fields == null
                || !fields.TryGetValue(EngineProtocol.Keys.Instance, out value)
                || !EngineProtocol.IsValidInstanceId(value))
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }

            string engine;
            if (!fields.TryGetValue(EngineProtocol.Keys.Engine, out engine)
                || !EngineProtocol.IsKnownEngineState(engine))
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }

            foreach (string key in fields.Keys)
            {
                bool allowed = key == EngineProtocol.Keys.Version
                    || key == EngineProtocol.Keys.Ok
                    || key == EngineProtocol.Keys.Instance
                    || key == EngineProtocol.Keys.Engine;
                if (!allowed)
                {
                    code = EngineProtocol.ErrorCodes.BadResponse;
                    return false;
                }
            }

            instance = value;
            return true;
        }

        public static bool TryReadReply(
            IReadOnlyDictionary<string, string> fields,
            out EngineReply reply,
            out string code)
        {
            reply = null;
            if (!TryValidateFields(fields, out code))
            {
                return false;
            }

            string version;
            if (!fields.TryGetValue(EngineProtocol.Keys.Version, out version)
                || version != EngineProtocol.Version.ToString(CultureInfo.InvariantCulture))
            {
                code = EngineProtocol.ErrorCodes.BadVersion;
                return false;
            }

            string ok;
            if (!fields.TryGetValue(EngineProtocol.Keys.Ok, out ok) || (ok != "0" && ok != "1"))
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }

            if (ok == "0")
            {
                string failure;
                if (fields.Count != 3
                    || !fields.TryGetValue(EngineProtocol.Keys.Code, out failure)
                    || !EngineProtocol.IsKnownErrorCode(failure))
                {
                    code = EngineProtocol.ErrorCodes.BadResponse;
                    return false;
                }
                reply = EngineReply.Failure(failure);
                code = "";
                return true;
            }

            if (fields.ContainsKey(EngineProtocol.Keys.Code))
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }

            foreach (KeyValuePair<string, string> pair in fields)
            {
                if (!IsAllowedSuccessKey(pair.Key) || !IsValidSuccessValue(pair.Key, pair.Value))
                {
                    code = EngineProtocol.ErrorCodes.BadResponse;
                    return false;
                }
            }

            reply = new EngineReply(true, "", Copy(fields));
            code = "";
            return true;
        }

        private static bool IsAllowedSuccessKey(string key)
        {
            switch (key)
            {
                case EngineProtocol.Keys.Version:
                case EngineProtocol.Keys.Ok:
                case EngineProtocol.Keys.Instance:
                case EngineProtocol.Keys.Engine:
                case EngineProtocol.Keys.Paired:
                case EngineProtocol.Keys.Running:
                case EngineProtocol.Keys.Source:
                case EngineProtocol.Keys.Trusted:
                case EngineProtocol.Keys.Ping:
                case EngineProtocol.Keys.Connections:
                case EngineProtocol.Keys.Stop:
                case EngineProtocol.Keys.ConnectionsKnown:
                case EngineProtocol.Keys.CheckedAt:
                case EngineProtocol.Keys.Cleanup:
                case EngineProtocol.Keys.TtlBad:
                    return true;
                default:
                    return false;
            }
        }

        private static bool IsValidSuccessValue(string key, string value)
        {
            switch (key)
            {
                case EngineProtocol.Keys.Instance:
                    return EngineProtocol.IsValidInstanceId(value);
                case EngineProtocol.Keys.Engine:
                    return EngineProtocol.IsKnownEngineState(value);
                case EngineProtocol.Keys.Paired:
                case EngineProtocol.Keys.Running:
                case EngineProtocol.Keys.Source:
                case EngineProtocol.Keys.Trusted:
                case EngineProtocol.Keys.Ping:
                case EngineProtocol.Keys.ConnectionsKnown:
                    return value == "0" || value == "1";
                case EngineProtocol.Keys.Connections:
                    int count;
                    return TryParseCount(value, out count);
                case EngineProtocol.Keys.TtlBad:
                    int ttlBad;
                    return TryParseCount(value, out ttlBad);
                case EngineProtocol.Keys.Stop:
                    return EngineProtocol.IsKnownStopReason(value);
                case EngineProtocol.Keys.CheckedAt:
                    return IsCheckedAtFormat(value);
                case EngineProtocol.Keys.Cleanup:
                    EngineCleanup cleanup;
                    return EngineRules.TryParseCleanup(value, out cleanup);
                default:
                    return true;
            }
        }

        // The service reports checked_at as non-negative Unix seconds and
        // refuses a value more than the skew bound in the future. Format and
        // skew are separate checks: this one is clock-free so a reply reader is
        // not tied to a wall clock. EngineStatus.TryParse applies the skew
        // bound with the sample time it already holds.
        public static bool IsCheckedAtFormat(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return true;
            }
            if (value.Length > 18)
            {
                return false;
            }
            for (int index = 0; index < value.Length; index++)
            {
                char character = value[index];
                if (character < '0' || character > '9')
                {
                    return false;
                }
            }
            long seconds;
            return long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out seconds)
                && seconds >= 0;
        }

        public static bool TryParseCheckedAt(
            string value,
            DateTimeOffset now,
            out DateTimeOffset? checkedAt)
        {
            checkedAt = null;
            if (string.IsNullOrEmpty(value))
            {
                return true;
            }
            if (!IsCheckedAtFormat(value))
            {
                return false;
            }
            long seconds = long.Parse(value, NumberStyles.None, CultureInfo.InvariantCulture);
            long nowSeconds = now.ToUnixTimeSeconds();
            long latest = nowSeconds > long.MaxValue - EngineServiceStatus.MaxFutureSkewSeconds
                ? long.MaxValue
                : nowSeconds + EngineServiceStatus.MaxFutureSkewSeconds;
            if (seconds > latest)
            {
                return false;
            }
            try
            {
                checkedAt = DateTimeOffset.FromUnixTimeSeconds(seconds);
                return true;
            }
            catch (ArgumentOutOfRangeException)
            {
                return false;
            }
        }

        public static bool TryParseCount(string value, out int count)
        {
            count = 0;
            if (string.IsNullOrEmpty(value) || value.Length > 6)
            {
                return false;
            }
            if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out count))
            {
                return false;
            }
            return count >= 0 && count <= 100000;
        }

        private static Dictionary<string, string> Copy(IReadOnlyDictionary<string, string> fields)
        {
            Dictionary<string, string> copy = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (KeyValuePair<string, string> pair in fields)
            {
                copy[pair.Key] = pair.Value;
            }
            return copy;
        }
    }
}
