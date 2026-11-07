using System;
using System.Collections.Generic;
using System.Text;

namespace HotspotShade.WinUI2.Core.Engine.Service
{
    // One framed message for the authenticated engine service boundary.
    //
    // The frame is a 4 byte big-endian length and exactly that many bytes of
    // one JSON object. The cap is 65536 bytes on the whole frame. This is the
    // Windows control plane cap, not the Unix privileged helper cap.
    //
    // The JSON object is flat. A reply may put its state under one nested
    // "fields" object; the decoder flattens that object so the existing
    // EngineWire and EngineStatus readers keep one field dictionary. Every
    // key is unique after flattening. Strings, integers, true, false, and null
    // are accepted as scalar values. Arrays, fractions, exponents, comments,
    // duplicate keys, trailing bytes, and deeper objects are refused.
    //
    // This class does no input or output. It creates no pipe, process, or
    // endpoint. A transport supplies the bytes.
    public static class EngineServiceFrame
    {
        public const int Version = 1;
        public const int LengthPrefixBytes = 4;
        public const int MaxFrameBytes = 65536;
        public const int MaxPayloadBytes = MaxFrameBytes - LengthPrefixBytes;

        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        public static bool TryEncode(
            IReadOnlyDictionary<string, string> fields,
            out byte[] frame,
            out string code)
        {
            frame = null;
            if (!EngineWire.TryValidateFields(fields, out code))
            {
                return false;
            }

            StringBuilder json = new StringBuilder();
            json.Append('{');
            bool first = true;
            foreach (KeyValuePair<string, string> pair in fields)
            {
                if (!first)
                {
                    json.Append(',');
                }
                first = false;
                AppendString(json, pair.Key);
                json.Append(':');
                AppendString(json, pair.Value);
            }
            json.Append('}');

            byte[] payload;
            try
            {
                payload = StrictUtf8.GetBytes(json.ToString());
            }
            catch (EncoderFallbackException)
            {
                code = EngineProtocol.ErrorCodes.BadRequest;
                return false;
            }
            if (payload.Length < 1 || payload.Length > MaxPayloadBytes)
            {
                code = EngineProtocol.ErrorCodes.BadRequest;
                return false;
            }

            frame = new byte[LengthPrefixBytes + payload.Length];
            frame[0] = (byte)(payload.Length >> 24);
            frame[1] = (byte)(payload.Length >> 16);
            frame[2] = (byte)(payload.Length >> 8);
            frame[3] = (byte)payload.Length;
            Buffer.BlockCopy(payload, 0, frame, LengthPrefixBytes, payload.Length);
            Array.Clear(payload, 0, payload.Length);
            code = "";
            return true;
        }

        public static bool TryDecode(
            byte[] frame,
            int count,
            out Dictionary<string, string> fields,
            out string code)
        {
            fields = null;
            if (frame == null || count < LengthPrefixBytes || count > MaxFrameBytes || count > frame.Length)
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }

            int length = ((frame[0] & 0xFF) << 24)
                | ((frame[1] & 0xFF) << 16)
                | ((frame[2] & 0xFF) << 8)
                | (frame[3] & 0xFF);
            if (length < 1
                || length > MaxPayloadBytes
                || length != count - LengthPrefixBytes)
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }

            string text;
            try
            {
                text = StrictUtf8.GetString(frame, LengthPrefixBytes, length);
            }
            catch (DecoderFallbackException)
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }
            if (text.Length < 2 || text[0] != '{')
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }

            Dictionary<string, string> parsed =
                new Dictionary<string, string>(StringComparer.Ordinal);
            JsonReader reader = new JsonReader(text);
            if (!reader.TryReadRootObject(parsed))
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }
            if (!EngineWire.TryValidateFields(parsed, out code))
            {
                return false;
            }

            fields = parsed;
            code = "";
            return true;
        }

        // The length prefix alone, for a streaming reader that must allocate
        // exactly one payload. A zero length or a value above the cap is
        // refused before any allocation.
        public static bool TryReadLength(byte[] prefix, out int length)
        {
            length = 0;
            if (prefix == null || prefix.Length != LengthPrefixBytes)
            {
                return false;
            }
            length = ((prefix[0] & 0xFF) << 24)
                | ((prefix[1] & 0xFF) << 16)
                | ((prefix[2] & 0xFF) << 8)
                | (prefix[3] & 0xFF);
            return length >= 1 && length <= MaxPayloadBytes;
        }

        private static void AppendString(StringBuilder text, string value)
        {
            text.Append('"');
            for (int index = 0; index < value.Length; index++)
            {
                char character = value[index];
                switch (character)
                {
                    case '"':
                        text.Append("\\\"");
                        break;
                    case '\\':
                        text.Append("\\\\");
                        break;
                    case '\b':
                        text.Append("\\b");
                        break;
                    case '\f':
                        text.Append("\\f");
                        break;
                    case '\n':
                        text.Append("\\n");
                        break;
                    case '\r':
                        text.Append("\\r");
                        break;
                    case '\t':
                        text.Append("\\t");
                        break;
                    default:
                        if (character < ' ' || character == '\u007F')
                        {
                            AppendUnicodeEscape(text, character);
                        }
                        else
                        {
                            text.Append(character);
                        }
                        break;
                }
            }
            text.Append('"');
        }

        private static void AppendUnicodeEscape(StringBuilder text, char character)
        {
            const string Digits = "0123456789abcdef";
            text.Append("\\u");
            text.Append(Digits[(character >> 12) & 0x0F]);
            text.Append(Digits[(character >> 8) & 0x0F]);
            text.Append(Digits[(character >> 4) & 0x0F]);
            text.Append(Digits[character & 0x0F]);
        }

        private sealed class JsonReader
        {
            private readonly string text;
            private int index;

            public JsonReader(string text)
            {
                this.text = text;
            }

            public bool TryReadRootObject(Dictionary<string, string> fields)
            {
                if (!TrySkipWhitespace() || !TryConsume('{'))
                {
                    return false;
                }
                if (!TryReadObjectBody(fields, 0))
                {
                    return false;
                }
                if (!TrySkipWhitespace())
                {
                    return false;
                }
                return index == text.Length;
            }

            private bool TryReadObjectBody(Dictionary<string, string> fields, int depth)
            {
                if (!TrySkipWhitespace())
                {
                    return false;
                }
                if (TryConsume('}'))
                {
                    return true;
                }

                while (true)
                {
                    string key;
                    if (!TryReadString(out key))
                    {
                        return false;
                    }
                    if (fields.ContainsKey(key))
                    {
                        return false;
                    }
                    if (!TrySkipWhitespace() || !TryConsume(':'))
                    {
                        return false;
                    }
                    if (!TrySkipWhitespace())
                    {
                        return false;
                    }

                    if (Peek() == '{')
                    {
                        // Only the one nested "fields" object is allowed, and
                        // only at the top level. It flattens into the same
                        // dictionary so a duplicate across the boundary is a
                        // protocol failure.
                        if (depth != 0 || key != "fields")
                        {
                            return false;
                        }
                        index++;
                        if (!TryReadObjectBody(fields, 1))
                        {
                            return false;
                        }
                    }
                    else
                    {
                        string value;
                        if (!TryReadScalar(out value))
                        {
                            return false;
                        }
                        fields[key] = value;
                    }

                    if (!TrySkipWhitespace())
                    {
                        return false;
                    }
                    if (TryConsume(','))
                    {
                        if (!TrySkipWhitespace())
                        {
                            return false;
                        }
                        continue;
                    }
                    if (TryConsume('}'))
                    {
                        return true;
                    }
                    return false;
                }
            }

            private bool TryReadString(out string value)
            {
                value = null;
                if (!TryConsume('"'))
                {
                    return false;
                }
                StringBuilder result = new StringBuilder();
                while (index < text.Length)
                {
                    char character = text[index];
                    index++;
                    if (character == '"')
                    {
                        value = result.ToString();
                        return true;
                    }
                    if (character < ' ')
                    {
                        return false;
                    }
                    if (character != '\\')
                    {
                        result.Append(character);
                        continue;
                    }
                    if (index >= text.Length)
                    {
                        return false;
                    }
                    char escape = text[index];
                    index++;
                    switch (escape)
                    {
                        case '"':
                            result.Append('"');
                            break;
                        case '\\':
                            result.Append('\\');
                            break;
                        case '/':
                            result.Append('/');
                            break;
                        case 'b':
                            result.Append('\b');
                            break;
                        case 'f':
                            result.Append('\f');
                            break;
                        case 'n':
                            result.Append('\n');
                            break;
                        case 'r':
                            result.Append('\r');
                            break;
                        case 't':
                            result.Append('\t');
                            break;
                        case 'u':
                            int first;
                            if (!TryReadHex4(out first))
                            {
                                return false;
                            }
                            result.Append((char)first);
                            break;
                        default:
                            return false;
                    }
                }
                return false;
            }

            private bool TryReadHex4(out int value)
            {
                value = 0;
                if (index + 4 > text.Length)
                {
                    return false;
                }
                for (int count = 0; count < 4; count++)
                {
                    char character = text[index + count];
                    int digit;
                    if (character >= '0' && character <= '9')
                    {
                        digit = character - '0';
                    }
                    else if (character >= 'a' && character <= 'f')
                    {
                        digit = character - 'a' + 10;
                    }
                    else if (character >= 'A' && character <= 'F')
                    {
                        digit = character - 'A' + 10;
                    }
                    else
                    {
                        return false;
                    }
                    value = (value << 4) | digit;
                }
                index += 4;
                return true;
            }

            private bool TryReadScalar(out string value)
            {
                value = null;
                if (Peek() == '"')
                {
                    return TryReadString(out value);
                }
                if (TryConsumeLiteral("true"))
                {
                    value = "1";
                    return true;
                }
                if (TryConsumeLiteral("false"))
                {
                    value = "0";
                    return true;
                }
                if (TryConsumeLiteral("null"))
                {
                    value = "";
                    return true;
                }

                int start = index;
                if (Peek() == '-')
                {
                    index++;
                }
                int digitStart = index;
                while (index < text.Length && text[index] >= '0' && text[index] <= '9')
                {
                    index++;
                }
                if (index == digitStart)
                {
                    index = start;
                    return false;
                }
                if (index - digitStart > 1 && text[digitStart] == '0')
                {
                    index = start;
                    return false;
                }
                value = text.Substring(start, index - start);
                return true;
            }

            private bool TryConsumeLiteral(string literal)
            {
                if (index + literal.Length > text.Length)
                {
                    return false;
                }
                if (string.CompareOrdinal(text, index, literal, 0, literal.Length) != 0)
                {
                    return false;
                }
                index += literal.Length;
                return true;
            }

            private bool TrySkipWhitespace()
            {
                while (index < text.Length)
                {
                    char character = text[index];
                    if (character != ' ' && character != '\t' && character != '\r' && character != '\n')
                    {
                        return true;
                    }
                    index++;
                }
                return true;
            }

            private bool TryConsume(char expected)
            {
                if (index < text.Length && text[index] == expected)
                {
                    index++;
                    return true;
                }
                return false;
            }

            private char Peek()
            {
                return index < text.Length ? text[index] : '\0';
            }
        }
    }
}
