using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace HotspotShade.WinUI2.Core.App
{
    public enum JsonKind
    {
        Null,
        Bool,
        Number,
        String,
        Array,
        Object
    }

    // One parsed JSON value. The parser is bounded: a document over the size
    // limit, nested too deeply, or with a duplicate key is refused. A field
    // with an unexpected type reads as missing, so one odd field never fails
    // a whole status answer. The engine is the only producer of these
    // documents, and it never puts a token or a key in them.
    public sealed class JsonValue
    {
        public const int MaxDocumentChars = 262144;
        public const int MaxDepth = 32;

        private static readonly JsonValue NullValue = new JsonValue(JsonKind.Null);

        private readonly Dictionary<string, JsonValue> members;
        private readonly List<string> order;
        private readonly List<JsonValue> items;

        private JsonValue(JsonKind kind)
        {
            Kind = kind;
            if (kind == JsonKind.Object)
            {
                members = new Dictionary<string, JsonValue>(StringComparer.Ordinal);
                order = new List<string>();
            }
            else if (kind == JsonKind.Array)
            {
                items = new List<JsonValue>();
            }
        }

        public JsonKind Kind { get; private set; }

        public bool BoolValue { get; private set; }

        public double NumberValue { get; private set; }

        public string StringValue { get; private set; }

        public int Count
        {
            get
            {
                if (items != null)
                {
                    return items.Count;
                }
                return order == null ? 0 : order.Count;
            }
        }

        public IList<string> Keys
        {
            get { return order == null ? (IList<string>)new string[0] : order.AsReadOnly(); }
        }

        public JsonValue this[int index]
        {
            get
            {
                if (items == null || index < 0 || index >= items.Count)
                {
                    return NullValue;
                }
                return items[index];
            }
        }

        // A missing member reads as JSON null.
        public JsonValue Get(string name)
        {
            JsonValue value;
            if (members != null && name != null && members.TryGetValue(name, out value))
            {
                return value;
            }
            return NullValue;
        }

        public bool Has(string name)
        {
            return members != null && name != null && members.ContainsKey(name);
        }

        public bool IsObject
        {
            get { return Kind == JsonKind.Object; }
        }

        public bool IsArray
        {
            get { return Kind == JsonKind.Array; }
        }

        // Typed reads. Each returns null for a missing or wrong-typed value.
        public string GetString(string name)
        {
            JsonValue value = Get(name);
            return value.Kind == JsonKind.String ? value.StringValue : null;
        }

        public bool? GetBool(string name)
        {
            JsonValue value = Get(name);
            if (value.Kind == JsonKind.Bool)
            {
                return value.BoolValue;
            }
            return null;
        }

        public double? GetNumber(string name)
        {
            JsonValue value = Get(name);
            if (value.Kind == JsonKind.Number)
            {
                return value.NumberValue;
            }
            return null;
        }

        // A whole number in the 32-bit range. A fraction or an out-of-range
        // value is not a count.
        public int? GetInt(string name)
        {
            double? number = GetNumber(name);
            if (!number.HasValue)
            {
                return null;
            }
            double value = number.Value;
            if (value != Math.Floor(value) || value < int.MinValue || value > int.MaxValue)
            {
                return null;
            }
            return (int)value;
        }

        public long? GetLong(string name)
        {
            double? number = GetNumber(name);
            if (!number.HasValue)
            {
                return null;
            }
            double value = number.Value;
            if (value != Math.Floor(value) || value < -9007199254740992D || value > 9007199254740992D)
            {
                return null;
            }
            return (long)value;
        }

        public JsonValue GetObject(string name)
        {
            JsonValue value = Get(name);
            return value.Kind == JsonKind.Object ? value : null;
        }

        public JsonValue GetArray(string name)
        {
            JsonValue value = Get(name);
            return value.Kind == JsonKind.Array ? value : null;
        }

        public static bool TryParse(string text, out JsonValue value)
        {
            value = null;
            if (text == null || text.Length == 0 || text.Length > MaxDocumentChars)
            {
                return false;
            }
            Parser parser = new Parser(text);
            try
            {
                JsonValue parsed = parser.ParseValue(0);
                parser.SkipSpace();
                if (!parser.AtEnd)
                {
                    return false;
                }
                value = parsed;
                return true;
            }
            catch (FormatException)
            {
                return false;
            }
        }

        // Parse a document whose root must be an object.
        public static bool TryParseObject(string text, out JsonValue value)
        {
            if (!TryParse(text, out value) || value.Kind != JsonKind.Object)
            {
                value = null;
                return false;
            }
            return true;
        }

        // Write a JSON string literal. The broker uses this for the few fixed
        // request bodies it builds. Control characters are escaped.
        public static string Quote(string text)
        {
            StringBuilder builder = new StringBuilder();
            builder.Append('"');
            if (text != null)
            {
                for (int index = 0; index < text.Length; index++)
                {
                    char c = text[index];
                    switch (c)
                    {
                        case '"':
                            builder.Append("\\\"");
                            break;
                        case '\\':
                            builder.Append("\\\\");
                            break;
                        case '\n':
                            builder.Append("\\n");
                            break;
                        case '\r':
                            builder.Append("\\r");
                            break;
                        case '\t':
                            builder.Append("\\t");
                            break;
                        default:
                            if (c < ' ')
                            {
                                builder.Append("\\u");
                                builder.Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                            }
                            else
                            {
                                builder.Append(c);
                            }
                            break;
                    }
                }
            }
            builder.Append('"');
            return builder.ToString();
        }

        private sealed class Parser
        {
            private readonly string text;
            private int at;

            public Parser(string text)
            {
                this.text = text;
            }

            public bool AtEnd
            {
                get { return at >= text.Length; }
            }

            public void SkipSpace()
            {
                while (at < text.Length)
                {
                    char c = text[at];
                    if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
                    {
                        at++;
                    }
                    else
                    {
                        break;
                    }
                }
            }

            public JsonValue ParseValue(int depth)
            {
                if (depth > MaxDepth)
                {
                    throw new FormatException("depth");
                }
                SkipSpace();
                if (at >= text.Length)
                {
                    throw new FormatException("end");
                }
                char c = text[at];
                switch (c)
                {
                    case '{':
                        return ParseObject(depth);
                    case '[':
                        return ParseArray(depth);
                    case '"':
                        {
                            JsonValue value = new JsonValue(JsonKind.String);
                            value.StringValue = ParseString();
                            return value;
                        }
                    case 't':
                        Expect("true");
                        return Bool(true);
                    case 'f':
                        Expect("false");
                        return Bool(false);
                    case 'n':
                        Expect("null");
                        return new JsonValue(JsonKind.Null);
                    default:
                        if (c == '-' || (c >= '0' && c <= '9'))
                        {
                            return ParseNumber();
                        }
                        throw new FormatException("value");
                }
            }

            private static JsonValue Bool(bool flag)
            {
                JsonValue value = new JsonValue(JsonKind.Bool);
                value.BoolValue = flag;
                return value;
            }

            private void Expect(string word)
            {
                if (at + word.Length > text.Length
                    || string.CompareOrdinal(text, at, word, 0, word.Length) != 0)
                {
                    throw new FormatException("literal");
                }
                at += word.Length;
            }

            private JsonValue ParseObject(int depth)
            {
                JsonValue value = new JsonValue(JsonKind.Object);
                at++;
                SkipSpace();
                if (at < text.Length && text[at] == '}')
                {
                    at++;
                    return value;
                }
                while (true)
                {
                    SkipSpace();
                    if (at >= text.Length || text[at] != '"')
                    {
                        throw new FormatException("key");
                    }
                    string key = ParseString();
                    SkipSpace();
                    if (at >= text.Length || text[at] != ':')
                    {
                        throw new FormatException("colon");
                    }
                    at++;
                    JsonValue member = ParseValue(depth + 1);
                    if (value.members.ContainsKey(key))
                    {
                        throw new FormatException("duplicate");
                    }
                    value.members.Add(key, member);
                    value.order.Add(key);
                    SkipSpace();
                    if (at >= text.Length)
                    {
                        throw new FormatException("end");
                    }
                    if (text[at] == ',')
                    {
                        at++;
                        continue;
                    }
                    if (text[at] == '}')
                    {
                        at++;
                        return value;
                    }
                    throw new FormatException("object");
                }
            }

            private JsonValue ParseArray(int depth)
            {
                JsonValue value = new JsonValue(JsonKind.Array);
                at++;
                SkipSpace();
                if (at < text.Length && text[at] == ']')
                {
                    at++;
                    return value;
                }
                while (true)
                {
                    value.items.Add(ParseValue(depth + 1));
                    SkipSpace();
                    if (at >= text.Length)
                    {
                        throw new FormatException("end");
                    }
                    if (text[at] == ',')
                    {
                        at++;
                        continue;
                    }
                    if (text[at] == ']')
                    {
                        at++;
                        return value;
                    }
                    throw new FormatException("array");
                }
            }

            private string ParseString()
            {
                at++;
                StringBuilder builder = new StringBuilder();
                while (true)
                {
                    if (at >= text.Length)
                    {
                        throw new FormatException("string end");
                    }
                    char c = text[at++];
                    if (c == '"')
                    {
                        return builder.ToString();
                    }
                    if (c < ' ')
                    {
                        throw new FormatException("control");
                    }
                    if (c != '\\')
                    {
                        builder.Append(c);
                        continue;
                    }
                    if (at >= text.Length)
                    {
                        throw new FormatException("escape end");
                    }
                    char escape = text[at++];
                    switch (escape)
                    {
                        case '"':
                            builder.Append('"');
                            break;
                        case '\\':
                            builder.Append('\\');
                            break;
                        case '/':
                            builder.Append('/');
                            break;
                        case 'b':
                            builder.Append('\b');
                            break;
                        case 'f':
                            builder.Append('\f');
                            break;
                        case 'n':
                            builder.Append('\n');
                            break;
                        case 'r':
                            builder.Append('\r');
                            break;
                        case 't':
                            builder.Append('\t');
                            break;
                        case 'u':
                            {
                                if (at + 4 > text.Length)
                                {
                                    throw new FormatException("unicode");
                                }
                                int code;
                                if (!int.TryParse(
                                    text.Substring(at, 4),
                                    NumberStyles.AllowHexSpecifier,
                                    CultureInfo.InvariantCulture,
                                    out code))
                                {
                                    throw new FormatException("unicode");
                                }
                                at += 4;
                                builder.Append((char)code);
                                break;
                            }
                        default:
                            throw new FormatException("escape");
                    }
                }
            }

            private JsonValue ParseNumber()
            {
                int start = at;
                if (text[at] == '-')
                {
                    at++;
                }
                int digits = 0;
                while (at < text.Length && text[at] >= '0' && text[at] <= '9')
                {
                    at++;
                    digits++;
                }
                if (digits == 0)
                {
                    throw new FormatException("number");
                }
                if (at < text.Length && text[at] == '.')
                {
                    at++;
                    int fraction = 0;
                    while (at < text.Length && text[at] >= '0' && text[at] <= '9')
                    {
                        at++;
                        fraction++;
                    }
                    if (fraction == 0)
                    {
                        throw new FormatException("fraction");
                    }
                }
                if (at < text.Length && (text[at] == 'e' || text[at] == 'E'))
                {
                    at++;
                    if (at < text.Length && (text[at] == '+' || text[at] == '-'))
                    {
                        at++;
                    }
                    int exponent = 0;
                    while (at < text.Length && text[at] >= '0' && text[at] <= '9')
                    {
                        at++;
                        exponent++;
                    }
                    if (exponent == 0)
                    {
                        throw new FormatException("exponent");
                    }
                }
                double number;
                if (!double.TryParse(
                    text.Substring(start, at - start),
                    NumberStyles.Float,
                    CultureInfo.InvariantCulture,
                    out number)
                    || double.IsInfinity(number)
                    || double.IsNaN(number))
                {
                    throw new FormatException("number");
                }
                JsonValue value = new JsonValue(JsonKind.Number);
                value.NumberValue = number;
                return value;
            }
        }
    }
}
