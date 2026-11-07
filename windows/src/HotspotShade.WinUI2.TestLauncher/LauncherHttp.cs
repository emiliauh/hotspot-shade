using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace HotspotShade.WinUI2.TestLauncher
{
    // One answer from the engine. Code is empty when the request reached the
    // engine; otherwise it names a fixed transport failure.
    internal sealed class LauncherResponse
    {
        public LauncherResponse(int status, byte[] body, string code)
        {
            Status = status;
            Body = body;
            Code = code ?? "";
        }

        public int Status { get; private set; }

        public byte[] Body { get; private set; }

        public string Code { get; private set; }

        public bool Reached
        {
            get { return Code.Length == 0; }
        }
    }

    // A WinHTTP client for the engine's loopback API. It uses 127.0.0.1 only,
    // no proxy, no name lookup, and no redirects, the same rules as the
    // broker's WindowsEngineLocalClient. The bearer header is built from a
    // copy of the per-launch secret that the caller clears.
    internal static class LauncherHttp
    {
        private const int AccessTypeNoProxy = 1;
        private const uint QueryStatusCode = 19;
        private const uint QueryFlagNumber = 0x20000000;
        private const uint AddRequestFlagAdd = 0x20000000;
        private const uint AddRequestFlagReplace = 0x80000000;
        // WINHTTP_OPTION_REDIRECT_POLICY is 88 in winhttp.h.
        private const int OptionRedirectPolicy = 88;
        private const int RedirectPolicyNever = 0;
        private const int MaximumBody = 262144;
        private const int ErrorWinHttpTimeout = 12002;

        public static LauncherResponse Send(
            int port,
            byte[] secret,
            string method,
            string path,
            byte[] body,
            int receiveTimeoutMilliseconds)
        {
            if (secret == null || secret.Length != 64)
            {
                return new LauncherResponse(0, null, "no_secret");
            }
            IntPtr session = IntPtr.Zero;
            IntPtr connect = IntPtr.Zero;
            IntPtr request = IntPtr.Zero;
            try
            {
                session = WinHttpOpen("HotspotShade-TestLauncher/1.0", AccessTypeNoProxy, IntPtr.Zero, IntPtr.Zero, 0);
                if (session == IntPtr.Zero)
                {
                    return new LauncherResponse(0, null, "engine_unavailable");
                }
                if (!WinHttpSetTimeouts(session, 1000, 2000, 5000, receiveTimeoutMilliseconds))
                {
                    return new LauncherResponse(0, null, "engine_unavailable");
                }
                connect = WinHttpConnect(session, "127.0.0.1", (ushort)port, 0);
                if (connect == IntPtr.Zero)
                {
                    return new LauncherResponse(0, null, "engine_unavailable");
                }
                request = WinHttpOpenRequest(connect, method, path, null, IntPtr.Zero, IntPtr.Zero, 0);
                if (request == IntPtr.Zero)
                {
                    return new LauncherResponse(0, null, "engine_unavailable");
                }
                int policy = RedirectPolicyNever;
                if (!WinHttpSetOption(request, OptionRedirectPolicy, ref policy, 4))
                {
                    // A redirect must never carry the bearer header.
                    return new LauncherResponse(0, null, "engine_unavailable");
                }

                char[] header = new char[22 + 64 + 2];
                try
                {
                    "Authorization: Bearer ".CopyTo(0, header, 0, 22);
                    for (int index = 0; index < 64; index++)
                    {
                        header[22 + index] = (char)secret[index];
                    }
                    header[86] = '\r';
                    header[87] = '\n';
                    if (!WinHttpAddRequestHeaders(request, header, header.Length, AddRequestFlagAdd | AddRequestFlagReplace))
                    {
                        return new LauncherResponse(0, null, "engine_unavailable");
                    }
                }
                finally
                {
                    Array.Clear(header, 0, header.Length);
                }
                if (body != null)
                {
                    char[] type = "Content-Type: application/json\r\n".ToCharArray();
                    if (!WinHttpAddRequestHeaders(request, type, type.Length, AddRequestFlagAdd | AddRequestFlagReplace))
                    {
                        return new LauncherResponse(0, null, "engine_unavailable");
                    }
                }

                int length = body == null ? 0 : body.Length;
                if (!WinHttpSendRequest(request, IntPtr.Zero, 0, body, length, length, IntPtr.Zero))
                {
                    return new LauncherResponse(0, null, MapError());
                }
                if (!WinHttpReceiveResponse(request, IntPtr.Zero))
                {
                    return new LauncherResponse(0, null, MapError());
                }
                int status = ReadStatusCode(request);
                if (status <= 0)
                {
                    return new LauncherResponse(0, null, "bad_response");
                }
                byte[] answer;
                string failure = ReadBody(request, out answer);
                if (failure != null)
                {
                    return new LauncherResponse(0, null, failure);
                }
                return new LauncherResponse(status, answer, "");
            }
            catch (Exception)
            {
                return new LauncherResponse(0, null, "engine_unavailable");
            }
            finally
            {
                if (request != IntPtr.Zero)
                {
                    WinHttpCloseHandle(request);
                }
                if (connect != IntPtr.Zero)
                {
                    WinHttpCloseHandle(connect);
                }
                if (session != IntPtr.Zero)
                {
                    WinHttpCloseHandle(session);
                }
            }
        }

        private static int ReadStatusCode(IntPtr request)
        {
            byte[] buffer = new byte[4];
            int length = buffer.Length;
            if (!WinHttpQueryHeaders(request, QueryStatusCode | QueryFlagNumber, IntPtr.Zero, buffer, ref length, IntPtr.Zero))
            {
                return 0;
            }
            return length == 4 ? BitConverter.ToInt32(buffer, 0) : 0;
        }

        private static string ReadBody(IntPtr request, out byte[] answer)
        {
            answer = null;
            using (MemoryStream body = new MemoryStream())
            {
                byte[] chunk = new byte[8192];
                while (true)
                {
                    int read = 0;
                    if (!WinHttpReadData(request, chunk, chunk.Length, ref read))
                    {
                        return "engine_unavailable";
                    }
                    if (read <= 0)
                    {
                        break;
                    }
                    if (body.Length + read > MaximumBody)
                    {
                        return "bad_response";
                    }
                    body.Write(chunk, 0, read);
                }
                answer = body.ToArray();
                return null;
            }
        }

        private static string MapError()
        {
            return Marshal.GetLastWin32Error() == ErrorWinHttpTimeout ? "timeout" : "engine_unavailable";
        }

        [DllImport("winhttp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr WinHttpOpen(string agent, int accessType, IntPtr proxyName, IntPtr proxyBypass, int flags);

        [DllImport("winhttp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr WinHttpConnect(IntPtr session, string serverName, ushort serverPort, int reserved);

        [DllImport("winhttp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr WinHttpOpenRequest(
            IntPtr connect,
            string verb,
            string objectName,
            string version,
            IntPtr referrer,
            IntPtr acceptTypes,
            int flags);

        [DllImport("winhttp.dll", SetLastError = true)]
        private static extern bool WinHttpSetTimeouts(IntPtr session, int resolveTimeout, int connectTimeout, int sendTimeout, int receiveTimeout);

        [DllImport("winhttp.dll", SetLastError = true)]
        private static extern bool WinHttpSetOption(IntPtr handle, int option, ref int buffer, int length);

        [DllImport("winhttp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool WinHttpAddRequestHeaders(IntPtr request, char[] headers, int length, uint modifiers);

        [DllImport("winhttp.dll", SetLastError = true)]
        private static extern bool WinHttpSendRequest(
            IntPtr request,
            IntPtr headers,
            int headersLength,
            byte[] optional,
            int optionalLength,
            int totalLength,
            IntPtr context);

        [DllImport("winhttp.dll", SetLastError = true)]
        private static extern bool WinHttpReceiveResponse(IntPtr request, IntPtr reserved);

        [DllImport("winhttp.dll", SetLastError = true)]
        private static extern bool WinHttpQueryHeaders(
            IntPtr request,
            uint infoLevel,
            IntPtr name,
            byte[] buffer,
            ref int length,
            IntPtr index);

        [DllImport("winhttp.dll", SetLastError = true)]
        private static extern bool WinHttpReadData(IntPtr request, byte[] buffer, int length, ref int read);

        [DllImport("winhttp.dll", SetLastError = true)]
        private static extern bool WinHttpCloseHandle(IntPtr handle);
    }
}
