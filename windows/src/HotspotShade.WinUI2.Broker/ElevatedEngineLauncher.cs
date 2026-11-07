using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using HotspotShade.WinUI2.Core.App;
using HotspotShade.WinUI2.Core.Engine;

namespace HotspotShade.WinUI2.Broker
{
    // The outcome of one Turn on launch. Engine is set only on success.
    internal sealed class ElevatedLaunchResult
    {
        public ElevatedLaunchResult(string code, ElevatedEngine engine)
        {
            Code = code ?? BrokerCodes.ElevationFailed;
            Engine = engine;
        }

        public string Code { get; private set; }

        public ElevatedEngine Engine { get; private set; }
    }

    // Start the elevated engine for Turn on. This is the only code in the
    // broker that asks Windows for administrator approval, and BrokerService
    // calls it only for the turn_on operation (ElevationPolicy).
    //
    // 1. Create the token pipe and the parent-liveness pipe. No handle is
    //    inheritable; the starter duplicates the read ends.
    // 2. Create a one-instance named pipe with a random name. Only an
    //    elevated process can open it.
    // 3. Start the packaged starter with the runas verb. Windows shows one
    //    UAC prompt. The only argument is the random pipe token.
    // 4. Accept the client only when its process id is the one that
    //    ShellExecuteEx returned.
    // 5. Ask the user engine for the pairing handoff. The frame goes into the
    //    handoff pipe; the broker never reads it.
    // 6. Send the three handle values and the port. The starter duplicates
    //    them into the elevated engine and answers with its process id.
    // 7. Open the engine process, check its image path, write the bearer
    //    secret, and keep the parent-liveness write end.
    //
    // Every failure closes every handle that the call created. Closing the
    // parent-liveness write end stops an engine that already started.
    internal static class ElevatedEngineLauncher
    {
        // The UAC prompt can wait for a person. After ShellExecuteEx returns,
        // the starter must connect quickly.
        private const uint ConnectMilliseconds = 30000;
        private const uint FrameMilliseconds = 15000;
        private const int TokenPipeBuffer = 4096;

        public static ElevatedLaunchResult Launch(
            string root,
            IntPtr handoffRead,
            int port,
            IntPtr ownerWindow,
            Func<bool> requestHandoff)
        {
            string starter = Path.Combine(root, "Elevate", ElevationProtocol.StarterFileName);
            string engine = Path.Combine(root, "Engine", EngineLaunchRules.ExecutableName);
            if (!File.Exists(starter) || !File.Exists(engine))
            {
                return new ElevatedLaunchResult(BrokerCodes.EngineMissing, null);
            }
            if (!File.Exists(Path.Combine(root, "Engine", "wintun.dll")))
            {
                return new ElevatedLaunchResult(BrokerCodes.AdapterDllMissing, null);
            }
            if (!InstallRules.IsProtectedPackageRoot(root, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)))
            {
                return new ElevatedLaunchResult(BrokerCodes.InstallUntrusted, null);
            }
            if (handoffRead == IntPtr.Zero)
            {
                return new ElevatedLaunchResult(BrokerCodes.HandoffUnsupported, null);
            }

            IntPtr tokenRead = IntPtr.Zero;
            IntPtr tokenWrite = IntPtr.Zero;
            IntPtr parentRead = IntPtr.Zero;
            IntPtr parentWrite = IntPtr.Zero;
            IntPtr starterProcess = IntPtr.Zero;
            IntPtr engineProcess = IntPtr.Zero;
            RendezvousPipe pipe = null;
            byte[] secret = null;
            bool success = false;
            try
            {
                if (!BrokerNative.CreatePipe(out tokenRead, out tokenWrite, IntPtr.Zero, TokenPipeBuffer))
                {
                    tokenRead = IntPtr.Zero;
                    tokenWrite = IntPtr.Zero;
                    return new ElevatedLaunchResult(BrokerCodes.ElevationFailed, null);
                }
                if (!BrokerNative.CreatePipe(out parentRead, out parentWrite, IntPtr.Zero, 0))
                {
                    parentRead = IntPtr.Zero;
                    parentWrite = IntPtr.Zero;
                    return new ElevatedLaunchResult(BrokerCodes.ElevationFailed, null);
                }

                string token = NewRendezvousToken();
                pipe = RendezvousPipe.Create(ElevationProtocol.PipeName(token));
                if (pipe == null)
                {
                    return new ElevatedLaunchResult(BrokerCodes.ElevationFailed, null);
                }

                BrokerNative.SHELLEXECUTEINFO info = new BrokerNative.SHELLEXECUTEINFO();
                info.cbSize = Marshal.SizeOf(typeof(BrokerNative.SHELLEXECUTEINFO));
                info.fMask = BrokerNative.SeeMaskNoCloseProcess | BrokerNative.SeeMaskNoAsync | BrokerNative.SeeMaskFlagNoUi;
                info.hwnd = ownerWindow;
                info.lpVerb = "runas";
                info.lpFile = starter;
                info.lpParameters = token;
                info.lpDirectory = Path.GetDirectoryName(starter);
                info.nShow = BrokerNative.SwHide;
                int shellError;
                if (!ShellExecuteOnSta(ref info, out shellError))
                {
                    return new ElevatedLaunchResult(
                        shellError == BrokerNative.ErrorCancelled ? BrokerCodes.ElevationCancelled : BrokerCodes.ElevationFailed,
                        null);
                }
                starterProcess = info.hProcess;
                if (starterProcess == IntPtr.Zero)
                {
                    return new ElevatedLaunchResult(BrokerCodes.ElevationFailed, null);
                }
                int starterId = BrokerNative.GetProcessId(starterProcess);

                if (!pipe.WaitForClient(starterProcess, ConnectMilliseconds))
                {
                    return new ElevatedLaunchResult(StarterExitCode(starterProcess), null);
                }
                if (starterId == 0 || pipe.ClientProcessId() != starterId)
                {
                    // Another elevated process reached the pipe first. Send
                    // it nothing.
                    return new ElevatedLaunchResult(BrokerCodes.ElevationFailed, null);
                }

                // The person approved the prompt and the starter is ready.
                // Only now does the user engine write the pairing frame.
                if (requestHandoff == null || !requestHandoff())
                {
                    return new ElevatedLaunchResult(BrokerCodes.HandoffFailed, null);
                }

                ElevationRequest request = new ElevationRequest(
                    port,
                    tokenRead.ToInt64(),
                    parentRead.ToInt64(),
                    handoffRead.ToInt64());
                if (!pipe.Write(ElevationProtocol.EncodeRequest(request), FrameMilliseconds))
                {
                    return new ElevatedLaunchResult(BrokerCodes.ElevationFailed, null);
                }
                byte[] reply = pipe.Read(ElevationProtocol.ReplyLength, FrameMilliseconds);
                ElevationReplyCode code;
                int engineId;
                if (reply == null || !ElevationProtocol.TryDecodeReply(reply, reply.Length, out code, out engineId))
                {
                    return new ElevatedLaunchResult(BrokerCodes.ElevatedEngineFailed, null);
                }
                if (code != ElevationReplyCode.Started)
                {
                    return new ElevatedLaunchResult(MapReply(code), null);
                }

                engineProcess = BrokerNative.OpenProcess(
                    BrokerNative.Synchronize | BrokerNative.ProcessQueryLimitedInformation,
                    false,
                    engineId);
                if (engineProcess == IntPtr.Zero || !BrokerNative.SamePath(BrokerNative.ImagePath(engineProcess), engine))
                {
                    return new ElevatedLaunchResult(BrokerCodes.ElevatedEngineFailed, null);
                }

                // The engine holds its own read ends now.
                BrokerNative.CloseHandle(tokenRead);
                tokenRead = IntPtr.Zero;
                BrokerNative.CloseHandle(parentRead);
                parentRead = IntPtr.Zero;

                secret = NewSecret();
                if (!WriteSecret(tokenWrite, secret))
                {
                    return new ElevatedLaunchResult(BrokerCodes.ElevatedEngineFailed, null);
                }
                BrokerNative.CloseHandle(tokenWrite);
                tokenWrite = IntPtr.Zero;

                ElevatedEngine started = new ElevatedEngine(port, engineId, engineProcess, parentWrite, secret);
                engineProcess = IntPtr.Zero;
                parentWrite = IntPtr.Zero;
                success = true;
                return new ElevatedLaunchResult(BrokerCodes.None, started);
            }
            catch (Exception)
            {
                return new ElevatedLaunchResult(BrokerCodes.ElevationFailed, null);
            }
            finally
            {
                if (!success && secret != null)
                {
                    Array.Clear(secret, 0, secret.Length);
                }
                if (pipe != null)
                {
                    pipe.Dispose();
                }
                Close(ref tokenRead);
                Close(ref tokenWrite);
                Close(ref parentRead);
                // Closing this end stops an engine that started before the
                // failure. The engine runs its own stop path.
                Close(ref parentWrite);
                if (engineProcess != IntPtr.Zero)
                {
                    BrokerNative.WaitForSingleObject(engineProcess, 5000);
                    Close(ref engineProcess);
                }
                Close(ref starterProcess);
            }
        }

        // ShellExecuteEx expects a single-threaded apartment. The broker runs
        // requests on thread-pool (MTA) threads, so the call runs on its own
        // STA thread and this thread waits for it. The prompt can wait for a
        // person, so the wait has no timeout; the call returns when the
        // person answers or Windows refuses.
        private static bool ShellExecuteOnSta(ref BrokerNative.SHELLEXECUTEINFO info, out int error)
        {
            BrokerNative.SHELLEXECUTEINFO local = info;
            bool ok = false;
            int lastError = 0;
            System.Threading.Thread thread = new System.Threading.Thread(delegate ()
            {
                ok = BrokerNative.ShellExecuteExW(ref local);
                lastError = ok ? 0 : Marshal.GetLastWin32Error();
            });
            thread.IsBackground = true;
            thread.SetApartmentState(System.Threading.ApartmentState.STA);
            thread.Start();
            thread.Join();
            info = local;
            error = lastError;
            return ok;
        }

        private static string MapReply(ElevationReplyCode code)
        {
            switch (code)
            {
                case ElevationReplyCode.OtherAccount:
                    return BrokerCodes.ElevationOtherAccount;
                case ElevationReplyCode.EngineMissing:
                    return BrokerCodes.EngineMissing;
                case ElevationReplyCode.AdapterDllMissing:
                    return BrokerCodes.AdapterDllMissing;
                case ElevationReplyCode.InstallUntrusted:
                    return BrokerCodes.InstallUntrusted;
                default:
                    return BrokerCodes.ElevatedEngineFailed;
            }
        }

        // The starter exits with an ElevationReplyCode value when it fails
        // before it connects.
        private static string StarterExitCode(IntPtr process)
        {
            if (BrokerNative.WaitForSingleObject(process, 0) != BrokerNative.WaitObject0)
            {
                return BrokerCodes.ElevationTimeout;
            }
            uint exit;
            if (!BrokerNative.GetExitCodeProcess(process, out exit))
            {
                return BrokerCodes.ElevationFailed;
            }
            if (exit == (uint)ElevationReplyCode.OtherAccount)
            {
                return BrokerCodes.ElevationOtherAccount;
            }
            return BrokerCodes.ElevationFailed;
        }

        private static string NewRendezvousToken()
        {
            byte[] bytes = new byte[ElevationProtocol.TokenHexLength / 2];
            using (RandomNumberGenerator generator = RandomNumberGenerator.Create())
            {
                generator.GetBytes(bytes);
            }
            StringBuilder text = new StringBuilder(ElevationProtocol.TokenHexLength);
            for (int index = 0; index < bytes.Length; index++)
            {
                text.Append(bytes[index].ToString("x2", System.Globalization.CultureInfo.InvariantCulture));
            }
            return text.ToString();
        }

        // A new 64-character lowercase hex bearer secret for the elevated
        // engine. It is never on a command line or in the environment.
        private static byte[] NewSecret()
        {
            using (EngineLaunchSecret value = EngineLaunchSecret.CreateRandom())
            using (MemoryStream memory = new MemoryStream())
            {
                try
                {
                    value.WriteTo(memory);
                    byte[] copy = new byte[EngineLaunchRules.SecretHexLength];
                    Array.Copy(memory.GetBuffer(), copy, copy.Length);
                    return copy;
                }
                finally
                {
                    byte[] buffer = memory.GetBuffer();
                    Array.Clear(buffer, 0, buffer.Length);
                }
            }
        }

        private static bool WriteSecret(IntPtr handle, byte[] secret)
        {
            byte[] buffer = new byte[EngineLaunchRules.SecretWriteLength];
            try
            {
                Buffer.BlockCopy(secret, 0, buffer, 0, EngineLaunchRules.SecretHexLength);
                buffer[EngineLaunchRules.SecretHexLength] = EngineLaunchRules.SecretTerminator;
                int written;
                return BrokerNative.WriteFile(handle, buffer, buffer.Length, out written, IntPtr.Zero)
                    && written == buffer.Length;
            }
            finally
            {
                Array.Clear(buffer, 0, buffer.Length);
            }
        }

        private static void Close(ref IntPtr handle)
        {
            if (handle != IntPtr.Zero)
            {
                BrokerNative.CloseHandle(handle);
                handle = IntPtr.Zero;
            }
        }
    }
}
