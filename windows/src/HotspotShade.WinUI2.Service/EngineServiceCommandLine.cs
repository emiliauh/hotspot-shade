using System;
using System.Collections.Generic;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.ServiceHost;

namespace HotspotShade.WinUI2.Service
{
    // The install-time service configuration. The values are not secrets. A
    // service installer sets them on the service command line, which only an
    // administrator can change. The source device token, the identity key,
    // and any bearer secret are never accepted here.
    public sealed class EngineServiceConfiguration
    {
        public EngineServiceConfiguration(
            string serviceInstanceId,
            string installedUserSid,
            string serviceBinaryPath,
            string engineImagePath,
            string stateFilePath)
        {
            string normalizedStatePath;
            if (!TryNormalizeStatePath(stateFilePath, out normalizedStatePath))
            {
                throw new ArgumentException(
                    "the durable state path must be an absolute local drive file path",
                    "stateFilePath");
            }

            Transport = new EngineServiceTransportOptions(
                serviceInstanceId,
                installedUserSid,
                serviceBinaryPath,
                engineImagePath);
            StateFilePath = normalizedStatePath;
        }

        public EngineServiceTransportOptions Transport { get; private set; }

        // A read-only frame written by the installer. This build never writes
        // this file.
        public string StateFilePath { get; private set; }

        // The durable state path uses the same strict Windows local drive
        // rule as the installed image paths. A UNC path, a relative path, a
        // dot segment, and a trailing dot or space are refused before any
        // file call.
        public static bool TryNormalizeStatePath(string value, out string normalized)
        {
            return WindowsServicePathPolicy.TryNormalize(value, out normalized);
        }
    }

    // Parses the service command line. Every option is required exactly
    // once, an unknown option is refused, and no value is echoed in an error.
    // The SCM supplies these arguments from the installed service record.
    public static class EngineServiceCommandLine
    {
        public const string InstanceOption = "--instance";
        public const string InstalledUserSidOption = "--installed-user-sid";
        public const string ServiceBinaryOption = "--service-binary";
        public const string EngineImageOption = "--engine-image";
        public const string StateFileOption = "--state-file";

        private const int MaxArguments = 32;

        public static bool TryParse(
            IReadOnlyList<string> arguments,
            out EngineServiceConfiguration configuration,
            out string error)
        {
            configuration = null;
            error = "invalid arguments";
            if (arguments == null
                || arguments.Count == 0
                || arguments.Count > MaxArguments
                || (arguments.Count % 2) != 0)
            {
                return false;
            }

            string instance = null;
            string sid = null;
            string serviceBinary = null;
            string engineImage = null;
            string stateFile = null;

            for (int index = 0; index < arguments.Count; index += 2)
            {
                string option = arguments[index];
                string value = arguments[index + 1];
                if (string.IsNullOrEmpty(option)
                    || string.IsNullOrEmpty(value)
                    || value.StartsWith("--", StringComparison.Ordinal))
                {
                    return false;
                }

                if (string.Equals(option, InstanceOption, StringComparison.Ordinal))
                {
                    if (instance != null)
                    {
                        error = "duplicate option";
                        return false;
                    }
                    instance = value;
                }
                else if (string.Equals(option, InstalledUserSidOption, StringComparison.Ordinal))
                {
                    if (sid != null)
                    {
                        error = "duplicate option";
                        return false;
                    }
                    sid = value;
                }
                else if (string.Equals(option, ServiceBinaryOption, StringComparison.Ordinal))
                {
                    if (serviceBinary != null)
                    {
                        error = "duplicate option";
                        return false;
                    }
                    serviceBinary = value;
                }
                else if (string.Equals(option, EngineImageOption, StringComparison.Ordinal))
                {
                    if (engineImage != null)
                    {
                        error = "duplicate option";
                        return false;
                    }
                    engineImage = value;
                }
                else if (string.Equals(option, StateFileOption, StringComparison.Ordinal))
                {
                    if (stateFile != null)
                    {
                        error = "duplicate option";
                        return false;
                    }
                    stateFile = value;
                }
                else
                {
                    error = "unknown option";
                    return false;
                }
            }

            if (instance == null
                || sid == null
                || serviceBinary == null
                || engineImage == null
                || stateFile == null)
            {
                error = "missing required option";
                return false;
            }

            try
            {
                configuration = new EngineServiceConfiguration(
                    instance,
                    sid,
                    serviceBinary,
                    engineImage,
                    stateFile);
                error = "";
                return true;
            }
            catch (ArgumentException)
            {
                error = "invalid configuration";
                return false;
            }
            catch (Exception)
            {
                error = "invalid configuration";
                return false;
            }
        }
    }

    // Fixed process exit codes. A nonzero value is paired with the SCM
    // ERROR_SERVICE_SPECIFIC_ERROR status, so the startup failure class is
    // visible without a log that could hold a path, SID, or token.
    internal static class EngineServiceScmExitCodes
    {
        public const int Success = 0;
        public const int Configuration = 1;
        public const int Platform = 2;
        public const int AccountRejected = 3;
        public const int StateNotTrusted = 4;
        public const int ListenerUnavailable = 5;
        public const int StopTimeout = 6;
        public const int Internal = 7;
        public const int EngineUnavailable = 8;
        public const int Disabled = 9;
        public const int GenerationFailed = 10;

        public static int ForDispatcherError(int error)
        {
            return error == WindowsServiceControlNativeMethods.ErrorFailedServiceControlConnect
                ? Platform
                : Internal;
        }

        public static int ForHostResult(
            EngineServiceHostResult result,
            bool stopRequested)
        {
            if (result == null)
            {
                return GenerationFailed;
            }
            if (result.Ok)
            {
                return Success;
            }
            if (result.Disabled)
            {
                return Disabled;
            }

            if (result.Code == EngineProtocol.ErrorCodes.Closed)
            {
                // A requested service stop is a clean stop even though the
                // host reports that no generation ran.
                return stopRequested ? Success : GenerationFailed;
            }
            if (result.Code == EngineProtocol.ErrorCodes.BoundaryAuthFailed)
            {
                return AccountRejected;
            }
            if (result.Code == EngineProtocol.ErrorCodes.CleanupUnknown
                || result.Code == EngineProtocol.ErrorCodes.CleanupPending
                || result.Code == EngineProtocol.ErrorCodes.CleanupBlocked)
            {
                return StateNotTrusted;
            }
            if (result.Code == EngineProtocol.ErrorCodes.BoundaryBusy)
            {
                return ListenerUnavailable;
            }
            if (result.Code == EngineProtocol.ErrorCodes.EngineStopTimeout)
            {
                return StopTimeout;
            }
            if (result.Code == EngineProtocol.ErrorCodes.Internal)
            {
                return Internal;
            }
            if (result.Code == EngineProtocol.ErrorCodes.EngineUnavailable
                || result.Code == EngineProtocol.ErrorCodes.Unsupported)
            {
                return EngineUnavailable;
            }
            return GenerationFailed;
        }
    }
}
