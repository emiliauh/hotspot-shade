using System;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost
{
    // Proves the configured installing account is a user account before the
    // service creates a pipe or reports Running. The core SID check is a form
    // check only. A custom group can share the S-1-5-21 form, so this gate
    // requires a positive LookupAccountSid SidTypeUser result.
    public sealed class EngineServiceInstalledAccountGate
    {
        private readonly string installedUserSid;
        private readonly IEngineServiceAccountTypeInspector accountTypes;
        private readonly TimeSpan timeout;

        public EngineServiceInstalledAccountGate(
            string installedUserSid,
            IEngineServiceAccountTypeInspector accountTypes,
            TimeSpan timeout)
        {
            if (!EngineServiceSidPolicy.IsUsableInstalledUserSid(installedUserSid))
            {
                throw new ArgumentException(
                    "the installed account must be an allowed user SID form",
                    "installedUserSid");
            }
            if (accountTypes == null)
            {
                throw new ArgumentNullException("accountTypes");
            }
            if (timeout <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException("timeout");
            }
            this.installedUserSid = installedUserSid;
            this.accountTypes = accountTypes;
            this.timeout = timeout;
        }

        public string InstalledUserSid
        {
            get { return installedUserSid; }
        }

        public async Task<EngineServiceCallerVerdict> VerifyAsync(
            CancellationToken cancellationToken)
        {
            EngineServiceAccountTypeResult result;
            try
            {
                Task<EngineServiceAccountTypeResult> task =
                    accountTypes.InspectAsync(installedUserSid, cancellationToken);
                if (task == null)
                {
                    return EngineServiceCallerVerdict.Deny(
                        EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                        EngineServiceEventCodes.CallerAccountTypeFailed);
                }
                result = await WithTimeout(task, timeout, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return EngineServiceCallerVerdict.Deny(
                    cancellationToken.IsCancellationRequested
                        ? EngineProtocol.ErrorCodes.Closed
                        : EngineProtocol.ErrorCodes.Timeout,
                    EngineServiceEventCodes.CallerAccountTypeFailed);
            }
            catch (Exception)
            {
                return EngineServiceCallerVerdict.Deny(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    EngineServiceEventCodes.CallerAccountTypeFailed);
            }

            if (result == null || !result.Ok)
            {
                return EngineServiceCallerVerdict.Deny(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    EngineServiceEventCodes.CallerAccountTypeFailed);
            }
            if (result.Type != EngineServiceAccountType.User)
            {
                return EngineServiceCallerVerdict.Deny(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    EngineServiceEventCodes.CallerAccountTypeNotUser);
            }
            return EngineServiceCallerVerdict.Allow(EngineServiceEventCodes.SameUserCaller);
        }

        private static async Task<EngineServiceAccountTypeResult> WithTimeout(
            Task<EngineServiceAccountTypeResult> task,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            if (task.IsCompleted)
            {
                return await task.ConfigureAwait(false);
            }
            Task completed = await Task.WhenAny(
                task,
                Task.Delay(timeout, cancellationToken)).ConfigureAwait(false);
            if (completed != task)
            {
                cancellationToken.ThrowIfCancellationRequested();
                throw new TimeoutException();
            }
            return await task.ConfigureAwait(false);
        }
    }
}
