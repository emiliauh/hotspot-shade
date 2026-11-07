using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.App;
using Windows.ApplicationModel;
using Windows.ApplicationModel.AppService;
using Windows.ApplicationModel.Background;
using Windows.Foundation.Collections;
using Windows.Foundation.Metadata;

namespace HotspotShade.WinUI2.Services
{
    // The window side of the app-service connection to the full-trust
    // broker. The window runs in an AppContainer: it cannot reach the
    // loopback engine and never sees a bearer secret. It starts the packaged
    // broker with FullTrustProcessLauncher, which asks for no administrator
    // approval, and accepts the connection only from its own package.
    public sealed class BrokerConnection : IBrokerChannel
    {
        private static readonly TimeSpan AttachBudget = TimeSpan.FromSeconds(15);

        private readonly object gate = new object();
        private AppServiceConnection connection;
        private BackgroundTaskDeferral deferral;
        private TaskCompletionSource<bool> attached = new TaskCompletionSource<bool>();
        private bool launching;

        public static readonly BrokerConnection Instance = new BrokerConnection();

        private BrokerConnection()
        {
        }

        // Raised on the connection thread when the broker connects or the
        // connection closes.
        public event EventHandler Changed;

        // The owner window for the UAC prompt at Turn on.
        public long OwnerWindow { get; set; }

        public bool IsConnected
        {
            get
            {
                lock (gate)
                {
                    return connection != null;
                }
            }
        }

        // The last launch failure, or null.
        public string LaunchFailure { get; private set; }

        // Start the broker if no connection exists. A running broker that
        // lost its connection after a suspend is asked to connect again: the
        // second copy signals the first and exits.
        public async Task EnsureStartedAsync()
        {
            lock (gate)
            {
                if (connection != null || launching)
                {
                    return;
                }
                launching = true;
            }
            try
            {
                if (!ApiInformation.IsApiContractPresent("Windows.ApplicationModel.FullTrustAppContract", 1, 0))
                {
                    LaunchFailure = AppText.BrokerMissing;
                    return;
                }
                await FullTrustProcessLauncher.LaunchFullTrustProcessForCurrentAppAsync();
                LaunchFailure = null;
            }
            catch (Exception)
            {
                LaunchFailure = AppText.BrokerMissing;
            }
            finally
            {
                lock (gate)
                {
                    launching = false;
                }
                RaiseChanged();
            }
        }

        // Called from App.OnBackgroundActivated. A caller from another package
        // is refused.
        public void Attach(IBackgroundTaskInstance task, AppServiceTriggerDetails details)
        {
            string own;
            try
            {
                own = Package.Current.Id.FamilyName;
            }
            catch (Exception)
            {
                own = null;
            }
            if (details == null || own == null
                || !string.Equals(details.CallerPackageFamilyName, own, StringComparison.Ordinal)
                || details.Name != BrokerProtocol.ServiceName)
            {
                BackgroundTaskDeferral refused = task.GetDeferral();
                refused.Complete();
                return;
            }
            AppServiceConnection created = details.AppServiceConnection;
            BackgroundTaskDeferral held = task.GetDeferral();
            TaskCompletionSource<bool> signal;
            lock (gate)
            {
                Detach();
                connection = created;
                deferral = held;
                signal = attached;
            }
            created.ServiceClosed += OnServiceClosed;
            task.Canceled += OnCanceled;
            signal.TrySetResult(true);
            Task ignored = SayHelloAsync(created);
            RaiseChanged();
        }

        public async Task<BrokerReply> SendAsync(IDictionary<string, string> fields)
        {
            AppServiceConnection current;
            Task<bool> wait;
            lock (gate)
            {
                current = connection;
                wait = attached.Task;
            }
            if (current == null)
            {
                Task first = await Task.WhenAny(wait, Task.Delay(AttachBudget)).ConfigureAwait(true);
                if (first != wait)
                {
                    return BrokerReply.Failure(BrokerCodes.Closed);
                }
                lock (gate)
                {
                    current = connection;
                }
                if (current == null)
                {
                    return BrokerReply.Failure(BrokerCodes.Closed);
                }
            }

            string op;
            fields.TryGetValue(BrokerProtocol.OpField, out op);
            ValueSet message = new ValueSet();
            foreach (KeyValuePair<string, string> pair in fields)
            {
                message.Add(pair.Key, pair.Value);
            }
            if (op == BrokerOps.TurnOn && OwnerWindow > 0)
            {
                message[BrokerProtocol.WindowField] = OwnerWindow.ToString(CultureInfo.InvariantCulture);
            }
            try
            {
                Task<AppServiceResponse> send = current.SendMessageAsync(message).AsTask();
                Task finished = await Task.WhenAny(send, Task.Delay(Budget(op))).ConfigureAwait(true);
                if (finished != send)
                {
                    return BrokerReply.Failure(BrokerCodes.Timeout);
                }
                AppServiceResponse response = send.Result;
                if (response.Status != AppServiceResponseStatus.Success || response.Message == null)
                {
                    return BrokerReply.Failure(BrokerCodes.Closed);
                }
                Dictionary<string, string> reply = new Dictionary<string, string>(StringComparer.Ordinal);
                foreach (string key in response.Message.Keys)
                {
                    string value = response.Message[key] as string;
                    if (value != null)
                    {
                        reply[key] = value;
                    }
                }
                return BrokerReply.FromFields(reply);
            }
            catch (Exception)
            {
                return BrokerReply.Failure(BrokerCodes.Closed);
            }
        }

        // The broker keeps the engines while this process lives. It learns
        // the process from this message.
        private static async Task SayHelloAsync(AppServiceConnection created)
        {
            try
            {
                uint id = Windows.System.Diagnostics.ProcessDiagnosticInfo.GetForCurrentProcess().ProcessId;
                ValueSet hello = new ValueSet();
                hello.Add(BrokerProtocol.OpField, BrokerOps.Hello);
                hello.Add(BrokerProtocol.ProcessField, id.ToString(CultureInfo.InvariantCulture));
                await created.SendMessageAsync(hello);
            }
            catch (Exception)
            {
            }
        }

        // A Turn on waits for a UAC prompt and a tunnel start. A Turn off
        // waits for the engine stop and exit. Status reads are short.
        private static TimeSpan Budget(string op)
        {
            switch (op)
            {
                case BrokerOps.TurnOn:
                    return TimeSpan.FromMinutes(5);
                case BrokerOps.TurnOff:
                    return TimeSpan.FromMinutes(2);
                case BrokerOps.Pair:
                case BrokerOps.PairCancel:
                case BrokerOps.Forget:
                case BrokerOps.Probe:
                    return TimeSpan.FromSeconds(20);
                default:
                    return TimeSpan.FromSeconds(10);
            }
        }

        private void OnServiceClosed(AppServiceConnection sender, AppServiceClosedEventArgs args)
        {
            lock (gate)
            {
                if (connection == sender)
                {
                    Detach();
                }
            }
            RaiseChanged();
        }

        private void OnCanceled(IBackgroundTaskInstance sender, BackgroundTaskCancellationReason reason)
        {
            lock (gate)
            {
                Detach();
            }
            RaiseChanged();
        }

        // Called with the gate held.
        private void Detach()
        {
            if (connection != null)
            {
                connection.ServiceClosed -= OnServiceClosed;
                connection = null;
            }
            if (deferral != null)
            {
                try
                {
                    deferral.Complete();
                }
                catch (Exception)
                {
                }
                deferral = null;
            }
            if (attached.Task.IsCompleted)
            {
                attached = new TaskCompletionSource<bool>();
            }
        }

        private void RaiseChanged()
        {
            EventHandler handler = Changed;
            if (handler != null)
            {
                handler(this, EventArgs.Empty);
            }
        }
    }
}
