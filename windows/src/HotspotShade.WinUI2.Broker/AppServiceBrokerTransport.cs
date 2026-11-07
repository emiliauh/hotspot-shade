using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.App;
using Windows.ApplicationModel;
using Windows.ApplicationModel.AppService;
using Windows.Foundation.Collections;

namespace HotspotShade.WinUI2.Broker
{
    // The broker side of the documented UWP full-trust app service pattern.
    // The UWP app hosts the app service in process and the full-trust broker
    // is the client. The broker opens no listener, so an unrelated local
    // process has no endpoint to reach. The broker connects only to its own
    // package family name, and the app accepts only a caller with that
    // package family name.
    //
    // Every request is a ValueSet of short strings, checked by
    // BrokerProtocol.TryValidate. The reply carries the fixed reply fields.
    // The engine bearer secret and the source device token never cross this
    // boundary.
    internal sealed class AppServiceBrokerTransport
    {
        private const int MaxConcurrentRequests = 8;

        private readonly BrokerService service;
        private readonly Action<int> onHello;
        private readonly SemaphoreSlim slots = new SemaphoreSlim(MaxConcurrentRequests, MaxConcurrentRequests);
        private readonly TaskCompletionSource<bool> closedSource =
            new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        private AppServiceConnection connection;
        private int closed;

        public AppServiceBrokerTransport(BrokerService service, Action<int> onHello)
        {
            if (service == null)
            {
                throw new ArgumentNullException("service");
            }
            this.service = service;
            this.onHello = onHello;
        }

        // Completes when the app closes the connection, for example when
        // Windows suspends the window. The broker keeps the engines while the
        // app process lives and connects again when the app asks.
        public Task Closed
        {
            get { return closedSource.Task; }
        }

        public async Task<bool> ConnectAsync(TimeSpan retryWindow)
        {
            DateTime deadline = DateTime.UtcNow + retryWindow;
            while (true)
            {
                if (Volatile.Read(ref closed) != 0)
                {
                    return false;
                }
                // A connection that failed to open is not reused. Every
                // attempt gets a fresh AppServiceConnection.
                AppServiceConnection created = new AppServiceConnection();
                created.AppServiceName = BrokerProtocol.ServiceName;
                created.PackageFamilyName = Package.Current.Id.FamilyName;
                created.RequestReceived += OnRequestReceived;
                created.ServiceClosed += OnServiceClosed;
                connection = created;

                AppServiceConnectionStatus status = AppServiceConnectionStatus.Unknown;
                bool thrown = false;
                try
                {
                    status = await created.OpenAsync();
                }
                catch (Exception)
                {
                    // An activation race throws instead of returning a
                    // status. Treat it as retryable inside the window.
                    thrown = true;
                }
                if (!thrown && status == AppServiceConnectionStatus.Success)
                {
                    return true;
                }
                if ((!thrown && !IsRetryable(status)) || DateTime.UtcNow >= deadline)
                {
                    Close();
                    return false;
                }
                DiscardAttempt(created);
                await Task.Delay(250).ConfigureAwait(false);
            }
        }

        private void DiscardAttempt(AppServiceConnection attempt)
        {
            attempt.RequestReceived -= OnRequestReceived;
            attempt.ServiceClosed -= OnServiceClosed;
            if (ReferenceEquals(connection, attempt))
            {
                connection = null;
            }
            try
            {
                ((IDisposable)attempt).Dispose();
            }
            catch (Exception)
            {
            }
        }

        public void Close()
        {
            if (Interlocked.Exchange(ref closed, 1) != 0)
            {
                return;
            }
            AppServiceConnection current = connection;
            connection = null;
            if (current != null)
            {
                current.RequestReceived -= OnRequestReceived;
                current.ServiceClosed -= OnServiceClosed;
                try
                {
                    ((IDisposable)current).Dispose();
                }
                catch (Exception)
                {
                }
            }
            closedSource.TrySetResult(true);
        }

        private void OnRequestReceived(AppServiceConnection sender, AppServiceRequestReceivedEventArgs args)
        {
            AppServiceDeferral deferral = args.GetDeferral();
            HandleAsync(args.Request, deferral);
        }

        private async void HandleAsync(AppServiceRequest request, AppServiceDeferral deferral)
        {
            bool entered = false;
            try
            {
                entered = await slots.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
                BrokerReply reply;
                if (!entered)
                {
                    reply = BrokerReply.Failure(BrokerCodes.Busy);
                }
                else if (Volatile.Read(ref closed) != 0)
                {
                    reply = BrokerReply.Failure(BrokerCodes.Closed);
                }
                else
                {
                    BrokerRequest parsed;
                    string code;
                    if (!BrokerProtocol.TryValidate(Copy(request.Message), out parsed, out code))
                    {
                        reply = BrokerReply.Failure(code);
                    }
                    else if (parsed.Op == BrokerOps.Hello)
                    {
                        if (onHello != null)
                        {
                            onHello(parsed.ProcessId);
                        }
                        reply = new BrokerReply(true, 200, BrokerCodes.None, "{\"ok\":true}", null, null, null);
                    }
                    else
                    {
                        reply = await service.HandleAsync(parsed).ConfigureAwait(false);
                    }
                }
                await request.SendResponseAsync(ToValueSet(reply));
            }
            catch (Exception)
            {
                // The app service may have closed while the operation ran.
                // The operation is bounded and the caller is gone.
            }
            finally
            {
                if (entered)
                {
                    slots.Release();
                }
                deferral.Complete();
            }
        }

        private void OnServiceClosed(AppServiceConnection sender, AppServiceClosedEventArgs args)
        {
            Close();
        }

        private static List<KeyValuePair<string, object>> Copy(ValueSet message)
        {
            List<KeyValuePair<string, object>> pairs = new List<KeyValuePair<string, object>>();
            if (message == null)
            {
                return pairs;
            }
            foreach (string key in message.Keys)
            {
                if (pairs.Count > BrokerProtocol.MaxRequestFields)
                {
                    break;
                }
                pairs.Add(new KeyValuePair<string, object>(key, message[key]));
            }
            return pairs;
        }

        private static ValueSet ToValueSet(BrokerReply reply)
        {
            ValueSet message = new ValueSet();
            foreach (KeyValuePair<string, string> pair in reply.ToFields())
            {
                message.Add(pair.Key, pair.Value);
            }
            return message;
        }

        private static bool IsRetryable(AppServiceConnectionStatus status)
        {
            return status == AppServiceConnectionStatus.AppUnavailable
                || status == AppServiceConnectionStatus.AppServiceUnavailable;
        }
    }
}
