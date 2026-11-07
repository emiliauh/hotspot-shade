using System;
using System.Threading;
using System.Threading.Tasks;

namespace HotspotShade.WinUI2.ServiceHost
{
    // Runs one sensitive action on a new thread. The thread pool is not used
    // because a pool thread may carry an impersonation token from an earlier
    // worker, and a thread that may hold a caller token must never return to
    // the pool. A new thread inherits the process token, not another thread's
    // token, and it exits after the action returns.
    public interface IEngineServiceCleanThreadRunner
    {
        Task<T> RunAsync<T>(Func<T> action, CancellationToken cancellationToken);
    }

    public sealed class EngineServiceCleanThreadDispatcher :
        IEngineServiceStopDispatcher,
        IEngineServiceCleanThreadRunner
    {
        public Task DispatchAsync(Action stopAction, CancellationToken cancellationToken)
        {
            if (stopAction == null)
            {
                throw new ArgumentNullException("stopAction");
            }
            Task<bool> task = RunThread<bool>(
                delegate
                {
                    stopAction();
                    return true;
                },
                "HotspotShadeServiceStop");
            return task;
        }

        public Task<T> RunAsync<T>(Func<T> action, CancellationToken cancellationToken)
        {
            if (action == null)
            {
                throw new ArgumentNullException("action");
            }
            if (cancellationToken.IsCancellationRequested)
            {
                TaskCompletionSource<T> canceled =
                    new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
                canceled.TrySetCanceled();
                return canceled.Task;
            }
            return RunThread<T>(action, "HotspotShadeServiceClean");
        }

        private static Task<T> RunThread<T>(Func<T> action, string name)
        {
            TaskCompletionSource<T> completion =
                new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
            Thread thread = new Thread(new ThreadStart(delegate
            {
                try
                {
                    completion.TrySetResult(action());
                }
                catch (Exception error)
                {
                    completion.TrySetException(error);
                }
            }));
            thread.IsBackground = true;
            thread.Name = name;
            try
            {
                thread.Start();
            }
            catch (Exception error)
            {
                completion.TrySetException(error);
            }
            return completion.Task;
        }
    }
}
