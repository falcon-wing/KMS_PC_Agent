
using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Net;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

namespace SecureTrustAgent.TRANS
{
    public sealed class ClientDisconnectTokenFactory
    {
        private readonly HttpListenerHashtable _hashtable;
        private readonly Func<HttpListenerRequest, ulong> _connectionIdFactory = GetConnectionId();

        public ClientDisconnectTokenFactory(HttpListener httpListener)
        {
            _hashtable = new HttpListenerHashtable(GetRegisterForDisconnectNotification(httpListener));

            lock (GetInternalLock(httpListener))
            {
                var hashtable = GetDisconnectResults(httpListener);
                if (null != hashtable)
                    throw new InvalidOperationException();

                SetDisconnectResults(httpListener, Hashtable.Synchronized(_hashtable));
            }
        }

        public CancellationToken GetClientDisconnectToken(HttpListenerRequest request)
        {
            var connectionId = _connectionIdFactory(request);
            // ReSharper disable once InconsistentlySynchronizedField
            return _hashtable.GetClientDisconnectToken(connectionId);
        }

        private static object GetInternalLock(HttpListener httpListener)
        {
            var internalLock = typeof(HttpListener)
                .GetField("m_InternalLock", BindingFlags.Instance | BindingFlags.NonPublic);

            if (null == internalLock)
                throw new InvalidOperationException();

            return internalLock.GetValue(httpListener);
        }

        private static object GetDisconnectResults(HttpListener httpListener)
        {
            var disconnectResults = typeof(HttpListener)
                .GetField("m_DisconnectResults", BindingFlags.Instance | BindingFlags.NonPublic);

            if (null == disconnectResults)
                throw new InvalidOperationException();

            return disconnectResults.GetValue(httpListener);
        }

        private static void SetDisconnectResults(HttpListener httpListener, Hashtable hashtable)
        {
            var disconnectResults = typeof(HttpListener)
                .GetField("m_DisconnectResults", BindingFlags.Instance | BindingFlags.NonPublic);

            if (null == disconnectResults)
                throw new InvalidOperationException();

            disconnectResults.SetValue(httpListener, hashtable);
        }

        private static Func<HttpListenerRequest, ulong> GetConnectionId()
        {
            var field = typeof(HttpListenerRequest).GetField("m_ConnectionId",
              BindingFlags.Instance | BindingFlags.NonPublic);

            if (null == field)
                throw new InvalidOperationException();

            return request => (ulong)field.GetValue(request);
        }

        private static Func<ulong, IAsyncResult> GetRegisterForDisconnectNotification(HttpListener httpListener)
        {
            var registerForDisconnectNotification = typeof(HttpListener)
              .GetMethod("RegisterForDisconnectNotification", BindingFlags.Instance | BindingFlags.NonPublic);

            if (null == registerForDisconnectNotification)
                throw new InvalidOperationException();

            var finishOwningDisconnectHandling =
              typeof(HttpListener).GetNestedType("DisconnectAsyncResult", BindingFlags.NonPublic)
                .GetMethod("FinishOwningDisconnectHandling", BindingFlags.Instance | BindingFlags.NonPublic);

            if (null == finishOwningDisconnectHandling)
                throw new InvalidOperationException();

            IAsyncResult RegisterForDisconnectNotification(ulong connectionId)
            {
                var invokeAttr = new object[] { connectionId, null };
                registerForDisconnectNotification.Invoke(httpListener, invokeAttr);

                var disconnectedAsyncResult = invokeAttr[1];
                if (null != disconnectedAsyncResult)
                    finishOwningDisconnectHandling.Invoke(disconnectedAsyncResult, null);

                return disconnectedAsyncResult as IAsyncResult;
            }

            return RegisterForDisconnectNotification;
        }

        private sealed class HttpListenerHashtable : Hashtable
        {
            private readonly ConcurrentDictionary<ulong, CancellationTokenSource> _clientDisconnectTokens =
              new ConcurrentDictionary<ulong, CancellationTokenSource>();

            private readonly Func<ulong, IAsyncResult> _registerForDisconnectNotification;

            public HttpListenerHashtable(Func<ulong, IAsyncResult> registerForDisconnectNotification)
                => _registerForDisconnectNotification = registerForDisconnectNotification;

            public CancellationToken GetClientDisconnectToken(ulong connectionId)
            {
                if (_clientDisconnectTokens.TryGetValue(connectionId, out var result))
                    return result.Token;

                result = _clientDisconnectTokens.GetOrAdd(connectionId, new CancellationTokenSource());

                var asyncResult = _registerForDisconnectNotification(connectionId);

                if (null == asyncResult)
                {
                    _clientDisconnectTokens.TryRemove(connectionId, out _);
                    Cancel(result);
                }

                return result.Token;
            }

            public override void Remove(object key)
            {
                base.Remove(key);

                var connectionId = (ulong)key;
                if (!_clientDisconnectTokens.TryRemove(connectionId, out var cancellationTokenSource))
                    return;

                Cancel(cancellationTokenSource);
            }

            private static void Cancel(CancellationTokenSource cancellationTokenSource)
            {
                // Use TaskScheduler.UnobservedTaskException for caller to catch exceptions
                Task.Run(cancellationTokenSource.Cancel);
            }
        }
    }
}
