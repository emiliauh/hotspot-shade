using System;

namespace HotspotShade.WinUI2.Broker
{
    // One copy of the loopback endpoint for the current engine process. The
    // secret is a copy of the per-launch bearer secret. A caller clears it as
    // soon as the request is finished. Nothing here writes to a log, a file,
    // or a command line.
    internal sealed class EngineHttpEndpoint
    {
        private readonly byte[] secret;

        public EngineHttpEndpoint(int port, byte[] secret, DateTime startedAtUtc)
        {
            if (secret == null || secret.Length != 64)
            {
                throw new ArgumentException("the endpoint needs a 64 character secret", "secret");
            }
            Port = port;
            StartedAtUtc = startedAtUtc;
            this.secret = new byte[secret.Length];
            Array.Copy(secret, this.secret, secret.Length);
        }

        public int Port { get; private set; }

        public DateTime StartedAtUtc { get; private set; }

        public byte[] CopySecret()
        {
            byte[] copy = new byte[secret.Length];
            Array.Copy(secret, copy, secret.Length);
            return copy;
        }

        public void Clear()
        {
            Array.Clear(secret, 0, secret.Length);
        }
    }
}
