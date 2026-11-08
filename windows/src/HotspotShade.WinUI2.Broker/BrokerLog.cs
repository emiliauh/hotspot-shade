using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using HotspotShade.WinUI2.Core.App;
using Windows.Storage;

namespace HotspotShade.WinUI2.Broker
{
    // The broker startup log. It holds fixed words and numbers only: a path,
    // a port, a handle, a ValueSet value, a token, or user data is never
    // passed here. Every write is bounded to 200 lines and 16 KB, and every
    // error is swallowed so logging can never change what the broker does.
    internal static class BrokerLog
    {
        private const string FallbackFolder = "HotspotShade";
        private static readonly object Gate = new object();

        public static void Write(
            string stage,
            string code,
            string status = null,
            int? attempt = null,
            int? win32 = null,
            int? hresult = null)
        {
            try
            {
                string line = BrokerLogFormat.Format(
                    DateTime.UtcNow,
                    stage,
                    code,
                    status,
                    attempt,
                    win32,
                    hresult);
                lock (Gate)
                {
                    Append(line);
                }
            }
            catch (Exception)
            {
                // A log failure must not change the broker lifetime.
            }
        }

        private static void Append(string line)
        {
            string package = PackagePath();
            if (package != null)
            {
                try
                {
                    AppendTo(package, line);
                    return;
                }
                catch (Exception)
                {
                    // The package folder exists but the write failed. Try the
                    // plain local folder once.
                }
            }
            string fallback = FallbackPath();
            if (fallback == null)
            {
                return;
            }
            try
            {
                AppendTo(fallback, line);
            }
            catch (Exception)
            {
                // A log failure must not change the broker lifetime.
            }
        }

        private static void AppendTo(string path, string line)
        {
            List<string> lines = new List<string>();
            using (FileStream stream = new FileStream(
                path,
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.ReadWrite))
            {
                stream.Seek(0, SeekOrigin.Begin);
                using (StreamReader reader = new StreamReader(stream, Encoding.UTF8, true, 4096, true))
                {
                    string existing;
                    while ((existing = reader.ReadLine()) != null)
                    {
                        lines.Add(existing);
                    }
                }
                lines.Add(line);
                IList<string> bounded = BrokerLogFormat.Bound(lines);
                stream.SetLength(0);
                stream.Seek(0, SeekOrigin.Begin);
                using (StreamWriter writer = new StreamWriter(stream, new UTF8Encoding(false), 4096, true))
                {
                    writer.NewLine = "\n";
                    for (int index = 0; index < bounded.Count; index++)
                    {
                        writer.WriteLine(bounded[index]);
                    }
                    writer.Flush();
                }
            }
        }

        // The package local folder is the real location.
        private static string PackagePath()
        {
            try
            {
                StorageFolder folder = ApplicationData.Current.LocalFolder;
                if (folder != null && !string.IsNullOrEmpty(folder.Path))
                {
                    return Path.Combine(folder.Path, BrokerLogFormat.FileName);
                }
            }
            catch (Exception)
            {
            }
            return null;
        }

        // Used only when package storage throws or its write fails.
        private static string FallbackPath()
        {
            try
            {
                string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                if (string.IsNullOrEmpty(local))
                {
                    return null;
                }
                string directory = Path.Combine(local, FallbackFolder);
                Directory.CreateDirectory(directory);
                return Path.Combine(directory, BrokerLogFormat.FileName);
            }
            catch (Exception)
            {
                return null;
            }
        }
    }
}
