using System;
using System.Collections.Generic;
using System.IO;
using HotspotShade.WinUI2.Core.App;
using Windows.Storage;

namespace HotspotShade.WinUI2.Services
{
    // The window side of the broker startup log. The broker writes it in the
    // package local folder; the window opens it read-only and shares it with
    // the writer. A missing, empty, or unreadable file is an empty snapshot,
    // never an error.
    public sealed class BrokerLogReader : IBrokerLogSource
    {
        public BrokerLogSnapshot Read(int maxLines)
        {
            try
            {
                StorageFolder folder = ApplicationData.Current.LocalFolder;
                if (folder == null || string.IsNullOrEmpty(folder.Path))
                {
                    return BrokerLogSnapshot.Empty;
                }
                string path = Path.Combine(folder.Path, BrokerLogFormat.FileName);
                if (!File.Exists(path))
                {
                    return BrokerLogSnapshot.Empty;
                }
                List<string> lines = new List<string>();
                using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (StreamReader reader = new StreamReader(stream))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        lines.Add(line);
                    }
                }
                return BrokerLogFormat.Snapshot(BrokerLogFormat.LastLines(lines, maxLines));
            }
            catch (Exception)
            {
                return BrokerLogSnapshot.Empty;
            }
        }
    }
}
