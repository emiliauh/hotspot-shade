using System.IO;

namespace HotspotShade.WinUI2.Core.Tests
{
    /// <summary>
    /// Reads a repository text file for the source-reading checks. Git for
    /// Windows can check files out with CRLF line endings. The checks search
    /// for multi-line text, so every line ending is turned into a single LF
    /// first. The checks then pass on LF and CRLF checkouts alike.
    /// </summary>
    internal static class SourceText
    {
        public static string Read(string path)
        {
            return File.ReadAllText(path).Replace("\r\n", "\n");
        }
    }
}
