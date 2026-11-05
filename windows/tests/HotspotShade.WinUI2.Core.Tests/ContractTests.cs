using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml.Linq;

namespace HotspotShade.WinUI2.Core.Tests
{
    // Static checks for the isolated windows/ tree. These checks replace no
    // Windows build. They catch a missing XAML include, a capability, a
    // certificate, a floating dependency, or a missing simulated label.
    internal static class ContractTests
    {
        private static readonly string[] ForbiddenApiNames =
        {
            "System.Net",
            "HttpClient",
            "TcpClient",
            "TcpListener",
            "UdpClient",
            "WebSocket",
            "Socket",
            "Windows.Networking",
            "Wintun",
            "FullTrustProcessLauncher",
            "Process.Start",
            "netsh",
            "route.exe"
        };

        private static readonly char[] ForbiddenPunctuation =
        {
            '\u2014',
            '\u2013',
            '\u2018',
            '\u2019',
            '\u201C',
            '\u201D'
        };

        public static void Run(TestRunner runner)
        {
            string root = FindWindowsRoot();
            runner.Check("contract: windows tree is present", delegate
            {
                AssertEx.True(root != null, "windows directory not found");
                AssertEx.True(File.Exists(Path.Combine(root, "README.md")), "README.md is missing");
                AssertEx.True(File.Exists(Path.Combine(root, "PARITY.md")), "PARITY.md is missing");
            });
            if (root == null)
            {
                return;
            }

            string appDir = Path.Combine(root, "src", "HotspotShade.WinUI2");
            string appProject = Path.Combine(appDir, "HotspotShade.WinUI2.csproj");
            string manifest = Path.Combine(appDir, "Package.appxmanifest");

            runner.Check("contract: page scroll viewers bound their content width", delegate
            {
                XDocument page = XDocument.Load(Path.Combine(appDir, "MainPage.xaml"));
                XNamespace x = "http://schemas.microsoft.com/winfx/2006/xaml";
                foreach (string name in new[] { "DashboardScroll", "ActivityScroll", "SettingsScroll" })
                {
                    XElement viewer = page.Descendants().Single(e => e.Name.LocalName == "ScrollViewer" && (string)e.Attribute(x + "Name") == name);
                    AssertEx.True((string)viewer.Attribute("MaxWidth") == "768", name + " must bound its viewport");
                    AssertEx.True((string)viewer.Attribute("HorizontalContentAlignment") == "Stretch", name + " must stretch its content");
                    XElement content = viewer.Elements().Single();
                    AssertEx.True(content.Attribute("MaxWidth") == null, name + " must not apply a second width limit to its content");
                }
            });

            runner.Check("contract: activity rows align time with the message", delegate
            {
                XDocument page = XDocument.Load(Path.Combine(appDir, "MainPage.xaml"));
                XNamespace x = "http://schemas.microsoft.com/winfx/2006/xaml";
                XElement viewer = page.Descendants().Single(e => (string)e.Attribute(x + "Name") == "ActivityScroll");
                XElement pageContent = viewer.Elements().Single();
                AssertEx.True(pageContent.Attribute("Spacing") == null, "collapsed activity states must not add gaps");
                XElement row = viewer.Descendants().Single(e => e.Name.LocalName == "DataTemplate").Elements().Single();
                XElement time = row.Elements().Single(e => (string)e.Attribute("Grid.Column") == "0");
                XElement text = row.Elements().Single(e => (string)e.Attribute("Grid.Column") == "1");
                AssertEx.Equal("{Binding Time}", (string)time.Attribute("Text"), "activity time");
                AssertEx.Equal("{Binding Message}", (string)text.Elements().First().Attribute("Text"), "activity message position");
                AssertEx.True(text.Elements().Count(e => (string)e.Attribute("Text") == "{Binding Message}") == 1, "activity message appears once");
                AssertEx.True(text.Attribute("Spacing") == null, "hidden details must not offset the message");
            });

            runner.Check("contract: XML files are well formed", delegate
            {
                int count = 0;
                foreach (string file in Files(root, "*.xaml", "*.csproj", "*.appxmanifest", "*.props", "*.config", "*.xml"))
                {
                    XDocument.Load(file);
                    count++;
                }
                AssertEx.True(count >= 8, "expected at least 8 XML files, found " + count);
            });

            runner.Check("contract: app project includes every source file", delegate
            {
                XDocument project = XDocument.Load(appProject);
                HashSet<string> compiled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                HashSet<string> pages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (XElement element in project.Descendants())
                {
                    string name = element.Name.LocalName;
                    XAttribute include = element.Attribute("Include");
                    if (include == null)
                    {
                        continue;
                    }
                    if (name == "Compile")
                    {
                        compiled.Add(Normalize(include.Value));
                    }
                    else if (name == "Page" || name == "ApplicationDefinition")
                    {
                        pages.Add(Normalize(include.Value));
                    }
                }

                foreach (string file in Directory.EnumerateFiles(appDir, "*.cs", SearchOption.AllDirectories))
                {
                    if (IsGenerated(file))
                    {
                        continue;
                    }
                    string relative = Normalize(Path.GetRelativePath(appDir, file));
                    AssertEx.True(compiled.Contains(relative), "missing Compile include for " + relative);
                }
                foreach (string file in Directory.EnumerateFiles(appDir, "*.xaml", SearchOption.AllDirectories))
                {
                    if (IsGenerated(file))
                    {
                        continue;
                    }
                    string relative = Normalize(Path.GetRelativePath(appDir, file));
                    AssertEx.True(pages.Contains(relative), "missing Page or ApplicationDefinition include for " + relative);
                }
            });

            runner.Check("contract: package declares no capabilities or extensions", delegate
            {
                XDocument package = XDocument.Load(manifest);
                AssertEx.False(package.Descendants().Any(e => e.Name.LocalName == "Capability"), "Capability element");
                AssertEx.False(package.Descendants().Any(e => e.Name.LocalName == "Extensions"), "Extensions element");
                string text = File.ReadAllText(manifest);
                AssertEx.DoesNotContain(text, "internetClient", "internet capability");
                AssertEx.DoesNotContain(text, "privateNetworkClientServer", "private network capability");
                AssertEx.DoesNotContain(text, "runFullTrust", "full trust capability");
            });

            runner.Check("contract: no signing material is committed", delegate
            {
                string project = File.ReadAllText(appProject);
                AssertEx.DoesNotContain(project, "PackageCertificateKeyFile", "certificate key file");
                foreach (string file in Files(root, "*.pfx", "*.cer", "*.key", "*.pem", "*.mobileprovision"))
                {
                    throw new Exception("signing material found: " + file);
                }
            });

            runner.Check("contract: app code has no network, process, or tunnel APIs", delegate
            {
                foreach (string file in Files(root, "*.cs"))
                {
                    if (file.EndsWith("ContractTests.cs", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    string text = File.ReadAllText(file);
                    for (int index = 0; index < ForbiddenApiNames.Length; index++)
                    {
                        AssertEx.DoesNotContain(text, ForbiddenApiNames[index], "forbidden API in " + file);
                    }
                }
            });

            runner.Check("contract: simulated labels are present", delegate
            {
                StringBuilder text = new StringBuilder();
                foreach (string file in Files(appDir, "*.cs", "*.xaml"))
                {
                    text.AppendLine(File.ReadAllText(file));
                }
                string all = text.ToString();
                AssertEx.Contains(all, "All data is simulated", "banner title");
                AssertEx.Contains(all, "No tunnel", "no tunnel label");
                AssertEx.Contains(all, "network listener", "no listener label");
                AssertEx.Contains(all, "not production ready", "readiness label");
                AssertEx.Contains(all, "Simulated", "simulated label");
            });

            runner.Check("contract: dependency versions are pinned", delegate
            {
                XDocument project = XDocument.Load(appProject);
                Dictionary<string, string> versions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (XElement reference in project.Descendants().Where(e => e.Name.LocalName == "PackageReference"))
                {
                    string name = (string)reference.Attribute("Include");
                    XElement version = reference.Elements().FirstOrDefault(e => e.Name.LocalName == "Version");
                    AssertEx.True(name != null, "package reference without a name");
                    AssertEx.True(version != null, "package reference without a version: " + name);
                    versions[name] = version.Value.Trim();
                }
                AssertEx.True(versions.ContainsKey("Microsoft.UI.Xaml"), "WinUI package is missing");
                AssertEx.True(versions.ContainsKey("Microsoft.NETCore.UniversalWindowsPlatform"), "UWP package is missing");
                AssertEx.Equal("2.8.7", versions["Microsoft.UI.Xaml"], "WinUI 2 version");
                AssertEx.Equal("6.2.15", versions["Microsoft.NETCore.UniversalWindowsPlatform"], "UWP package version");
                XElement uwp = project.Descendants().Single(e => e.Name.LocalName == "PackageReference" &&
                    (string)e.Attribute("Include") == "Microsoft.NETCore.UniversalWindowsPlatform");
                XElement testVersion = uwp.Elements().Single(e => e.Name.LocalName == "Version" && e.Attribute("Condition") != null);
                AssertEx.Equal("6.2.14", testVersion.Value.Trim(), "UWP test package version");
                AssertEx.Contains((string)testVersion.Attribute("Condition"), "HotspotShadeTestUwp6214", "UWP test version condition");
                foreach (KeyValuePair<string, string> pair in versions)
                {
                    AssertEx.False(pair.Value.IndexOf('*') >= 0, "floating version for " + pair.Key);
                    AssertEx.False(pair.Value.IndexOf('[') >= 0, "range version for " + pair.Key);
                    AssertEx.False(pair.Value.IndexOf('(') >= 0, "range version for " + pair.Key);
                }
            });

            runner.Check("contract: manifest assets exist", delegate
            {
                XDocument package = XDocument.Load(manifest);
                string[] attributeNames = { "Logo", "Square150x150Logo", "Square44x44Logo", "Image" };
                for (int index = 0; index < attributeNames.Length; index++)
                {
                    foreach (XElement element in package.Descendants())
                    {
                        XAttribute attribute = element.Attribute(attributeNames[index]);
                        if (attribute != null)
                        {
                            AssertAsset(appDir, attribute.Value);
                        }
                    }
                }
                XElement logo = package.Descendants().FirstOrDefault(e => e.Name.LocalName == "Logo");
                if (logo != null)
                {
                    AssertAsset(appDir, logo.Value);
                }
            });

            runner.Check("contract: docs state the prototype limits", delegate
            {
                string readme = File.ReadAllText(Path.Combine(root, "README.md"));
                AssertEx.Contains(readme, "UWP", "UWP architecture");
                AssertEx.Contains(readme, "WinUI 2", "WinUI 2");
                AssertEx.Contains(readme, "not production ready", "readiness statement");
                AssertEx.Contains(readme, "Windows 11 SDK", "SDK prerequisite");
                string parity = File.ReadAllText(Path.Combine(root, "PARITY.md"));
                AssertEx.Contains(parity, "Incomplete", "incomplete parity");
                AssertEx.Contains(parity, "not production ready", "parity readiness");
            });

            runner.Check("contract: source text uses ASCII punctuation", delegate
            {
                foreach (string file in Files(root, "*.cs", "*.xaml", "*.md", "*.sh", "*.csproj", "*.appxmanifest", "*.xml", "*.config"))
                {
                    string text = File.ReadAllText(file);
                    for (int index = 0; index < text.Length; index++)
                    {
                        for (int check = 0; check < ForbiddenPunctuation.Length; check++)
                        {
                            if (text[index] == ForbiddenPunctuation[check])
                            {
                                throw new Exception("forbidden punctuation U+"
                                    + ((int)text[index]).ToString("X4") + " in " + file);
                            }
                        }
                    }
                }
            });
        }

        private static string FindWindowsRoot()
        {
            DirectoryInfo directory = new DirectoryInfo(AppContext.BaseDirectory);
            while (directory != null)
            {
                string candidate = Path.Combine(directory.FullName, "windows");
                if (Directory.Exists(candidate) && File.Exists(Path.Combine(candidate, "README.md")))
                {
                    return candidate;
                }
                directory = directory.Parent;
            }
            return null;
        }

        private static IEnumerable<string> Files(string root, params string[] patterns)
        {
            for (int pattern = 0; pattern < patterns.Length; pattern++)
            {
                foreach (string file in Directory.EnumerateFiles(root, patterns[pattern], SearchOption.AllDirectories))
                {
                    string normalized = file.Replace('\\', '/');
                    if (normalized.Contains("/bin/") || normalized.Contains("/obj/") || normalized.Contains("/.vs/")
                        || normalized.Contains("/AppPackages/") || normalized.Contains("/TestResults/"))
                    {
                        continue;
                    }
                    yield return file;
                }
            }
        }

        private static bool IsGenerated(string file)
        {
            string normalized = file.Replace('\\', '/');
            return normalized.Contains("/bin/") || normalized.Contains("/obj/")
                || normalized.Contains("/AppPackages/") || normalized.Contains("/TestResults/");
        }

        private static string Normalize(string path)
        {
            return path.Replace('\\', '/').TrimStart('.', '/');
        }

        private static void AssertAsset(string appDir, string relative)
        {
            string file = Path.Combine(appDir, relative.Replace('\\', '/'));
            AssertEx.True(File.Exists(file), "missing asset: " + relative);
        }
    }
}
