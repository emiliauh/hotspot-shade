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

            runner.Check("contract: package declares the broker capabilities and no network capability", delegate
            {
                XDocument package = XDocument.Load(manifest);
                List<string> names = package.Descendants()
                    .Where(e => e.Name.LocalName == "Capability" || e.Name.LocalName == "DeviceCapability")
                    .Select(e => (string)e.Attribute("Name"))
                    .OrderBy(name => name, StringComparer.Ordinal)
                    .ToList();
                AssertEx.Equal(2, names.Count, "capability count");
                AssertEx.Equal("allowElevation", names[0], "elevation capability for Turn on");
                AssertEx.Equal("runFullTrust", names[1], "full-trust broker capability");
                string text = SourceText.Read(manifest);
                AssertEx.DoesNotContain(text, "internetClient", "internet capability");
                AssertEx.DoesNotContain(text, "privateNetworkClientServer", "private network capability");
                AssertEx.DoesNotContain(text, "(simulated)", "simulated display name");
                List<string> categories = package.Descendants()
                    .Where(e => e.Name.LocalName == "Extension")
                    .Select(e => (string)e.Attribute("Category"))
                    .OrderBy(name => name, StringComparer.Ordinal)
                    .ToList();
                AssertEx.Equal(2, categories.Count, "extension count");
                AssertEx.Equal("windows.appService", categories[0], "app service extension");
                AssertEx.Equal("windows.fullTrustProcess", categories[1], "full-trust extension");
            });

            runner.Check("contract: no signing material is committed", delegate
            {
                string project = SourceText.Read(appProject);
                AssertEx.DoesNotContain(project, "PackageCertificateKeyFile", "certificate key file");
                foreach (string file in Files(root, "*.pfx", "*.cer", "*.key", "*.pem", "*.mobileprovision"))
                {
                    throw new Exception("signing material found: " + file);
                }
            });

            runner.Check("contract: source code has no network client, shell, or tunnel APIs outside the reviewed files", delegate
            {
                foreach (string file in Files(Path.Combine(root, "src"), "*.cs"))
                {
                    string normalized = file.Replace('\\', '/');
                    string text = SourceText.Read(file);
                    bool releaseProbe = normalized.Contains("/src/HotspotShade.WinUI2.ReleaseProbe/");
                    // The broker, the starter, the console launcher, and the
                    // window core name the wintun.dll file to check that it is
                    // installed. None of them loads it; only the engine does.
                    bool namesAdapterFile = normalized.Contains("/src/HotspotShade.WinUI2.Broker/")
                        || normalized.Contains("/src/HotspotShade.WinUI2.Elevate/")
                        || normalized.Contains("/src/HotspotShade.WinUI2.TestLauncher/")
                        || normalized.Contains("/src/HotspotShade.WinUI2.Core/App/");
                    for (int index = 0; index < ForbiddenApiNames.Length; index++)
                    {
                        string name = ForbiddenApiNames[index];
                        if (releaseProbe && name == "Process.Start")
                        {
                            continue;
                        }
                        if (namesAdapterFile && name == "Wintun")
                        {
                            AssertEx.False(text.Contains("WintunOpen") || text.Contains("WintunCreate") || text.Contains("LoadLibrary"), "adapter API in " + file);
                            continue;
                        }
                        if (name == "FullTrustProcessLauncher" && normalized.EndsWith("/src/HotspotShade.WinUI2/Services/BrokerConnection.cs"))
                        {
                            continue;
                        }
                        AssertEx.DoesNotContain(text, name, "forbidden API in " + file);
                    }
                    // Only the elevated launcher asks Windows for elevation.
                    if (!normalized.EndsWith("/src/HotspotShade.WinUI2.Broker/ElevatedEngineLauncher.cs"))
                    {
                        AssertEx.DoesNotContain(text, "\"runas\"", "elevation verb in " + file);
                    }
                    if (!normalized.EndsWith("/src/HotspotShade.WinUI2.Broker/ElevatedEngineLauncher.cs")
                        && !normalized.EndsWith("/src/HotspotShade.WinUI2.Broker/BrokerNative.cs"))
                    {
                        // The release probe turns shell execution off.
                        string scan = releaseProbe ? text.Replace("UseShellExecute = false", "") : text;
                        AssertEx.DoesNotContain(scan, "ShellExecute", "shell execution in " + file);
                    }
                    if (!normalized.EndsWith("/src/HotspotShade.WinUI2.Broker/Win32EngineHost.cs")
                        && !normalized.EndsWith("/src/HotspotShade.WinUI2.Elevate/Program.cs")
                        && !normalized.Contains("/src/HotspotShade.WinUI2.ServiceHost/")
                        && !normalized.Contains("/src/HotspotShade.WinUI2.Service/")
                        && !normalized.Contains("/src/HotspotShade.WinUI2.Core/Engine/Service/"))
                    {
                        AssertEx.DoesNotContain(text, "CreateProcess", "process creation in " + file);
                    }
                    AssertEx.DoesNotContain(text, "TerminateProcess", "forced termination in " + file);
                    AssertEx.DoesNotContain(text, "SetEnvironmentVariable", "environment write in " + file);
                    AssertEx.DoesNotContain(text, "EnvironmentVariables", "child environment in " + file);
                }
            });

            runner.Check("contract: the window and the core hold no process, pipe, or loopback client", delegate
            {
                string[] scoped = { appDir, Path.Combine(root, "src", "HotspotShade.WinUI2.Core", "App") };
                string[] names = { "CreateProcess", "CreatePipe", "WinHttp", "127.0.0.1", "DllImport", "ShellExecute" };
                for (int dir = 0; dir < scoped.Length; dir++)
                {
                    foreach (string file in Files(scoped[dir], "*.cs"))
                    {
                        string text = SourceText.Read(file);
                        for (int index = 0; index < names.Length; index++)
                        {
                            AssertEx.DoesNotContain(text, names[index], names[index] + " in " + file);
                        }
                    }
                }
            });

            runner.Check("contract: the app has no demo, preview, or simulated surface", delegate
            {
                string[] words = { "simulated", "Simulated", "Simulate", "simulate", "Demo", "demo", "preview", "Preview", "fake", "Fake" };
                foreach (string file in Files(appDir, "*.cs", "*.xaml", "*.appxmanifest"))
                {
                    string text = SourceText.Read(file);
                    for (int index = 0; index < words.Length; index++)
                    {
                        AssertEx.DoesNotContain(text, words[index], "demo word in " + file);
                    }
                }
                foreach (string file in Files(Path.Combine(root, "src", "HotspotShade.WinUI2.Core"), "*.cs"))
                {
                    string name = Path.GetFileName(file);
                    AssertEx.False(name.StartsWith("Demo", StringComparison.Ordinal), "demo source " + file);
                }
                foreach (string file in Files(Path.Combine(root, "src", "HotspotShade.WinUI2.Core", "App"), "*.cs"))
                {
                    string text = SourceText.Read(file);
                    AssertEx.DoesNotContain(text, "simulated", "simulated data in " + file);
                    AssertEx.DoesNotContain(text, "--demo", "demo engine in " + file);
                }
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
                AssertEx.Equal("6.2.14", versions["Microsoft.NETCore.UniversalWindowsPlatform"], "UWP package version");
                XElement uwp = project.Descendants().Single(e => e.Name.LocalName == "PackageReference" &&
                    (string)e.Attribute("Include") == "Microsoft.NETCore.UniversalWindowsPlatform");
                XElement testVersion = uwp.Elements().Single(e => e.Name.LocalName == "Version" && e.Attribute("Condition") != null);
                AssertEx.Equal("$(HotspotShadeUwpVersion)", testVersion.Value.Trim(), "UWP override package version");
                AssertEx.Contains((string)testVersion.Attribute("Condition"), "HotspotShadeUwpVersion", "UWP override version condition");
                foreach (KeyValuePair<string, string> pair in versions)
                {
                    AssertEx.False(pair.Value.IndexOf('*') >= 0, "floating version for " + pair.Key);
                    AssertEx.False(pair.Value.IndexOf('[') >= 0, "range version for " + pair.Key);
                    AssertEx.False(pair.Value.IndexOf('(') >= 0, "range version for " + pair.Key);
                }
            });

            runner.Check("contract: the .NET SDK is pinned and the payload build checks it", delegate
            {
                string globalJson = SourceText.Read(Path.Combine(root, "global.json"));
                AssertEx.Contains(globalJson, "\"version\": \"8.0.427\"", "SDK 8.0.427 is the floor");
                AssertEx.Contains(globalJson, "\"rollForward\": \"latestFeature\"", "later 8.0.x SDKs are allowed");
                AssertEx.Contains(globalJson, "\"allowPrerelease\": false", "no preview SDK");
                string stage = SourceText.Read(Path.Combine(root, "tools", "stage_payload.ps1"));
                AssertEx.Contains(stage, "[Version]\"8.0.427\"", "the script knows the SDK floor");
                AssertEx.Contains(stage, "This build needs .NET SDK 8.0.427 or a later 8.0.x SDK", "plain message for an old SDK");
                AssertEx.Contains(stage, "Invoke-WindowsDotnet", "dotnet runs from the windows folder");
                AssertEx.Contains(stage, "[Version]\"8.0.33\"", "the self-contained broker runtime is checked after the publish");
                string starter = SourceText.Read(Path.Combine(root, "src", "HotspotShade.WinUI2.Elevate", "HotspotShade.WinUI2.Elevate.csproj"));
                AssertEx.Contains(starter, "<TreatWarningsAsErrors>true</TreatWarningsAsErrors>", "the starter keeps the advisory as an error");
                AssertEx.DoesNotContain(starter, "<NoWarn>", "no warning is suppressed");
                AssertEx.DoesNotContain(starter, "<WarningsNotAsErrors>", "no warning is excused from the error rule");
                AssertEx.True(File.Exists(Path.Combine(root, "tools", "check_package_dependencies.ps1")), "the dependency check script exists");
            });

            runner.Check("contract: payload content items do not break a compile-only build", delegate
            {
                XDocument project = XDocument.Load(appProject);
                List<XElement> payload = project.Descendants()
                    .Where(e => e.Name.LocalName == "Content" && ((string)e.Attribute("Include") ?? "").Contains("$(HotspotShadePayloadDir)Engine"))
                    .ToList();
                AssertEx.Equal(2, payload.Count, "engine and adapter content items");
                foreach (XElement item in payload)
                {
                    string condition = (string)item.Attribute("Condition") ?? "";
                    AssertEx.Contains(condition, "Exists('", "an absent payload file is skipped: " + (string)item.Attribute("Include"));
                }
                string text = SourceText.Read(appProject);
                AssertEx.Contains(text, "Name=\"HotspotShadeCheckPayload\"", "a package build still requires the payload");
                AssertEx.Contains(text, "!Exists('$(HotspotShadePayloadDir)Engine\\hotspotshade.exe')", "a missing engine stops a package build");
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
                string readme = SourceText.Read(Path.Combine(root, "README.md"));
                AssertEx.Contains(readme, "UWP", "UWP architecture");
                AssertEx.Contains(readme, "WinUI 2", "WinUI 2");
                AssertEx.Contains(readme, "not production ready", "readiness statement");
                AssertEx.Contains(readme, "BUILD_AND_TEST_ON_PC.md", "PC build guide link");
                AssertEx.True(File.Exists(Path.Combine(root, "BUILD_AND_TEST_ON_PC.md")), "PC build guide");
                AssertEx.Contains(readme, "Windows 11 SDK", "SDK prerequisite");
                string parity = SourceText.Read(Path.Combine(root, "PARITY.md"));
                AssertEx.Contains(parity, "Incomplete", "incomplete parity");
                AssertEx.Contains(parity, "not production ready", "parity readiness");
            });

            runner.Check("contract: source text uses ASCII punctuation", delegate
            {
                foreach (string file in Files(root, "*.cs", "*.xaml", "*.md", "*.sh", "*.csproj", "*.appxmanifest", "*.xml", "*.config"))
                {
                    string text = SourceText.Read(file);
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
