using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml.Linq;

namespace HotspotShade.WinUI2.Core.Tests
{
    // Checks the destination-privacy report and the read-only Settings card.
    // The checks are hermetic. They create no route, device, or connection.
    internal static class PrivacyCapabilityTests
    {
        public static void Run(TestRunner runner)
        {
            runner.Check("privacy: report lists the four shared modes in order", delegate
            {
                WindowsPrivacyReport report = WindowsPrivacyCapabilities.Build();
                AssertEx.Equal(4, report.Modes.Count, "mode count");
                AssertEx.Equal(WindowsPrivacyMode.Off, report.Modes[0].Mode, "first mode");
                AssertEx.Equal(WindowsPrivacyMode.Shape, report.Modes[1].Mode, "second mode");
                AssertEx.Equal(WindowsPrivacyMode.Hide, report.Modes[2].Mode, "third mode");
                AssertEx.Equal(WindowsPrivacyMode.Cover, report.Modes[3].Mode, "fourth mode");
                AssertEx.Equal(WindowsPrivacyMode.Off, report.SelectedMode, "selected mode");
                AssertEx.Equal("Off", report.ModeText, "mode text");
            });

            runner.Check("privacy: no mode is enabled and no traffic claim is made", delegate
            {
                WindowsPrivacyReport report = WindowsPrivacyCapabilities.Build();
                for (int index = 0; index < report.Modes.Count; index++)
                {
                    AssertEx.False(report.Modes[index].CanEnable, report.Modes[index].Title + " must not be enabled");
                }
                AssertEx.False(report.AppliesAnyMode, "no mode may apply");
                AssertEx.False(report.CanSelectMode, "no mode may be selectable");
                AssertEx.Contains(report.ModeStateText, "No service is connected", "current mode state");
                AssertEx.Contains(report.StorageNote, "saves no mode", "storage note");
                AssertEx.Contains(report.StorageNote, "applies no mode", "apply note");
                AssertEx.Contains(report.Intro, "no engine", "intro");
            });

            runner.Check("privacy: unavailable modes state that this build cannot honor them", delegate
            {
                WindowsPrivacyReport report = WindowsPrivacyCapabilities.Build();
                WindowsPrivacyModeRow shape = Find(report, WindowsPrivacyMode.Shape);
                WindowsPrivacyModeRow hide = Find(report, WindowsPrivacyMode.Hide);
                AssertEx.Contains(shape.StateText, "Unavailable", "shape state");
                AssertEx.Contains(shape.StateText, "does not implement", "shape reason");
                AssertEx.Contains(shape.Detail, "Not implemented", "shape detail");
                AssertEx.Contains(hide.StateText, "Unavailable", "hide state");
                AssertEx.Contains(hide.StateText, "does not implement", "hide reason");
                for (int index = 1; index < report.Modes.Count; index++)
                {
                    string state = report.Modes[index].StateText;
                    AssertEx.True(
                        state.StartsWith("Unavailable", StringComparison.Ordinal)
                            || state.StartsWith("Deferred", StringComparison.Ordinal),
                        "non-current mode must state that it is unavailable: " + state);
                    AssertEx.True(report.Modes[index].Detail.Length > 40, "mode detail is too short");
                }
            });

            runner.Check("privacy: off is not in force while no service runs", delegate
            {
                WindowsPrivacyReport report = WindowsPrivacyCapabilities.Build();
                WindowsPrivacyModeRow off = Find(report, WindowsPrivacyMode.Off);
                AssertEx.Contains(off.StateText, "Not in force", "off state");
                AssertEx.Contains(off.StateText, "No service is connected", "off reason");
                AssertEx.Contains(off.Detail, "no engine", "off detail");
                AssertEx.Contains(off.Detail, "no traffic is normalized", "off traffic");
                AssertEx.False(off.CanEnable, "off must not be offered as a control");
                AssertEx.True(off.IsCurrent, "off is the current choice");
            });

            runner.Check("privacy: hide names the relayed TLS boundary and stays unavailable", delegate
            {
                WindowsPrivacyReport report = WindowsPrivacyCapabilities.Build();
                WindowsPrivacyModeRow hide = Find(report, WindowsPrivacyMode.Hide);
                AssertEx.Contains(hide.Detail, "copies each application's TLS bytes", "relay boundary");
                AssertEx.Contains(hide.Detail, "would not change another", "client boundary");
                AssertEx.Contains(hide.Detail, "ClientHello", "handshake owner");
                AssertEx.Contains(hide.Detail, "Unavailable under the current design", "unsupported boundary");
                AssertEx.Contains(hide.Detail, "the mode is unavailable", "availability");
                AssertEx.Contains(hide.Detail, "An application may use ECH or encrypted DNS on its own", "application option");
                AssertEx.DoesNotContain(hide.Detail, "later engine build", "no future engine promise");
                AssertEx.DoesNotContain(hide.Detail, "would hide a name", "no hidden-name promise");
                AssertEx.DoesNotContain(hide.Detail, "DNS over HTTPS", "no encrypted DNS promise");

                WindowsPrivacyFact ech = FindFact(report, "ech");
                AssertEx.Contains(ech.Detail, "copies application TLS bytes", "ECH relay boundary");
                AssertEx.Contains(ech.Detail, "cannot add ECH to another application's ClientHello", "ECH owner limit");
            });

            runner.Check("privacy: no categorical destination, billing, or guarantee claim", delegate
            {
                WindowsPrivacyReport report = WindowsPrivacyCapabilities.Build();
                StringBuilder text = ReportText(report);
                string all = text.ToString();
                AssertEx.DoesNotContain(all, "every destination name", "universal visibility claim");
                AssertEx.DoesNotContain(all, "hides nothing", "categorical concealment claim");
                AssertEx.DoesNotContain(all, "changes what your plan is billed", "billing claim");
                AssertEx.DoesNotContain(all, "defeat", "detection defeat claim");
                AssertEx.DoesNotContain(all, "guarantee", "service guarantee");
                AssertEx.DoesNotContain(all, "always", "universal claim");
                AssertEx.Contains(report.Intro, "unless an application uses its own ECH", "application ECH");
                AssertEx.Contains(report.Limits[1], "Tethering detection is a separate problem", "detection scope");
                AssertEx.Contains(report.Limits[2], "makes a claim about your plan", "billing scope");
            });

            runner.Check("privacy: cover is deferred and needs an owned endpoint", delegate
            {
                WindowsPrivacyReport report = WindowsPrivacyCapabilities.Build();
                WindowsPrivacyModeRow cover = Find(report, WindowsPrivacyMode.Cover);
                AssertEx.Contains(cover.StateText, "Deferred", "cover state");
                AssertEx.Contains(cover.StateText, "endpoint you own", "cover reason");
                AssertEx.Contains(cover.Detail, "endpoint that you own", "cover detail");
                AssertEx.Contains(cover.Detail, "no external relay", "cover relay limit");
                AssertEx.Contains(cover.Detail, "out of scope", "cover name limit");
            });

            runner.Check("privacy: termination is out of scope", delegate
            {
                WindowsPrivacyReport report = WindowsPrivacyCapabilities.Build();
                AssertEx.Contains(report.OutOfScopeNote, "out of scope", "scope note");
                AssertEx.Contains(report.OutOfScopeNote, "ends no TLS", "termination limit");
                AssertEx.Contains(report.OutOfScopeNote, "certificate authority", "certificate limit");
                AssertEx.Equal(4, report.Modes.Count, "termination is not a mode row");
            });

            runner.Check("privacy: flags report no ECH and no server name override", delegate
            {
                WindowsPrivacyReport report = WindowsPrivacyCapabilities.Build();
                AssertEx.Contains(report.FlagsLine, "ech no", "ECH flag");
                AssertEx.Contains(report.FlagsLine, "sni_override no", "server name flag");
                AssertEx.Contains(report.FlagsLine, "background_relay no", "relay flag");
                WindowsPrivacyFact ech = FindFact(report, "ech");
                AssertEx.True(ech.ValueText.StartsWith("No.", StringComparison.Ordinal), "ECH value");
                WindowsPrivacyFact service = FindFact(report, "service");
                AssertEx.Contains(service.ValueText, "No service is connected", "service value");
            });

            runner.Check("privacy: report holds no destination value or credential", delegate
            {
                WindowsPrivacyReport report = WindowsPrivacyCapabilities.Build();
                string all = ReportText(report).ToString();
                AssertEx.DoesNotContain(all, "://", "URL");
                AssertEx.DoesNotContain(all, "token", "token");
                AssertEx.DoesNotContain(all, "bearer", "bearer");
                AssertEx.DoesNotContain(all, "password", "password");
                AssertEx.DoesNotContain(all, "PRIVATE KEY", "private key");
                AssertEx.DoesNotContain(all, "192.168", "private address");
                AssertEx.DoesNotContain(all, "2001:", "address literal");
                AssertEx.DoesNotContain(all, "@", "account value");
                AssertAscii(all, "privacy report");
            });

            runner.Check("privacy: settings card is read-only and states the limit", delegate
            {
                string root = FindWindowsRoot();
                AssertEx.True(root != null, "windows directory not found");
                string appDir = Path.Combine(root, "src", "HotspotShade.WinUI2");
                string page = Path.Combine(appDir, "MainPage.xaml");
                XDocument document = XDocument.Load(page);
                XElement heading = document.Descendants().SingleOrDefault(
                    e => e.Name.LocalName == "TextBlock"
                        && (string)e.Attribute("Text") == "Destination privacy");
                AssertEx.True(heading != null, "destination privacy card is missing");
                XElement card = heading.Ancestors().FirstOrDefault(e => e.Name.LocalName == "Border");
                AssertEx.True(card != null, "destination privacy card has no border");

                string[] controls = { "ToggleSwitch", "RadioButton", "Button", "ComboBox", "CheckBox", "HyperlinkButton" };
                for (int index = 0; index < controls.Length; index++)
                {
                    AssertEx.False(
                        card.Descendants().Any(e => e.Name.LocalName == controls[index]),
                        "privacy card must not offer a " + controls[index]);
                }

                AssertEx.True(
                    card.Descendants().Any(e => e.Name.LocalName == "ItemsControl"
                        && (string)e.Attribute("ItemsSource") == "{x:Bind Privacy.Modes, Mode=OneTime}"),
                    "privacy mode list is missing");
                AssertEx.True(
                    card.Descendants().Any(e => (string)e.Attribute("Text") == "{x:Bind Privacy.StorageNote, Mode=OneTime}"),
                    "privacy storage note is missing");

                string codeBehind = File.ReadAllText(Path.Combine(appDir, "MainPage.xaml.cs"));
                AssertEx.Contains(codeBehind, "PrivacyCapabilityViewModel Privacy", "page privacy property");
                int privacyIndex = codeBehind.IndexOf("Privacy = new PrivacyCapabilityViewModel();", StringComparison.Ordinal);
                int initIndex = codeBehind.IndexOf("this.InitializeComponent();", StringComparison.Ordinal);
                AssertEx.True(privacyIndex >= 0, "page does not create the privacy view model");
                AssertEx.True(initIndex > privacyIndex, "privacy data must be ready before the page initializes");

                string viewModel = Path.Combine(appDir, "ViewModels", "PrivacyCapabilityViewModel.cs");
                AssertEx.True(File.Exists(viewModel), "privacy view model is missing");
                string viewModelText = File.ReadAllText(viewModel);
                AssertEx.Contains(viewModelText, "CanEnable", "view model enable state");
                AssertEx.DoesNotContain(viewModelText, "IsEnabled = true", "view model must not enable a control");
            });
        }

        private static StringBuilder ReportText(WindowsPrivacyReport report)
        {
            StringBuilder text = new StringBuilder();
            text.AppendLine(report.Intro);
            text.AppendLine(report.StorageNote);
            text.AppendLine(report.OutOfScopeNote);
            text.AppendLine(report.FlagsLine);
            for (int index = 0; index < report.Modes.Count; index++)
            {
                text.AppendLine(report.Modes[index].Title);
                text.AppendLine(report.Modes[index].StateText);
                text.AppendLine(report.Modes[index].Detail);
            }
            for (int index = 0; index < report.Facts.Count; index++)
            {
                text.AppendLine(report.Facts[index].Title);
                text.AppendLine(report.Facts[index].ValueText);
                text.AppendLine(report.Facts[index].Detail);
            }
            for (int index = 0; index < report.Limits.Count; index++)
            {
                text.AppendLine(report.Limits[index]);
            }
            return text;
        }

        private static WindowsPrivacyModeRow Find(WindowsPrivacyReport report, WindowsPrivacyMode mode)
        {
            for (int index = 0; index < report.Modes.Count; index++)
            {
                if (report.Modes[index].Mode == mode)
                {
                    return report.Modes[index];
                }
            }
            throw new Exception("mode not found: " + mode);
        }

        private static WindowsPrivacyFact FindFact(WindowsPrivacyReport report, string id)
        {
            for (int index = 0; index < report.Facts.Count; index++)
            {
                if (string.Equals(report.Facts[index].Id, id, StringComparison.Ordinal))
                {
                    return report.Facts[index];
                }
            }
            throw new Exception("fact not found: " + id);
        }

        private static void AssertAscii(string text, string what)
        {
            for (int index = 0; index < text.Length; index++)
            {
                AssertEx.True(text[index] < 128, what + " has a non-ASCII character");
            }
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
    }
}
