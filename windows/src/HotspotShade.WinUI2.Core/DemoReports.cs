using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace HotspotShade.WinUI2.Core
{
    // Plain text reports for the copy actions. Every report is simulated and
    // holds no credential. Documentation addresses and example names only.
    public static class DemoReports
    {
        public static List<DemoFailureRow> CreateFailureRows()
        {
            return new List<DemoFailureRow>
            {
                new DemoFailureRow(6, "TCP IPv4", "example.com:443", DemoText.FailureNoAnswer, "request"),
                new DemoFailureRow(3, "TCP IPv4", "example.com:443", DemoText.FailureNoAnswer, "connect"),
                new DemoFailureRow(2, "UDP IPv4", "dns.example:53", "Unreachable", "greeting"),
                new DemoFailureRow(2, "TCP IPv6", "[2001:db8::20]:80", "Refused", "auth"),
                new DemoFailureRow(1, "TCP IPv4", "example.org:8443", "Failed", null)
            };
        }

        public static string FailureReport(DemoFailuresContent content)
        {
            StringBuilder text = new StringBuilder();
            text.AppendLine("HotspotShade simulated failure report");
            text.AppendLine("Mode: Demo. No engine is present.");
            text.AppendLine("Total failures: " + content.Total.ToString(CultureInfo.InvariantCulture));
            text.AppendLine("Groups: " + content.Rows.Count.ToString(CultureInfo.InvariantCulture));
            for (int index = 0; index < content.Rows.Count; index++)
            {
                DemoFailureRow row = content.Rows[index];
                text.Append((index + 1).ToString(CultureInfo.InvariantCulture));
                text.Append(". ");
                text.Append(row.Count.ToString(CultureInfo.InvariantCulture));
                text.Append(" x ");
                text.Append(row.Kind);
                text.Append(" ");
                text.Append(row.Target);
                text.Append(". ");
                text.Append(row.Reason);
                text.Append(". Stage: ");
                text.Append(row.PhaseLabel);
                text.AppendLine(".");
            }
            text.AppendLine("The data is simulated and stays in this prototype session.");
            return text.ToString();
        }

        public static string DiagnosticsReport(
            DemoDashboardContent dashboard,
            DemoActivityContent activity,
            DemoFailuresContent failures,
            DemoTheme theme,
            bool pingEnabled,
            DateTimeOffset now)
        {
            StringBuilder text = new StringBuilder();
            text.AppendLine("HotspotShade Windows prototype diagnostics (simulated)");
            text.AppendLine("Time: " + now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture));
            text.AppendLine("Mode: Demo. No engine is present.");
            text.AppendLine("Tunnel: none. No route and no network listener exist.");
            text.AppendLine("App version: " + DemoText.PrototypeVersion);
            text.AppendLine("Platform: WinUI 2 for UWP");
            text.AppendLine("Theme: " + theme.ToString());
            text.AppendLine("Ping setting: " + (pingEnabled ? "on" : "off"));
            text.AppendLine("Status: " + dashboard.Title);
            text.AppendLine("Pairing: " + (dashboard.IsPaired ? DemoText.Paired : DemoText.NotPaired));
            text.AppendLine("Activity lines: " + activity.Lines.Count.ToString(CultureInfo.InvariantCulture));
            text.AppendLine("Failures: " + failures.Rows.Count.ToString(CultureInfo.InvariantCulture)
                + " groups, " + failures.Total.ToString(CultureInfo.InvariantCulture) + " attempts");
            text.AppendLine("Credential: none. The prototype holds no source device credential.");
            text.AppendLine("This report contains simulated data only.");
            return text.ToString();
        }
    }
}
