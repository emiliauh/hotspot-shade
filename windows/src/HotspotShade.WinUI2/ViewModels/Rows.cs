using System;
using System.Globalization;
using HotspotShade.WinUI2.Core.App;
using Windows.UI.Xaml;

namespace HotspotShade.WinUI2.ViewModels
{
    // One attention line. The action label and visibility come from the
    // Core presenter.
    public sealed class AttentionRow
    {
        public AttentionRow(AttentionLine line)
        {
            Text = line.Text;
            Action = line.Action;
            ActionLabel = DashboardModel.Label(line.Action);
            ActionVisibility = line.Action == DashboardAction.None ? Visibility.Collapsed : Visibility.Visible;
        }

        public string Text { get; private set; }

        public string ActionLabel { get; private set; }

        public DashboardAction Action { get; private set; }

        public Visibility ActionVisibility { get; private set; }
    }

    // One engine log line. The Details toggle adds the level and the
    // sequence number.
    public sealed class ActivityRow
    {
        public ActivityRow(LogLine line, bool showDetails)
        {
            Time = FormatTime(line.Timestamp);
            Message = line.Message;
            Details = line.Level + "  #" + line.Seq.ToString(CultureInfo.InvariantCulture);
            DetailsVisibility = showDetails ? Visibility.Visible : Visibility.Collapsed;
            AccessibilityLabel = showDetails
                ? Time + ". " + Message + ". " + line.Level + ", number " + line.Seq.ToString(CultureInfo.InvariantCulture) + "."
                : Time + ". " + Message;
        }

        public string Time { get; private set; }

        public string Message { get; private set; }

        public string Details { get; private set; }

        public Visibility DetailsVisibility { get; private set; }

        public string AccessibilityLabel { get; private set; }

        private static string FormatTime(double? timestamp)
        {
            if (!timestamp.HasValue || timestamp.Value <= 0)
            {
                return "--:--:--";
            }
            try
            {
                DateTime local = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                    .AddSeconds(timestamp.Value)
                    .ToLocalTime();
                return local.ToString("HH:mm:ss", CultureInfo.InvariantCulture);
            }
            catch (ArgumentOutOfRangeException)
            {
                return "--:--:--";
            }
        }
    }

    // One failure group row for Recent failures.
    public sealed class FailureRow
    {
        public FailureRow(FailureGroup group)
        {
            Count = group.Count.ToString(CultureInfo.InvariantCulture);
            Kind = AppSession.FailureKind(group);
            Target = AppSession.FailureTarget(group);
            Stage = string.IsNullOrEmpty(group.Phase) ? "-" : group.Phase;
            Reason = AppSession.FailureReason(group);
            AccessibilityLabel = Count + " failures. " + Kind + ". " + Target + ". " + Stage + ". " + Reason + ".";
        }

        public string Count { get; private set; }

        public string Kind { get; private set; }

        public string Target { get; private set; }

        public string Stage { get; private set; }

        public string Reason { get; private set; }

        public string AccessibilityLabel { get; private set; }
    }
}
