using HotspotShade.WinUI2.Core;
using Windows.UI.Xaml;

namespace HotspotShade.WinUI2.ViewModels
{
    // One attention line for the view. The action label and visibility come
    // from the core item.
    public sealed class AttentionRow
    {
        public AttentionRow(DemoAttentionItem item)
        {
            Text = item.Text;
            Action = item.Action;
            ActionLabel = item.ActionLabel;
            ActionVisibility = item.HasAction ? Visibility.Visible : Visibility.Collapsed;
        }

        public string Text { get; private set; }

        public string ActionLabel { get; private set; }

        public DemoAttentionAction Action { get; private set; }

        public Visibility ActionVisibility { get; private set; }
    }

    // One activity line for the view. The Details toggle changes the details
    // visibility and the accessibility text.
    public sealed class ActivityRow
    {
        public ActivityRow(DemoLogLine line, bool showDetails)
        {
            Time = line.TimeText;
            Message = line.Message;
            Details = line.DetailsText;
            DetailsVisibility = showDetails ? Visibility.Visible : Visibility.Collapsed;
            AccessibilityLabel = line.AccessibilityText(showDetails);
        }

        public string Time { get; private set; }

        public string Message { get; private set; }

        public string Details { get; private set; }

        public Visibility DetailsVisibility { get; private set; }

        public string AccessibilityLabel { get; private set; }
    }
}
