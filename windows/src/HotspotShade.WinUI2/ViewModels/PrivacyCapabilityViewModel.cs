using System;
using System.Collections.Generic;
using System.Text;
using HotspotShade.WinUI2.Core;

namespace HotspotShade.WinUI2.ViewModels
{
    // One destination-privacy mode row for the Settings card. The row is
    // read-only. It never offers a control while no service backs the mode.
    public sealed class PrivacyModeRowViewModel
    {
        public PrivacyModeRowViewModel(WindowsPrivacyModeRow row)
        {
            if (row == null)
            {
                throw new ArgumentNullException("row");
            }
            Title = row.Title;
            StateText = row.StateText;
            Detail = row.Detail;
            AccessibilityLabel = row.AccessibilityLabel;
            IsCurrent = row.IsCurrent;
            CanEnable = row.CanEnable;
        }

        public string Title { get; private set; }

        public string StateText { get; private set; }

        public string Detail { get; private set; }

        public string AccessibilityLabel { get; private set; }

        public bool IsCurrent { get; private set; }

        // Always false in this build. The XAML card offers no switch.
        public bool CanEnable { get; private set; }
    }

    // One capability fact row for the Settings card.
    public sealed class PrivacyFactRowViewModel
    {
        public PrivacyFactRowViewModel(WindowsPrivacyFact fact)
        {
            if (fact == null)
            {
                throw new ArgumentNullException("fact");
            }
            Id = fact.Id;
            Title = fact.Title;
            ValueText = fact.ValueText;
            Detail = fact.Detail;
            AccessibilityLabel = fact.AccessibilityLabel;
        }

        public string Id { get; private set; }

        public string Title { get; private set; }

        public string ValueText { get; private set; }

        public string Detail { get; private set; }

        public string AccessibilityLabel { get; private set; }
    }

    // The read-only destination-privacy card. It wraps the fixed Core report
    // and adds only view text. It holds no host, address, name, token, or key.
    public sealed class PrivacyCapabilityViewModel
    {
        public PrivacyCapabilityViewModel()
        {
            WindowsPrivacyReport report = WindowsPrivacyCapabilities.Build();
            Intro = report.Intro;
            ModeText = report.ModeText;
            ModeStateText = report.ModeStateText;
            FlagsLine = report.FlagsLine;
            OutOfScopeNote = report.OutOfScopeNote;
            StorageNote = report.StorageNote;
            AppliesAnyMode = report.AppliesAnyMode;
            CanSelectMode = report.CanSelectMode;
            LimitsText = JoinLimits(report.Limits);

            List<PrivacyModeRowViewModel> modes = new List<PrivacyModeRowViewModel>();
            for (int index = 0; index < report.Modes.Count; index++)
            {
                modes.Add(new PrivacyModeRowViewModel(report.Modes[index]));
            }
            Modes = modes;

            List<PrivacyFactRowViewModel> facts = new List<PrivacyFactRowViewModel>();
            for (int index = 0; index < report.Facts.Count; index++)
            {
                facts.Add(new PrivacyFactRowViewModel(report.Facts[index]));
            }
            Facts = facts;
        }

        public string Intro { get; private set; }

        public string ModeText { get; private set; }

        public string ModeStateText { get; private set; }

        public IReadOnlyList<PrivacyModeRowViewModel> Modes { get; private set; }

        public IReadOnlyList<PrivacyFactRowViewModel> Facts { get; private set; }

        public string LimitsText { get; private set; }

        public string FlagsLine { get; private set; }

        public string OutOfScopeNote { get; private set; }

        public string StorageNote { get; private set; }

        // Always false. The card states the value in words.
        public bool AppliesAnyMode { get; private set; }

        // Always false. The card offers no mode control.
        public bool CanSelectMode { get; private set; }

        private static string JoinLimits(IReadOnlyList<string> limits)
        {
            if (limits == null || limits.Count == 0)
            {
                return "";
            }
            StringBuilder text = new StringBuilder();
            for (int index = 0; index < limits.Count; index++)
            {
                if (index > 0)
                {
                    text.AppendLine();
                    text.AppendLine();
                }
                text.Append(limits[index]);
            }
            return text.ToString();
        }
    }
}
