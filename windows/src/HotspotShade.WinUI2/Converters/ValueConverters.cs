using System;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Data;

namespace HotspotShade.WinUI2.Converters
{
    // Show or hide an element from a boolean. Use ConverterParameter=Invert
    // for the opposite value.
    public sealed class BoolToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, string language)
        {
            bool visible = value is bool && (bool)value;
            string mode = parameter as string;
            if (mode != null && mode.Equals("Invert", StringComparison.OrdinalIgnoreCase))
            {
                visible = !visible;
            }
            return visible ? Visibility.Visible : Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, string language)
        {
            throw new NotSupportedException();
        }
    }

    // Show an element only when the enum value name matches the parameter.
    public sealed class EnumNameToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, string language)
        {
            string expected = parameter as string;
            string actual = value == null ? "" : value.ToString();
            bool visible = expected != null && string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase);
            return visible ? Visibility.Visible : Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, string language)
        {
            throw new NotSupportedException();
        }
    }

    // Show an element only when the string has content.
    public sealed class StringToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, string language)
        {
            string text = value as string;
            return string.IsNullOrWhiteSpace(text) ? Visibility.Collapsed : Visibility.Visible;
        }

        public object ConvertBack(object value, Type targetType, object parameter, string language)
        {
            throw new NotSupportedException();
        }
    }
}
