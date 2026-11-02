using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace NetFlow.App.Converters;

public class TabVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        string? currentTab = value?.ToString();
        string? targetTab = parameter?.ToString();
        bool isMatch = string.Equals(currentTab, targetTab, StringComparison.OrdinalIgnoreCase);

        if (targetType == typeof(Visibility))
        {
            return isMatch ? Visibility.Visible : Visibility.Collapsed;
        }

        return isMatch;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is true)
        {
            return parameter?.ToString() ?? System.Windows.Data.Binding.DoNothing;
        }
        return System.Windows.Data.Binding.DoNothing;
    }
}

public class BooleanToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        bool b = value is true;
        if (parameter?.ToString() == "Inverse") b = !b;
        return b ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
