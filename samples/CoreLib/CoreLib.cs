using MicroCard.Framework;

[assembly: DependencyExport(DependencyAccess.Any)]
[assembly: DeviceAssemblyIdentity("mscorlib")]

namespace MicroCard.Core;

public static class CoreLibrary
{
    public static int Identity(int value) => value;
}

public static class Int32Math
{
    public static int Min(int left, int right) => left < right ? left : right;
    public static int Max(int left, int right) => left > right ? left : right;
    public static int Clamp(int value, int minimum, int maximum) =>
        value < minimum ? minimum : value > maximum ? maximum : value;
    public static int Sign(int value) => value < 0 ? -1 : value > 0 ? 1 : 0;
    public static int AbsSaturating(int value) =>
        value == int.MinValue ? int.MaxValue : value < 0 ? -value : value;
    public static int AddChecked(int left, int right) => checked(left + right);
    public static int SubtractChecked(int left, int right) => checked(left - right);
    public static int MultiplyChecked(int left, int right) => checked(left * right);
}

public static class Int32Comparison
{
    public static bool Equals(int left, int right) => left == right;
    public static int Compare(int left, int right) => left < right ? -1 : left > right ? 1 : 0;
}
