namespace MicroCard.Build;

internal static class EmbeddedIdentifier
{
    internal static bool IsValid(string? value)
    {
        if (value is null || value.Length is < 1 or > 64 || !IsAlphaNumeric(value[0]))
            return false;
        foreach (char character in value)
            if (!IsAlphaNumeric(character) && character is not ('.' or '_' or '-'))
                return false;
        return true;
    }

    private static bool IsAlphaNumeric(char value) =>
        value is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9';
}
