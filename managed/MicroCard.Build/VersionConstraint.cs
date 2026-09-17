namespace MicroCard.Build;

public readonly struct NormalizedVersion : System.IComparable<NormalizedVersion>
{
    public NormalizedVersion(ushort major, ushort minor, ushort patch, ushort revision)
    {
        Major = major;
        Minor = minor;
        Patch = patch;
        Revision = revision;
    }

    public ushort Major { get; }
    public ushort Minor { get; }
    public ushort Patch { get; }
    public ushort Revision { get; }
    public ushort[] ToArray() => new[] { Major, Minor, Patch, Revision };

    public int CompareTo(NormalizedVersion other)
    {
        var result = Major.CompareTo(other.Major);
        if (result != 0) return result;
        result = Minor.CompareTo(other.Minor);
        if (result != 0) return result;
        result = Patch.CompareTo(other.Patch);
        return result != 0 ? result : Revision.CompareTo(other.Revision);
    }
}

public readonly struct NormalizedVersionRange
{
    public NormalizedVersionRange(
        NormalizedVersion? minimum,
        bool minimumInclusive,
        NormalizedVersion? maximum,
        bool maximumInclusive)
    {
        Minimum = minimum;
        MinimumInclusive = minimumInclusive;
        Maximum = maximum;
        MaximumInclusive = maximumInclusive;
    }

    public NormalizedVersion? Minimum { get; }
    public bool MinimumInclusive { get; }
    public NormalizedVersion? Maximum { get; }
    public bool MaximumInclusive { get; }

    public bool IsMatch(NormalizedVersion version)
    {
        if (Minimum is { } minimum)
        {
            var comparison = version.CompareTo(minimum);
            if (comparison < 0 || comparison == 0 && !MinimumInclusive)
                return false;
        }
        if (Maximum is { } maximum)
        {
            var comparison = version.CompareTo(maximum);
            if (comparison > 0 || comparison == 0 && !MaximumInclusive)
                return false;
        }
        return true;
    }
}

/// <summary>Allocation-free parsing and matching for the bounded MicroCard version-constraint grammar.</summary>
public static class VersionConstraint
{
    public static bool IsValid(string? constraint) =>
        TryEvaluate(constraint, default, evaluate: false, out _);

    public static bool IsMatch(string? constraint, string? version)
    {
        if (!TryReadVersion(version, out var candidate))
            return false;
        return TryEvaluate(constraint, candidate, evaluate: true, out var matches) && matches;
    }

    public static NormalizedVersion ParseVersion(string? version)
    {
        if (!TryReadVersion(version, out var parsed))
            throw new System.FormatException("Invalid semantic version");
        return parsed.ToNormalized();
    }

    public static NormalizedVersionRange[] Normalize(string? constraint)
    {
        if (string.IsNullOrWhiteSpace(constraint) || constraint!.Length > 128)
            throw new System.FormatException("Invalid version constraint");
        var ranges = new System.Collections.Generic.List<NormalizedVersionRange>();
        var offset = 0;
        var haveTerm = false;
        var group = new NormalizedVersionRange(null, false, null, false);
        while (true)
        {
            SkipSeparators(constraint, ref offset);
            if (offset == constraint.Length || AtOr(constraint, offset))
            {
                if (!haveTerm || Empty(group))
                    throw new System.FormatException("Empty version range");
                ranges.Add(group);
                if (ranges.Count > 8)
                    throw new System.FormatException("Too many version alternatives");
                if (offset == constraint.Length)
                    break;
                offset += 2;
                haveTerm = false;
                group = new NormalizedVersionRange(null, false, null, false);
                continue;
            }
            if (!ReadNormalizedTerm(constraint, ref offset, out var term))
                throw new System.FormatException("Invalid version constraint");
            group = Intersect(group, term);
            haveTerm = true;
            if (offset < constraint.Length && !char.IsWhiteSpace(constraint[offset]) &&
                constraint[offset] != ',' && !AtOr(constraint, offset))
                throw new System.FormatException("Invalid version separator");
        }
        ranges.Sort(static (left, right) => CompareMinimum(left, right));
        var canonical = new System.Collections.Generic.List<NormalizedVersionRange>(ranges.Count);
        foreach (var range in ranges)
        {
            if (canonical.Count == 0 || !Touches(canonical[canonical.Count - 1], range))
                canonical.Add(range);
            else
                canonical[canonical.Count - 1] = Union(canonical[canonical.Count - 1], range);
        }
        return canonical.ToArray();
    }

    private static bool ReadNormalizedTerm(string text, ref int offset, out NormalizedVersionRange range)
    {
        range = default;
        var operation = Operation.Exact;
        if (text[offset] is '^' or '~' or '=')
            operation = text[offset++] switch { '^' => Operation.Caret, '~' => Operation.Tilde, _ => Operation.Exact };
        else if (text[offset] is '<' or '>')
        {
            operation = text[offset++] == '<' ? Operation.Less : Operation.Greater;
            if (offset < text.Length && text[offset] == '=')
            {
                operation = operation == Operation.Less ? Operation.LessOrEqual : Operation.GreaterOrEqual;
                offset++;
            }
        }
        if (offset == text.Length)
            return false;
        var parsed = default(Version);
        var components = 0;
        var wildcard = false;
        while (true)
        {
            if (offset < text.Length && text[offset] is '*' or 'x' or 'X')
            {
                wildcard = true;
                offset++;
            }
            else if (!ReadComponent(text, ref offset, out var component))
                return false;
            else
                parsed.Set(components, component);
            components++;
            if (offset >= text.Length || text[offset] != '.')
                break;
            if (wildcard || components == 4)
                return false;
            offset++;
        }
        if (components < 2 || wildcard && operation != Operation.Exact)
            return false;
        var value = parsed.ToNormalized();
        if (wildcard || operation is Operation.Caret or Operation.Tilde)
        {
            if (!TryUpperBound(operation, parsed, components, wildcard, out var upper))
                return false;
            range = new NormalizedVersionRange(value, true, upper.ToNormalized(), false);
            return true;
        }
        range = operation switch
        {
            Operation.Exact => new(value, true, value, true),
            Operation.Less => new(null, false, value, false),
            Operation.LessOrEqual => new(null, false, value, true),
            Operation.Greater => new(value, false, null, false),
            Operation.GreaterOrEqual => new(value, true, null, false),
            _ => default,
        };
        return true;
    }

    private static NormalizedVersionRange Intersect(NormalizedVersionRange left, NormalizedVersionRange right)
    {
        var minimum = left.Minimum;
        var minimumInclusive = left.MinimumInclusive;
        if (minimum is null || right.Minimum is { } rightMinimum &&
            (rightMinimum.CompareTo(minimum.Value) > 0 ||
             rightMinimum.CompareTo(minimum.Value) == 0 && !right.MinimumInclusive))
        {
            minimum = right.Minimum;
            minimumInclusive = right.MinimumInclusive;
        }
        else if (right.Minimum is { } equalMinimum && equalMinimum.CompareTo(minimum.Value) == 0)
            minimumInclusive &= right.MinimumInclusive;

        var maximum = left.Maximum;
        var maximumInclusive = left.MaximumInclusive;
        if (maximum is null || right.Maximum is { } rightMaximum &&
            (rightMaximum.CompareTo(maximum.Value) < 0 ||
             rightMaximum.CompareTo(maximum.Value) == 0 && !right.MaximumInclusive))
        {
            maximum = right.Maximum;
            maximumInclusive = right.MaximumInclusive;
        }
        else if (right.Maximum is { } equalMaximum && equalMaximum.CompareTo(maximum.Value) == 0)
            maximumInclusive &= right.MaximumInclusive;
        return new NormalizedVersionRange(minimum, minimumInclusive, maximum, maximumInclusive);
    }

    private static bool Empty(NormalizedVersionRange range)
    {
        if (range.Minimum is not { } minimum || range.Maximum is not { } maximum)
            return false;
        var comparison = minimum.CompareTo(maximum);
        return comparison > 0 || comparison == 0 && !(range.MinimumInclusive && range.MaximumInclusive);
    }

    private static int CompareMinimum(NormalizedVersionRange left, NormalizedVersionRange right)
    {
        if (left.Minimum is null) return right.Minimum is null ? 0 : -1;
        if (right.Minimum is null) return 1;
        var comparison = left.Minimum.Value.CompareTo(right.Minimum.Value);
        return comparison != 0 ? comparison : right.MinimumInclusive.CompareTo(left.MinimumInclusive);
    }

    private static bool Touches(NormalizedVersionRange left, NormalizedVersionRange right)
    {
        if (left.Maximum is null || right.Minimum is null)
            return true;
        var comparison = left.Maximum.Value.CompareTo(right.Minimum.Value);
        return comparison > 0 || comparison == 0 && (left.MaximumInclusive || right.MinimumInclusive);
    }

    private static NormalizedVersionRange Union(NormalizedVersionRange left, NormalizedVersionRange right)
    {
        if (left.Maximum is null || right.Maximum is null)
            return new NormalizedVersionRange(left.Minimum, left.MinimumInclusive, null, false);
        var comparison = left.Maximum.Value.CompareTo(right.Maximum.Value);
        if (comparison > 0)
            return left;
        if (comparison < 0)
            return new NormalizedVersionRange(left.Minimum, left.MinimumInclusive,
                right.Maximum, right.MaximumInclusive);
        return new NormalizedVersionRange(left.Minimum, left.MinimumInclusive,
            left.Maximum, left.MaximumInclusive || right.MaximumInclusive);
    }

    private static bool TryEvaluate(string? text, Version candidate, bool evaluate, out bool matches)
    {
        matches = false;
        if (string.IsNullOrWhiteSpace(text) || text!.Length > 128)
            return false;

        var offset = 0;
        var groupHasTerm = false;
        var groupMatches = true;
        while (true)
        {
            SkipSeparators(text, ref offset);
            if (offset == text.Length)
            {
                if (!groupHasTerm)
                    return false;
                matches |= groupMatches;
                return true;
            }
            if (AtOr(text, offset))
            {
                if (!groupHasTerm)
                    return false;
                matches |= groupMatches;
                groupHasTerm = false;
                groupMatches = true;
                offset += 2;
                continue;
            }
            if (!ReadTerm(text, ref offset, candidate, evaluate, out var termMatches))
                return false;
            groupHasTerm = true;
            groupMatches &= termMatches;
            if (offset < text.Length && !char.IsWhiteSpace(text[offset]) && text[offset] != ',' && !AtOr(text, offset))
                return false;
        }
    }

    private static bool ReadTerm(string text, ref int offset, Version candidate, bool evaluate, out bool matches)
    {
        matches = !evaluate;
        var operation = Operation.Exact;
        if (text[offset] is '^' or '~' or '=')
        {
            operation = text[offset++] switch
            {
                '^' => Operation.Caret,
                '~' => Operation.Tilde,
                _ => Operation.Exact,
            };
        }
        else if (text[offset] is '<' or '>')
        {
            operation = text[offset++] == '<' ? Operation.Less : Operation.Greater;
            if (offset < text.Length && text[offset] == '=')
            {
                operation = operation == Operation.Less ? Operation.LessOrEqual : Operation.GreaterOrEqual;
                offset++;
            }
        }
        if (offset == text.Length)
            return false;

        var parsed = default(Version);
        var components = 0;
        var wildcard = false;
        while (true)
        {
            if (offset < text.Length && text[offset] is '*' or 'x' or 'X')
            {
                wildcard = true;
                offset++;
            }
            else if (!ReadComponent(text, ref offset, out var component))
            {
                return false;
            }
            else
            {
                parsed.Set(components, component);
            }
            components++;
            if (offset >= text.Length || text[offset] != '.')
                break;
            if (wildcard || components == 4)
                return false;
            offset++;
        }
        if (components < 2 || wildcard && operation != Operation.Exact)
            return false;
        if (!evaluate)
            return ValidateUpperBound(operation, parsed, components, wildcard);

        var comparison = candidate.CompareTo(parsed);
        switch (operation)
        {
            case Operation.Exact when !wildcard: matches = comparison == 0; return true;
            case Operation.Less: matches = comparison < 0; return true;
            case Operation.LessOrEqual: matches = comparison <= 0; return true;
            case Operation.Greater: matches = comparison > 0; return true;
            case Operation.GreaterOrEqual: matches = comparison >= 0; return true;
        }
        if (!TryUpperBound(operation, parsed, components, wildcard, out var upper))
            return false;
        matches = comparison >= 0 && candidate.CompareTo(upper) < 0;
        return true;
    }

    private static bool ValidateUpperBound(Operation operation, Version parsed, int components, bool wildcard)
    {
        if (!wildcard && operation is not (Operation.Caret or Operation.Tilde))
            return true;
        return TryUpperBound(operation, parsed, components, wildcard, out _);
    }

    private static bool TryUpperBound(Operation operation, Version lower, int components, bool wildcard, out Version upper)
    {
        upper = lower;
        var increment = -1;
        if (wildcard)
            increment = components - 2;
        else if (operation == Operation.Tilde)
            increment = components == 2 ? 0 : components - 2;
        else if (operation == Operation.Caret)
        {
            for (var index = 0; index < components; index++)
            {
                if (lower.Get(index) != 0)
                {
                    increment = index;
                    break;
                }
            }
            if (increment < 0)
                increment = components - 1;
        }
        else
            return false;

        if (upper.Get(increment) == ushort.MaxValue)
            return false;
        upper.Set(increment, (ushort)(upper.Get(increment) + 1));
        upper.ClearAfter(increment);
        return true;
    }

    private static bool TryReadVersion(string? text, out Version version)
    {
        version = default;
        if (string.IsNullOrEmpty(text) || text!.Length > 31)
            return false;
        var offset = 0;
        var components = 0;
        while (true)
        {
            if (components == 4 || !ReadComponent(text, ref offset, out var component))
                return false;
            version.Set(components++, component);
            if (offset == text.Length)
                return components >= 2;
            if (text[offset++] != '.')
                return false;
        }
    }

    private static bool ReadComponent(string text, ref int offset, out ushort component)
    {
        component = 0;
        var start = offset;
        var value = 0;
        while (offset < text.Length && text[offset] is >= '0' and <= '9')
        {
            value = value * 10 + text[offset++] - '0';
            if (value > ushort.MaxValue)
                return false;
        }
        if (offset == start || offset - start > 1 && text[start] == '0')
            return false;
        component = (ushort)value;
        return true;
    }

    private static void SkipSeparators(string text, ref int offset)
    {
        while (offset < text.Length && (char.IsWhiteSpace(text[offset]) || text[offset] == ','))
            offset++;
    }

    private static bool AtOr(string text, int offset) =>
        offset + 1 < text.Length && text[offset] == '|' && text[offset + 1] == '|';

    private enum Operation { Exact, Less, LessOrEqual, Greater, GreaterOrEqual, Caret, Tilde }

    private struct Version
    {
        private ushort _major;
        private ushort _minor;
        private ushort _patch;
        private ushort _revision;

        public readonly ushort Get(int index) => index switch
        {
            0 => _major,
            1 => _minor,
            2 => _patch,
            3 => _revision,
            _ => throw new System.ArgumentOutOfRangeException(nameof(index)),
        };

        public void Set(int index, ushort value)
        {
            switch (index)
            {
                case 0: _major = value; break;
                case 1: _minor = value; break;
                case 2: _patch = value; break;
                case 3: _revision = value; break;
                default: throw new System.ArgumentOutOfRangeException(nameof(index));
            }
        }

        public void ClearAfter(int index)
        {
            if (index < 3) _revision = 0;
            if (index < 2) _patch = 0;
            if (index < 1) _minor = 0;
        }

        public readonly int CompareTo(Version other)
        {
            var result = _major.CompareTo(other._major);
            if (result != 0) return result;
            result = _minor.CompareTo(other._minor);
            if (result != 0) return result;
            result = _patch.CompareTo(other._patch);
            return result != 0 ? result : _revision.CompareTo(other._revision);
        }

        public readonly NormalizedVersion ToNormalized() =>
            new(_major, _minor, _patch, _revision);
    }
}
