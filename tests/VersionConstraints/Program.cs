using System;
using System.Linq;
using MicroCard.Build;

var cases = new (string Constraint, string Version, bool Expected)[]
{
    ("1.2.3", "1.2.3", true), ("=1.2.3", "1.2.3", true), ("1.2.3", "1.2.4", false),
    ("1.2.x", "1.2.0", true), ("1.2.X", "1.2.65535", true), ("1.2.*", "1.3.0", false),
    ("<1.2.3", "1.2.2", true), ("<1.2.3", "1.2.3", false), ("<=1.2.3", "1.2.3", true),
    (">1.2.3", "1.2.4", true), (">1.2.3", "1.2.3", false), (">=1.2.3", "1.2.3", true),
    (">=1.2.0 <2.0.0", "1.9.4", true), (">=1.2.0, <2.0.0", "2.0.0", false),
    ("1.2.x || >=2.1.0", "2.2.0", true), ("1.2.x || >=2.1.0", "2.0.0", false),
    ("^1.2.3", "1.9.0", true), ("^1.2.3", "2.0.0", false),
    ("^0.2.3", "0.2.9", true), ("^0.2.3", "0.3.0", false),
    ("~1.2.3", "1.2.99", true), ("~1.2.3", "1.3.0", false),
    ("~1.2", "1.99.0", true), ("~1.2", "2.0.0", false),
};

foreach (var item in cases)
{
    var actual = VersionConstraint.IsMatch(item.Constraint, item.Version);
    if (actual != item.Expected)
        throw new InvalidOperationException($"{item.Constraint} against {item.Version}: expected {item.Expected}, got {actual}");
    var normalized = VersionConstraint.Normalize(item.Constraint);
    var normalizedMatch = normalized.Any(range => range.IsMatch(VersionConstraint.ParseVersion(item.Version)));
    if (normalizedMatch != item.Expected)
        throw new InvalidOperationException($"Normalized {item.Constraint} disagrees for {item.Version}");
}

var merged = VersionConstraint.Normalize("1.2.x || >=1.2.5 <2.0.0");
if (merged.Length != 1 || !merged[0].IsMatch(VersionConstraint.ParseVersion("1.9.9")))
    throw new InvalidOperationException("Overlapping alternatives were not canonicalized");

var invalid = new[]
{
    "", "1", "1..2", "01.2.3", "1.2.x.4", ">1.2.x", "1.2.3 ||", "|| 1.2.3",
    "1.2.3beta", "65536.0.0", "^65535.0.0", "1.2.3 | 2.0.0",
};
foreach (var constraint in invalid)
{
    if (VersionConstraint.IsValid(constraint))
        throw new InvalidOperationException($"Expected invalid constraint: {constraint}");
}

if (VersionConstraint.IsMatch("1.2.x", "1.02.3") || VersionConstraint.IsMatch("1.2.x", "1.2.3.4.5"))
    throw new InvalidOperationException("Accepted an invalid candidate version");

string[] validIdentifiers = ["a", "mscorlib", "MicroCard.Cryptography", "selected-buffer", new('a', 64)];
string[] invalidIdentifiers = ["", ".hidden", "a/b", "a\\b", "a\"b", "a b", "é", "a\n", new('a', 65)];
if (validIdentifiers.Any(value => !EmbeddedIdentifier.IsValid(value)) ||
    invalidIdentifiers.Any(EmbeddedIdentifier.IsValid))
    throw new InvalidOperationException("Embedded identifier grammar mismatch");

Console.WriteLine($"PASS: {cases.Length} version matches and {invalid.Length + 2} rejection cases");
