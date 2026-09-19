using System.Collections.Immutable;
using System.Diagnostics;
using System.Text.Json;
using MicroCard.Analyzers;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

if (args.Length != 2) throw new ArgumentException("usage: AnalyzerHarness SOURCE_DIRECTORY CASES_JSON");
var sources = Directory.GetFiles(args[0], "*.cs")
    .OrderBy(path => path, StringComparer.Ordinal)
    .Select(path => (path, text: File.ReadAllText(path))).ToArray();
if (sources.Length == 0) throw new InvalidDataException("No analyzer case sources");
var cases = JsonSerializer.Deserialize<Dictionary<string, string?>>(File.ReadAllText(args[1]))
    ?? throw new InvalidDataException("Missing cases");
var references = ((string?)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")
    ?? throw new InvalidOperationException("Runtime references unavailable"))
    .Split(Path.PathSeparator).Append(typeof(MicroCard.Framework.Host).Assembly.Location)
    .Distinct(StringComparer.Ordinal).Select(path => MetadataReference.CreateFromFile(path)).ToImmutableArray();
var analyzers = ImmutableArray.Create<DiagnosticAnalyzer>(new MicroCardProfileAnalyzer());
var elapsed = Stopwatch.StartNew();
foreach (var (symbol, expected) in cases)
{
    var parseOptions = new CSharpParseOptions(LanguageVersion.Preview,
        preprocessorSymbols: symbol.Length == 0 ? [] : [symbol]);
    var trees = sources.Select(source => CSharpSyntaxTree.ParseText(source.text, parseOptions, source.path));
    var options = new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary,
        optimizationLevel: symbol == "CASE_LOCALS" ? OptimizationLevel.Debug : OptimizationLevel.Release,
        nullableContextOptions: NullableContextOptions.Enable);
    var compilation = CSharpCompilation.Create("AnalyzerCases", trees, references, options);
    var diagnostics = await compilation.WithAnalyzers(analyzers).GetAllDiagnosticsAsync();
    var errors = diagnostics.Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error).ToArray();
    if (diagnostics.Any(diagnostic => diagnostic.Id == "AD0001"))
        throw new InvalidOperationException($"Analyzer crashed for {symbol}: {string.Join("\n", diagnostics)}");
    if (expected is null ? errors.Length != 0 : !errors.Any(diagnostic => diagnostic.Id == expected))
        throw new InvalidOperationException($"{symbol}: expected {expected ?? "success"}\n{string.Join("\n", diagnostics)}");
}
Console.WriteLine($"PASS: {cases.Count} in-process analyzer cases in {elapsed.Elapsed.TotalSeconds:F3}s");
