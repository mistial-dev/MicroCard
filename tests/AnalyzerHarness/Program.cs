using System.Collections.Immutable;
using System.Diagnostics;
using System.Text.Json;
using MicroCard.Analyzers;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

if (args.Length is not (2 or 3)) throw new ArgumentException("usage: AnalyzerHarness SOURCE_DIRECTORY CASES_JSON [EMISSION_JSON]");
var emission = args.Length == 3
    ? JsonSerializer.Deserialize<Emission>(File.ReadAllText(args[2]))
        ?? throw new InvalidDataException("Missing emission configuration")
    : null;
var emissionReferences = emission?.References.Select(path => MetadataReference.CreateFromFile(path)).ToImmutableArray();
var sources = Directory.GetFiles(args[0], "*.cs")
    .OrderBy(path => path, StringComparer.Ordinal)
    .Select(path => (path, text: File.ReadAllText(path))).ToArray();
if (sources.Length == 0) throw new InvalidDataException("No analyzer case sources");
var cases = JsonSerializer.Deserialize<Dictionary<string, string?>>(File.ReadAllText(args[1]))
    ?? throw new InvalidDataException("Missing cases");
if (emission is not null && emission.Outputs.Keys.Any(symbol => !cases.ContainsKey(symbol)))
    throw new InvalidDataException("Emission requested an unknown analyzer case");
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
    if (emission is not null && emission.Outputs.TryGetValue(symbol, out var output))
    {
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        var generated = emission.GeneratedSources.Select(path => CSharpSyntaxTree.ParseText(File.ReadAllText(path), parseOptions, path));
        var candidate = compilation.WithReferences(emissionReferences!.Value)
            .AddSyntaxTrees(generated).WithOptions(options.WithDeterministic(true));
        using var stream = File.Create(output);
        var result = candidate.Emit(stream);
        if (!result.Success)
            throw new InvalidOperationException($"{symbol}: emission failed\n{string.Join("\n", result.Diagnostics)}");
    }
}
Console.WriteLine($"PASS: {cases.Count} in-process analyzer cases in {elapsed.Elapsed.TotalSeconds:F3}s");

record Emission(string[] References, string[] GeneratedSources, Dictionary<string, string> Outputs);
