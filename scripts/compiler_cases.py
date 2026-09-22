"""Compile checkpoint cases once and verify the independent MC04 preprocessor gate."""
import hashlib
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from analyzer_cases import run_analyzer_cases
from validation_common import ROOT, build_managed, run

BOUNDARIES = [
    ('CASE_TRANSACTION_SCOPE', 'transaction-scope'),
    ('CASE_PARAMETERS_BOUNDARY', 'parameter-boundary'),
    ('CASE_DEPENDENCY_BOUNDARY', 'dependency-boundary'),
    ('CASE_ENTRY_BOUNDARY', 'entry-boundary'),
    ('CASE_METHOD_ROWS_BOUNDARY', 'method-row-boundary'),
    ('CASE_TYPE_ROWS_BOUNDARY', 'type-row-boundary'),
    ('CASE_FIELD_ROWS_BOUNDARY', 'field-row-boundary'),
]
REJECTIONS = [
    ('CASE_TRANSACTION_CURRENT', 'ambient-transaction', 'Unsupported System.Transactions member'),
    ('CASE_TRANSACTION', 'unsafe-transaction', 'Transactional method reaches irreversible Hardware.Write'),
    ('CASE_STORAGE_SCHEMA', 'storage-schema-bypass', 'Persistent byte maximum'),
    ('CASE_SYSTEM_SHA256_OVERLOAD', 'system-sha256-overload-bypass', 'Unsupported System.Security.Cryptography member'),
    ('CASE_SYSTEM_RNG_OVERLOAD', 'system-rng-overload-bypass', 'Unsupported System.Security.Cryptography member'),
    ('CASE_ASYNC_METHOD', 'async-bypass', 'Nested type unsupported'),
    ('CASE_USING_DECLARATION', 'using-bypass', 'MC04 exception handlers unsupported'),
    ('CASE_TYPEOF', 'typeof-bypass', 'Unsupported MC04 CIL operand InlineTok'),
    ('CASE_INIT_PROPERTY', 'init-property-bypass', 'Modified signatures unsupported'),
    ('CASE_REF_RETURN', 'ref-return-bypass', 'By-reference signatures unsupported'),
    ('CASE_STATIC_CONSTRUCTOR', 'static-constructor-bypass', 'Static constructor unsupported'),
    ('CASE_INTERFACE', 'interface-bypass', 'Interfaces unsupported'),
    ('CASE_NESTED_TYPE', 'nested-type-bypass', 'Nested type unsupported'),
    ('CASE_STATIC_FIELD', 'static-field-bypass', 'Unsupported field flags'),
    ('CASE_FIELD_TYPE', 'field-type-bypass', 'Only Int32 fields and constants supported'),
    ('CASE_METHOD_IMPL_FLAGS', 'method-flags-bypass', 'Unsupported method flags'),
    ('CASE_INHERITANCE', 'inheritance-bypass', 'Unsupported base type'),
    ('CASE_LITERAL_FIELD_TYPE', 'literal-field-bypass', 'Only Int32 fields and constants supported'),
    ('CASE_EVENT', 'event-bypass', 'Only Int32 fields and constants supported'),
    ('CASE_STATIC_AUTO_PROPERTY', 'static-auto-property-bypass', 'Unsupported field flags'),
    ('CASE_AUTO_PROPERTY_FIELD', 'auto-property-field-bypass', 'Only Int32 fields and constants supported'),
    ('CASE_IDENTIFIER', 'identifier-bypass', 'embedded identifier grammar'),
    ('CASE_PARAMETERS', 'parameters-bypass', 'Method parameter quota exceeded'),
    ('CASE_DEPENDENCY_LIMIT', 'dependency-limit-bypass', 'Dependency quota exceeded'),
    ('CASE_ENTRY_LIMIT', 'entry-limit-bypass', 'Entry-point quota exceeded'),
    ('CASE_METHOD_ROWS_LIMIT', 'method-row-limit-bypass', 'MC04 metadata row quota exceeded'),
    ('CASE_TYPE_ROWS_LIMIT', 'type-row-limit-bypass', 'MC04 metadata row quota exceeded'),
    ('CASE_FIELD_ROWS_LIMIT', 'field-row-limit-bypass', 'MC04 metadata row quota exceeded'),
    ('CASE_LOCALS', 'excessive-locals', 'MC04 local-variable quota exceeded'),
    ('CASE_SWITCH_LIMIT', 'excessive-switch', 'Switch quota'),
]


def run_compiler_cases(jobs=1, prebuilt=False):
    if not prebuilt:
        build_managed(["tests/AnalyzerHarness", "tests/AnalyzerCases",
                       "tests/TransactionRuntimeNegative", "managed/MicroCard.Tool"], jobs)
    directory = ROOT / "work/compiler-cases"
    directory.mkdir(parents=True, exist_ok=True)
    resolved = run("dotnet", "msbuild", "tests/AnalyzerCases", "-t:ResolveReferences",
                   "-p:Configuration=Release", "-p:BuildProjectReferences=false",
                   "-getItem:ReferencePath", capture_output=True, text=True)
    references = [item["FullPath"] for item in json.loads(resolved.stdout)["Items"]["ReferencePath"]]
    symbols = [symbol for symbol, _ in BOUNDARIES] + [symbol for symbol, _, _ in REJECTIONS]
    outputs = {symbol: str(directory / symbol / "AnalyzerCases.dll") for symbol in symbols}
    for output in outputs.values():
        Path(output).unlink(missing_ok=True)
    emission = directory / "emission.json"
    emission.write_text(json.dumps({
        "References": references,
        "GeneratedSources": [str(path) for path in sorted((ROOT / "tests/AnalyzerCases/obj/Release/net10.0").glob("*.cs"))],
        "Outputs": outputs,
    }, indent=2) + "\n")
    run_analyzer_cases(emission, prebuilt=True)
    framework = ROOT / "managed/MicroCard.Framework/bin/Release/net10.0/MicroCard.Framework.dll"
    pin = hashlib.sha256(framework.read_bytes()).hexdigest()
    tool = ROOT / "managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll"
    cases = [(outputs[symbol], name, None) for symbol, name in BOUNDARIES]
    cases += [(outputs[symbol], name, error) for symbol, name, error in REJECTIONS]
    cases.append((ROOT / "tests/TransactionRuntimeNegative/bin/Release/net10.0/TransactionRuntimeNegative.dll",
                  "unsafe-explicit-transaction", "Transactional method reaches irreversible Hardware.Write"))

    def check(case):
        assembly, name, error = case
        prefix = directory / name / "output"
        prefix.parent.mkdir(parents=True, exist_ok=True)
        for suffix in (".mca", ".json", ".map.json"):
            prefix.with_suffix(suffix).unlink(missing_ok=True)
        result = run("dotnet", str(tool), str(assembly), str(prefix), str(framework), pin,
                     check=False, capture_output=True, text=True)
        if error is None:
            assert result.returncode == 0 and prefix.with_suffix(".mca").exists(), (name, result.stdout, result.stderr)
        else:
            assert result.returncode != 0 and error in result.stdout + result.stderr, (name, result.stdout, result.stderr)
            assert not prefix.with_suffix(".mca").exists(), f"{name} emitted a rejected assembly"

    with ThreadPoolExecutor(max_workers=jobs) as workers:
        list(workers.map(check, cases))
    print(f"PASS: {len(cases)} independent preprocessor cases; {len(symbols)} in-process compilations")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, default=1)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    run_compiler_cases(args.jobs)
