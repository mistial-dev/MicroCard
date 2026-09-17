# Rider authoring

Reference `MicroCard.Analyzers` as a private development package. Its `buildTransitive` asset adds the analyzer DLL to MSBuild, so command-line builds and Rider use the same diagnostics. In [Rider's Roslyn Analyzers settings](https://www.jetbrains.com/help/rider/Settings_Roslyn_Analyzers.html), keep **Enable Roslyn analyzers** enabled. **Include Roslyn analyzers in Solution-Wide analysis** is optional and requires Rider's solution-wide analysis setting.

Set each project's `RootNamespace` to the namespace used by its source files. MicroCard's projects do this explicitly when the assembly name and namespace differ, so Rider's namespace-to-project inspection does not report false mismatches. File-scoped namespaces and array collection expressions are part of the supported authoring profile.

All MicroCard diagnostics are enabled by default at **error** severity. An ordinary build fails when any of them is present. `/warnaserror` is not required.

- `MCA0001`: unsupported C# language feature
- `MCA0002`: unsupported managed type
- `MCA0003`: declaration shape that cannot be lowered
- `MCA0004`: call outside the trusted framework or declared managed dependencies
- `MCA0005`: invalid assembly lifecycle declaration
- `MCA0006`: invalid dependency export policy
- `MCA0007`: invalid dependency requirement
- `MCA0008`: irreversible operation reachable from a transaction
- `MCA0009`: recursion or a managed call path beyond the 32-frame runtime limit
- `MCA0010`–`MCA0017`: locals, arena allocation, loops, switches, object counts and parameter bounds
- `MCA0018`–`MCA0023`: dependency, entry-point and MC04 table bounds
- `MCA0024`: invalid persistent-storage declaration
- `MCA0025`: persistent-storage access outside the signed schema

Rider may display a per-solution severity override. Keep `MCA0001` through `MCA0025` at **Error** for normal development. Repository or user `.editorconfig` settings can override Roslyn severities, so CI must run the ordinary build and the independent preprocessor/device checks even when the editor looks clean.

Rider 2026.1 was verified against this repository: after loading the solution it reports `Roslyn analyzers are present in solution` and includes the managed projects in solution-wide analysis. No Rider-specific plugin is required because `MicroCard.Analyzers` is a standard Roslyn analyzer reference.

The analyzer gives early authoring feedback. A suppressed, disabled or bypassed analyzer never authorizes an assembly. The preprocessor and Rust device verifier remain security boundaries and must independently reject unsupported bytecode, signatures, native imports, transaction effects and resource declarations.

The repository acceptance script packs the analyzer, places it behind a test SDK package, restores a clean consumer through that intermediate dependency, and proves a valid build succeeds. It then builds one unsuppressed failing case for every diagnostic ID and requires each ordinary build to fail, which verifies the published default severity.
