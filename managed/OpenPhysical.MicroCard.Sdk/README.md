# OpenPhysical.MicroCard.Sdk

This package is the single authoring dependency for MC04 assemblies. It provides the
compile-time application model and XML documentation, Roslyn diagnostics, and the
MSBuild conversion target. The application model is consumed during conversion and
is not emitted as an MC04 device dependency.

```xml
<PackageReference Include="OpenPhysical.MicroCard.Sdk"
                  Version="$(MicroCardSdkVersion)"
                  PrivateAssets="all" />
```

`dotnet build` writes the converted `.mca`, manifest, and debug map beneath
`obj/<Configuration>/<TargetFramework>/microcard`.
