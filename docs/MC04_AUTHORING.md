# Write an MC04 assembly

An MC04 application is a C# assembly converted into the compact MC04 device format.
Start from the `microcard-assembly` template. It creates a normal SDK-style project,
so completion, XML documentation, and diagnostics work in Visual Studio, Rider, and
other C# editors.

## Install the local template

Until the packages are published, create a local feed from a MicroCard checkout:

```sh
mkdir -p work/packages
dotnet pack managed/OpenPhysical.MicroCard.Sdk -c Release -o work/packages
dotnet pack managed/OpenPhysical.MicroCard.Templates -c Release -o work/packages
dotnet new install work/packages/OpenPhysical.MicroCard.Templates.0.1.0-wip.nupkg
dotnet new microcard-assembly -n CredentialCard \
  --sdkVersion 0.1.0-wip \
  --aid A000000001
```

The generated project has one authoring dependency:

```xml
<PackageReference Include="OpenPhysical.MicroCard.Sdk"
                  Version="$(MicroCardSdkVersion)"
                  PrivateAssets="all" />
```

Use a .NET 10 SDK. The template does not require a particular patch release.

## Application shape

`CardAssembly` marks one public static application class. `Process` is required.
`Install`, `Select`, `Deselect`, and `Uninstall` are optional. Every lifecycle method
that is present must be public, static, parameterless, and return `void`.

```csharp
using MicroCard.Framework;

[CardAssembly("A000000001")]
public static class CredentialCard
{
    public static void Install() { }

    public static void Process()
    {
        AssemblyContext context = AssemblyContext.Current;
        context.Response.SetStatus(StatusWord.Success);
    }
}
```

The application uses `AssemblyContext.Current` for the current command, response,
persistent storage, opaque keys, random data, secure-channel state, credentials, and
runtime operations. `StorageId`, `KeySlot`, `CredentialSlot`, `KeyAlgorithm`,
`StatusWord`, and `SecurityLevel` prevent unrelated integer identities from being
mixed accidentally. These service handles and typed values lower directly to MC04
operations and allocate no device objects. The generated [API reference](MC04_API.md)
lists every recognized call.

Declare persistent keys before using them:

```csharp
[assembly: PersistentInt32(1)]
[assembly: PersistentBytes(2, 256)]

int count = AssemblyContext.Current.Storage.GetInt32((StorageId)1);
AssemblyContext.Current.Storage.SetInt32((StorageId)1, checked(count + 1));
```

Ordinary writes become durable at the safe command boundary and do not allocate
rollback state. Use the supported local `System.Transactions` profile only when a
group of changes needs rollback:

```csharp
using System.Transactions;

using var scope = new TransactionScope();
UpdatePersistentState();
scope.Complete();
```

Disposing a completed scope commits synchronously. Disposing without `Complete()`
aborts it. Nested scopes, async flow, distributed transactions, and resource-manager
enlistment are outside the MC04 profile. See [transactions](TRANSACTIONS.md) for the
failure rules.

## Build and verify

An ordinary build compiles the C# project, runs the profile analyzer, and converts the
result:

```sh
dotnet build CredentialCard
```

The outputs are under
`CredentialCard/obj/Debug/net10.0/microcard/`:

- `CredentialCard.mca` is the executable MC04 image.
- `CredentialCard.json` is host-side manifest input for packaging.
- `CredentialCard.map.json` is a host-only debug map.

Validate the image with the host runtime:

```sh
cargo run -p microcard-sim -- \
  verify-assembly CredentialCard/obj/Debug/net10.0/microcard/CredentialCard.mca
```

The low-level `run-mc04` command accepts a numeric MethodDef row and can exercise a
pure managed method. It does not provide the native `AssemblyContext` services needed
to invoke `Process`. Run signed loading, selection, APDU processing, SCP03, and
persistence through the host acceptance path:

```sh
python3 scripts/wallet_acceptance.py
```

The [wallet guide](WALLET.md) describes that flow. To run any converted template
assembly through signed loading, installation, selection, and invocation on the host:

```sh
python3 scripts/run_mc04_assembly.py \
  path/to/MyAssembly.mca path/to/MyAssembly.json A000000001 [COMMAND_HEX]
```

## What the SDK contributes

`OpenPhysical.MicroCard.Sdk` contains four build-time pieces:

1. `MicroCard.AppModel.dll` and its XML documentation give the compiler and editor the
   supported application types.
2. Roslyn analyzers report unsupported source shapes during editing and builds.
3. MSBuild targets invoke the MC04 converter after compilation.
4. Conversion matches calls by exact type, member, and signature against
   `abi/mc04.toml`.

The app-model reference is compile-time only. The converter consumes recognized calls
and does not emit `MicroCard.AppModel` as a device dependency. Runtime dependencies
are only the managed libraries explicitly declared by the application and resolved
from signed packages. The Rust verifier independently checks the converted image, so
editor diagnostics never grant runtime authority.

Run the isolated package and template acceptance test with:

```sh
python3 scripts/sdk_template_smoke.py
```
