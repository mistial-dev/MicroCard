using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;
using MicroCard.Build;

namespace MicroCard.Analyzers;

public sealed partial class MicroCardProfileAnalyzer
{
    private static void AnalyzeInvocation(OperationAnalysisContext context)
    {
        var operation = (IInvocationOperation)context.Operation;
        if (!AllowedMember(operation.TargetMethod, context.Compilation))
            Report(context, ExternalCall, operation.Syntax.GetLocation(), operation.TargetMethod.ToDisplayString());
        AnalyzePersistentAccess(context, operation);
    }

    private static void AnalyzePersistentAccess(
        OperationAnalysisContext context,
        IInvocationOperation operation)
    {
        var method = operation.TargetMethod;
        if (method.ContainingAssembly?.Name != "MicroCard.Framework" ||
            method.ContainingNamespace?.ToDisplayString() != "MicroCard.Framework" ||
            method.ContainingType?.Name is not ("DomainStorage" or "DomainStore"))
            return;
        var kind = method.Name switch
        {
            "GetInt32" or "SetInt32" => 1,
            "GetBytes" or "SetBytes" or "DeleteBytes" or "ContainsBytes" => 2,
            _ => 0,
        };
        if (kind == 0 || operation.Arguments.Length == 0)
            return;
        var keyValue = operation.Arguments[0].Value.ConstantValue;
        if (!keyValue.HasValue || keyValue.Value is not int key || key < 0)
        {
            Report(context, PersistentAccess, operation.Arguments[0].Syntax.GetLocation(),
                "Persistent storage keys must be non-negative compile-time Int32 constants");
            return;
        }
        var declarations = context.Compilation.Assembly.GetAttributes()
            .Where(IsPersistentSchemaAttribute);
        var declared = declarations.Any(attribute =>
            attribute.ConstructorArguments.Length > 0 &&
            attribute.ConstructorArguments[0].Value is int declaredKey && declaredKey == key &&
            (kind == 1 && IsFrameworkAttribute(attribute, "PersistentInt32Attribute") ||
             kind == 2 && IsFrameworkAttribute(attribute, "PersistentBytesAttribute")));
        if (!declared)
            Report(context, PersistentAccess, operation.Arguments[0].Syntax.GetLocation(),
                $"Persistent storage key {key} is not declared with the required value kind");
    }

    private static bool IsAssemblyAttribute(AttributeData attribute) =>
        IsFrameworkAttribute(attribute, "CardAssemblyAttribute");

    private static bool IsLifecycleName(string name) =>
        name is "Install" or "Select" or "Deselect" or "Process" or "Uninstall";

    private static bool IsLifecycleMethod(IMethodSymbol method) =>
        IsLifecycleName(method.Name) && method.ContainingType.GetAttributes().Any(IsAssemblyAttribute);

    private static bool IsFrameworkAttribute(AttributeData attribute, string name) =>
        attribute.AttributeClass?.Name == name &&
        attribute.AttributeClass.ContainingAssembly?.Name == "MicroCard.Framework" &&
        attribute.AttributeClass.ContainingNamespace?.ToDisplayString() == "MicroCard.Framework";

    private static bool IsDependencyExportAttribute(AttributeData attribute) =>
        IsFrameworkAttribute(attribute, "DependencyExportAttribute");

    private static bool IsDependencyAttribute(AttributeData attribute) =>
        IsFrameworkAttribute(attribute, "DependencyAttribute");

    private static bool IsPersistentSchemaAttribute(AttributeData attribute) =>
        IsFrameworkAttribute(attribute, "PersistentInt32Attribute") ||
        IsFrameworkAttribute(attribute, "PersistentBytesAttribute");

    private static void AnalyzeExportPolicy(CompilationAnalysisContext context)
    {
        var attribute = context.Compilation.Assembly.GetAttributes()
            .FirstOrDefault(IsDependencyExportAttribute);
        if (attribute is null)
            return;
        var location = attribute.ApplicationSyntaxReference?.GetSyntax(context.CancellationToken).GetLocation()
            ?? Location.None;
        if (attribute.ConstructorArguments.Length != 1)
        {
            context.ReportDiagnostic(Diagnostic.Create(ExportPolicy, location,
                "Dependency export policy requires exactly one policy or public-key argument"));
            return;
        }
        var argument = attribute.ConstructorArguments[0];
        if (argument.Kind == TypedConstantKind.Enum && argument.Value is int policy && policy is 1 or 2)
            return;
        if (argument.Value is string key && key.Length == 64 && key.All(Uri.IsHexDigit))
            return;
        context.ReportDiagnostic(Diagnostic.Create(ExportPolicy, location,
            "SpecificPublicKey requires exactly 32 bytes of hexadecimal; other policies take Any or SameSigner"));
    }

    private static void AnalyzeDependencies(CompilationAnalysisContext context)
    {
        var types = AllTypes(context.Compilation.Assembly.GlobalNamespace).ToArray();
        int typeRows = types.Length + 1;
        if (typeRows > 253)
        {
            var location = types[252].Locations.FirstOrDefault(static item => item.IsInSource)
                ?? Location.None;
            context.ReportDiagnostic(Diagnostic.Create(TypeRowLimit, location, typeRows));
        }
        var fields = types.SelectMany(type => type.GetMembers().OfType<IFieldSymbol>())
            .Where(static field => !field.IsConst)
            .ToArray();
        if (fields.Length > 1022)
        {
            var location = fields[1022].Locations.FirstOrDefault(static item => item.IsInSource)
                ?? fields[1022].ContainingType.Locations.FirstOrDefault(static item => item.IsInSource)
                ?? Location.None;
            context.ReportDiagnostic(Diagnostic.Create(FieldRowLimit, location, fields.Length));
        }
        var methods = types
            .SelectMany(type => type.GetMembers().OfType<IMethodSymbol>())
            .ToArray();
        if (methods.Length > 256)
        {
            var location = methods[256].Locations.FirstOrDefault(static item => item.IsInSource)
                ?? methods[256].ContainingType.Locations.FirstOrDefault(static item => item.IsInSource)
                ?? Location.None;
            context.ReportDiagnostic(Diagnostic.Create(MethodRowLimit, location, methods.Length));
        }
        var entries = types
            .SelectMany(type => type.GetAttributes().Where(IsAssemblyAttribute))
            .ToArray();
        if (entries.Length > 4)
        {
            var location = entries[4].ApplicationSyntaxReference?
                .GetSyntax(context.CancellationToken).GetLocation() ?? Location.None;
            context.ReportDiagnostic(Diagnostic.Create(EntryPointLimit, location, entries.Length));
        }
        var identityAttributes = context.Compilation.Assembly.GetAttributes()
            .Where(attribute => IsFrameworkAttribute(attribute, "DeviceAssemblyIdentityAttribute"))
            .ToArray();
        if (identityAttributes.Length > 1)
            context.ReportDiagnostic(Diagnostic.Create(DependencyPolicy, Location.None,
                "Only one device assembly identity may be declared"));
        if (identityAttributes.Length == 0 &&
            (!EmbeddedIdentifier.IsValid(context.Compilation.AssemblyName) ||
             context.Compilation.AssemblyName is "MicroCard.Framework" or "System.Runtime"))
            context.ReportDiagnostic(Diagnostic.Create(DependencyPolicy, Location.None,
                "Assembly identity must use the embedded identifier grammar and cannot use a reserved platform identity"));
        foreach (var identity in identityAttributes)
        {
            var location = identity.ApplicationSyntaxReference?.GetSyntax(context.CancellationToken).GetLocation()
                ?? Location.None;
            if (identity.ConstructorArguments.Length != 1 ||
                identity.ConstructorArguments[0].Value is not string name || !EmbeddedIdentifier.IsValid(name) ||
                name is "MicroCard.Framework" or "System.Runtime")
                context.ReportDiagnostic(Diagnostic.Create(DependencyPolicy, location,
                    "Device assembly identity must use the embedded identifier grammar and cannot use a reserved platform identity"));
        }
        var dependencies = context.Compilation.Assembly.GetAttributes()
            .Where(IsDependencyAttribute)
            .ToArray();
        if (dependencies.Length > 16)
        {
            var location = dependencies[16].ApplicationSyntaxReference?
                .GetSyntax(context.CancellationToken).GetLocation() ?? Location.None;
            context.ReportDiagnostic(Diagnostic.Create(DependencyLimit, location, dependencies.Length));
        }
        var names = new HashSet<string>(StringComparer.Ordinal);
        var referenceNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (var attribute in dependencies)
        {
            var location = attribute.ApplicationSyntaxReference?.GetSyntax(context.CancellationToken).GetLocation()
                ?? Location.None;
            if (attribute.ConstructorArguments.Length != 2 ||
                attribute.ConstructorArguments[0].Value is not string assembly ||
                !EmbeddedIdentifier.IsValid(assembly) || assembly == context.Compilation.AssemblyName ||
                assembly is "MicroCard.Framework" or "System.Runtime" ||
                !names.Add(assembly) ||
                attribute.ConstructorArguments[1].Value is not string version ||
                !VersionConstraint.IsValid(version))
            {
                context.ReportDiagnostic(Diagnostic.Create(DependencyPolicy, location,
                    "Dependency requires a unique assembly name and a valid bounded version constraint"));
                continue;
            }
            var referenceName = attribute.NamedArguments
                .FirstOrDefault(argument => argument.Key == "ReferenceAssembly").Value.Value as string ?? assembly;
            if (referenceName.Length is < 1 or > 64 || referenceName == context.Compilation.AssemblyName ||
                referenceName is "MicroCard.Framework" or "System.Runtime" ||
                !referenceNames.Add(referenceName))
                context.ReportDiagnostic(Diagnostic.Create(DependencyPolicy, location,
                    $"Dependency '{assembly}' requires a unique reference assembly name of 1 to 64 characters"));
            foreach (var argument in attribute.NamedArguments)
            {
                if (argument.Key == "PackageDigestHex" &&
                    argument.Value.Value is string digest && !IsHex32(digest))
                    context.ReportDiagnostic(Diagnostic.Create(DependencyPolicy, location,
                        $"Dependency '{assembly}' package digest must be exactly 32 bytes of hexadecimal"));
                if (argument.Key == "SignerPublicKeyHex" &&
                    argument.Value.Value is string signer && !IsHex32(signer))
                    context.ReportDiagnostic(Diagnostic.Create(DependencyPolicy, location,
                        $"Dependency '{assembly}' signer must be exactly 32 bytes of hexadecimal"));
                if (argument.Key == "Scope" &&
                    (argument.Value.Value is not int scope || scope is < 0 or > 2))
                    context.ReportDiagnostic(Diagnostic.Create(DependencyPolicy, location,
                        $"Dependency '{assembly}' has an invalid resolution scope"));
            }
        }
        var storage = context.Compilation.Assembly.GetAttributes()
            .Where(IsPersistentSchemaAttribute)
            .ToArray();
        if (storage.Length > 64)
        {
            var location = storage[64].ApplicationSyntaxReference?
                .GetSyntax(context.CancellationToken).GetLocation() ?? Location.None;
            context.ReportDiagnostic(Diagnostic.Create(PersistentSchema, location,
                $"Assembly declares {storage.Length} persistent keys; the limit is 64"));
        }
        var storageKeys = new HashSet<int>();
        foreach (var attribute in storage)
        {
            var location = attribute.ApplicationSyntaxReference?.GetSyntax(context.CancellationToken).GetLocation()
                ?? Location.None;
            if (attribute.ConstructorArguments.Length == 0 ||
                attribute.ConstructorArguments[0].Value is not int key || key < 0)
            {
                context.ReportDiagnostic(Diagnostic.Create(PersistentSchema, location,
                    "Persistent storage keys must be non-negative Int32 constants"));
                continue;
            }
            if (!storageKeys.Add(key))
                context.ReportDiagnostic(Diagnostic.Create(PersistentSchema, location,
                    $"Persistent storage key {key} is declared more than once"));
            if (IsFrameworkAttribute(attribute, "PersistentBytesAttribute") &&
                (attribute.ConstructorArguments.Length != 2 ||
                 attribute.ConstructorArguments[1].Value is not int maxLength ||
                 maxLength is < 1 or > 2048))
                context.ReportDiagnostic(Diagnostic.Create(PersistentSchema, location,
                    $"Persistent byte key {key} requires a maximum length from 1 through 2048"));
        }
    }

    private static IEnumerable<INamedTypeSymbol> AllTypes(INamespaceSymbol scope)
    {
        foreach (var type in scope.GetTypeMembers())
            yield return type;
        foreach (var child in scope.GetNamespaceMembers())
            foreach (var type in AllTypes(child))
                yield return type;
    }

    private static bool ValidAid(string aid) => aid.Length is >= 10 and <= 32 &&
        (aid.Length & 1) == 0 && aid.All(Uri.IsHexDigit);

    private static bool IsHex32(string value) => value.Length == 64 && value.All(Uri.IsHexDigit);
}

