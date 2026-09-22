using System;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;
using MicroCard.Build;

namespace MicroCard.Analyzers;

public sealed partial class MicroCardProfileAnalyzer
{
    private static void AnalyzeUnsupportedSyntax(SyntaxNodeAnalysisContext context) =>
        context.ReportDiagnostic(Diagnostic.Create(LanguageFeature, context.Node.GetLocation(),
            context.Node.Kind().ToString()));

    private static void AnalyzeType(SymbolAnalysisContext context)
    {
        var type = (INamedTypeSymbol)context.Symbol;
        if (type.IsImplicitlyDeclared || !type.Locations.Any(static location => location.IsInSource))
            return;
        var location = type.Locations.First(static item => item.IsInSource);
        if (type.TypeKind != TypeKind.Class)
            Report(context, ShapeRule, location, $"Type '{type.Name}' must be a class");
        if (!type.IsSealed && !type.IsStatic)
            Report(context, ShapeRule, location, $"Type '{type.Name}' must be sealed or static");
        if (type.Arity != 0)
            Report(context, ShapeRule, location, $"Generic type '{type.Name}' is unsupported");
        if (type.ContainingType is not null)
            Report(context, ShapeRule, location, $"Nested type '{type.Name}' is unsupported");
        if (type.Interfaces.Length != 0)
            Report(context, ShapeRule, location, $"Type '{type.Name}' cannot implement interfaces");
        if (type.BaseType is { SpecialType: not SpecialType.System_Object })
            Report(context, ShapeRule, location, $"Type '{type.Name}' cannot inherit from '{type.BaseType}'");

        var entry = type.GetAttributes().FirstOrDefault(IsAssemblyAttribute);
        var hooks = type.GetMembers().OfType<IMethodSymbol>()
            .Where(method => IsLifecycleName(method.Name))
            .ToArray();
        if (entry is null)
            return;

        if (entry.ConstructorArguments.Length != 1 ||
            entry.ConstructorArguments[0].Value is not string aid || !ValidAid(aid))
            Report(context, Lifecycle, location, "Assembly AID must be 5 to 16 bytes of hexadecimal");
        foreach (var group in hooks.GroupBy(static hook => hook.Name, StringComparer.Ordinal))
            if (group.Count() != 1)
                Report(context, Lifecycle, location,
                    $"Assembly '{type.Name}' has more than one '{group.Key}' method");
        if (!hooks.Any(static hook => hook.Name == "Process"))
            Report(context, Lifecycle, location, $"Assembly '{type.Name}' requires a Process method");
    }

    private static void AnalyzeMethod(SymbolAnalysisContext context)
    {
        var method = (IMethodSymbol)context.Symbol;
        if (method.IsImplicitlyDeclared || !method.Locations.Any(static location => location.IsInSource))
            return;
        var location = method.Locations.First(static item => item.IsInSource);
        if (method.IsAsync)
            Report(context, LanguageFeature, location, "async method");
        if (method.MethodKind == MethodKind.StaticConstructor)
            Report(context, ShapeRule, location, "Static constructors are unsupported");
        if (method.Arity != 0)
            Report(context, ShapeRule, location, $"Generic method '{method.Name}' is unsupported");
        if (method.IsAbstract || method.IsVirtual || method.IsOverride || method.IsExtern)
            Report(context, ShapeRule, location, $"Method '{method.Name}' must use direct, managed dispatch");
        if (method.MethodImplementationFlags != System.Reflection.MethodImplAttributes.IL)
            Report(context, ShapeRule, location, $"Method '{method.Name}' has unsupported implementation flags");
        if (method.ReturnsByRef || method.ReturnsByRefReadonly)
            Report(context, ShapeRule, location, $"Method '{method.Name}' cannot return by reference");
        if (method.Parameters.Length > 32)
            context.ReportDiagnostic(Diagnostic.Create(ParameterLimit, location,
                method.Name, method.Parameters.Length));
        CheckType(context, method.ReturnType, location);
        foreach (var parameter in method.Parameters)
        {
            CheckType(context, parameter.Type, parameter.Locations.FirstOrDefault() ?? location);
            if (parameter.RefKind != RefKind.None)
                Report(context, ShapeRule, parameter.Locations.FirstOrDefault() ?? location,
                    $"Parameter '{parameter.Name}' cannot be passed by reference");
        }

        if (IsLifecycleMethod(method) &&
            (!method.IsStatic || method.DeclaredAccessibility != Accessibility.Public ||
             method.Parameters.Length != 0 || !method.ReturnsVoid || method.Arity != 0))
            Report(context, Lifecycle, location,
                $"Lifecycle method '{method.Name}' must be public static parameterless void");
    }

    private static void AnalyzeField(SymbolAnalysisContext context)
    {
        var field = (IFieldSymbol)context.Symbol;
        if (field.IsImplicitlyDeclared || !field.Locations.Any(static location => location.IsInSource))
            return;
        var location = field.Locations.First(static item => item.IsInSource);
        if (field.IsConst && (field.Type.SpecialType == SpecialType.System_Int32 ||
            field.Type.TypeKind == TypeKind.Enum))
            return;
        if (field.IsStatic || field.Type.SpecialType != SpecialType.System_Int32)
            Report(context, ShapeRule, location,
                $"Field '{field.Name}' must be an instance Int32 field or an Int32 constant");
    }

    private static void AnalyzePropertySymbol(SymbolAnalysisContext context)
    {
        var property = (IPropertySymbol)context.Symbol;
        if (property.IsImplicitlyDeclared || !property.Locations.Any(static location => location.IsInSource))
            return;
        CheckType(context, property.Type, property.Locations.First(static item => item.IsInSource));
        if (property.IsIndexer)
            Report(context, ShapeRule, property.Locations[0], "Indexers are unsupported");
        bool autoProperty = property.DeclaringSyntaxReferences
            .Select(reference => reference.GetSyntax(context.CancellationToken))
            .OfType<PropertyDeclarationSyntax>()
            .Any(static declaration => declaration.AccessorList?.Accessors.All(
                static accessor => accessor.Body is null && accessor.ExpressionBody is null) == true);
        if (autoProperty &&
            (property.IsStatic || property.Type.SpecialType != SpecialType.System_Int32))
            Report(context, ShapeRule, property.Locations[0],
                $"Auto-property '{property.Name}' requires an unsupported backing field; only instance Int32 storage is available");
    }

    private static void AnalyzeEvent(SymbolAnalysisContext context)
    {
        var eventSymbol = (IEventSymbol)context.Symbol;
        if (eventSymbol.IsImplicitlyDeclared ||
            !eventSymbol.Locations.Any(static location => location.IsInSource))
            return;
        Report(context, ShapeRule,
            eventSymbol.Locations.First(static location => location.IsInSource),
            $"Event '{eventSymbol.Name}' is unsupported");
    }

    private static void AnalyzeObjectCreation(OperationAnalysisContext context)
    {
        var operation = (IObjectCreationOperation)context.Operation;
        if (operation.Syntax is AttributeSyntax)
            return;
        if (operation.Type is INamedTypeSymbol transactionScope && IsTransactionScope(transactionScope))
        {
            bool canonical = operation.Constructor is { Parameters.Length: 0 } &&
                operation.Syntax.FirstAncestorOrSelf<LocalDeclarationStatementSyntax>() is
                    { UsingKeyword.RawKind: not 0, Declaration.Variables.Count: 1 } declaration &&
                declaration.Declaration.Variables[0].Initializer?.Value == operation.Syntax;
            if (!canonical)
                Report(context, ShapeRule, operation.Syntax.GetLocation(),
                    "TransactionScope must be a parameterless using declaration");
            return;
        }
        if (operation.Type is not null && !IsSupportedType(operation.Type, context.Compilation))
            Report(context, TypeRule, operation.Syntax.GetLocation(), operation.Type.ToDisplayString());
        ReportRepeatedAllocation(context, operation);
    }

    private static void AnalyzeVariable(OperationAnalysisContext context)
    {
        var operation = (IVariableDeclaratorOperation)context.Operation;
        if (operation.Symbol is ILocalSymbol local && !IsSupportedType(local.Type, context.Compilation))
            Report(context, TypeRule, operation.Syntax.GetLocation(), local.Type.ToDisplayString());
    }

    private static void AnalyzeProperty(OperationAnalysisContext context)
    {
        var operation = (IPropertyReferenceOperation)context.Operation;
        if (operation.Property.Name == "Length" && operation.Instance?.Type is IArrayTypeSymbol)
            return;
        if (IsAmbientTransactionProperty(operation.Property))
        {
            if (operation.Parent is IAssignmentOperation assignment &&
                ReferenceEquals(assignment.Target, operation))
                Report(context, ExternalCall, operation.Syntax.GetLocation(), operation.Property.ToDisplayString());
            return;
        }
        if (!AllowedMember(operation.Property, context.Compilation))
            Report(context, ExternalCall, operation.Syntax.GetLocation(), operation.Property.ToDisplayString());
    }

    private static void AnalyzeFieldUse(OperationAnalysisContext context)
    {
        var operation = (IFieldReferenceOperation)context.Operation;
        if (operation.Field.HasConstantValue ||
            SymbolEqualityComparer.Default.Equals(operation.Field.ContainingAssembly, context.Compilation.Assembly))
            return;
        Report(context, ExternalCall, operation.Syntax.GetLocation(), operation.Field.ToDisplayString());
    }

    private static bool AllowedMember(ISymbol member, Compilation compilation)
    {
        if (SymbolEqualityComparer.Default.Equals(member.ContainingAssembly, compilation.Assembly))
            return true;
        if (member.ContainingAssembly?.Name == Mc04Abi.FrameworkAssembly &&
            member.ContainingType?.BaseType is { Name: "Attribute" } baseType &&
            baseType.ContainingNamespace?.ToDisplayString() == "System")
            return true;
        if (IsCatalogMember(member))
            return true;
        if (member is IMethodSymbol transactionMethod && IsExplicitTransactionCall(transactionMethod))
            return true;
        return member.ContainingAssembly is { } provider &&
               provider.GetAttributes().Any(IsDependencyExportAttribute) &&
               compilation.Assembly.GetAttributes().Any(attribute =>
                   IsDependencyAttribute(attribute) &&
                   attribute.ConstructorArguments.Length > 0 &&
                   ((attribute.NamedArguments.FirstOrDefault(argument => argument.Key == "ReferenceAssembly").Value.Value as string)
                    ?? (attribute.ConstructorArguments[0].Value as string)) == provider.Name);
    }

    private static bool IsCatalogMember(ISymbol symbol)
    {
        var method = symbol switch
        {
            IMethodSymbol value => value,
            IPropertySymbol { GetMethod: { } getter } => getter,
            _ => null,
        };
        if (method is null || method.ContainingAssembly?.Name is not { } assembly ||
            method.ContainingNamespace?.ToDisplayString() is not { } ns)
            return false;
        var parameters = method.Parameters.Select(static parameter => AbiType(parameter.Type)).ToArray();
        return parameters.All(static parameter => parameter is not null) &&
            AbiType(method.ReturnType) is { } result &&
            Mc04Abi.Find(assembly, ns, method.ContainingType.Name, method.MetadataName,
                !method.IsStatic, parameters!, result) is not null;
    }

    private static string? AbiType(ITypeSymbol type)
    {
        if (type.SpecialType == SpecialType.System_Void) return "void";
        if (type.SpecialType == SpecialType.System_Boolean) return "bool";
        if (type.SpecialType == SpecialType.System_Int32) return "int32";
        if (type is IArrayTypeSymbol { IsSZArray: true, ElementType.SpecialType: SpecialType.System_Byte })
            return "byte[]";
        if (type is IArrayTypeSymbol { IsSZArray: true, ElementType.SpecialType: SpecialType.System_Int32 })
            return "int32[]";
        if (type is INamedTypeSymbol { Arity: 0 } named)
        {
            var prefix = named.TypeKind == TypeKind.Enum ? "enum:" : "ref:";
            return prefix + named.ContainingNamespace.ToDisplayString() + "." + named.Name;
        }
        return null;
    }

    private static void CheckType(SymbolAnalysisContext context, ITypeSymbol type, Location location)
    {
        if (!IsSupportedType(type, context.Compilation))
            Report(context, TypeRule, location, type.ToDisplayString());
    }

    private static bool IsSupportedType(ITypeSymbol type, Compilation compilation)
    {
        if (type.SpecialType is SpecialType.System_Void or SpecialType.System_Boolean or
            SpecialType.System_SByte or SpecialType.System_Byte or SpecialType.System_Int16 or
            SpecialType.System_UInt16 or SpecialType.System_Int32 or SpecialType.System_UInt32)
            return true;
        if (type is IArrayTypeSymbol array)
            return array.IsSZArray && array.ElementType.SpecialType is
                SpecialType.System_Byte or SpecialType.System_Int32;
        if (type is not INamedTypeSymbol named || named.Arity != 0)
            return false;
        if (named.ContainingAssembly?.Name == "MicroCard.Framework" &&
            named.ContainingNamespace?.ToDisplayString() == "MicroCard.Framework" &&
            named.Name is "AssemblyContext" or "CommandService" or "ResponseService" or
                "StorageService" or "KeyService" or "RandomService" or "SecureChannelService" or
                "CredentialService" or "RuntimeService" or "KeyHandle" or "StorageId" or
                "KeySlot" or "CredentialSlot" or "KeyAlgorithm" or "StatusWord" or "SecurityLevel")
            return true;
        if (IsTransactionScope(named))
            return true;
        if (IsTransactionType(named))
            return true;
        return SymbolEqualityComparer.Default.Equals(named.ContainingAssembly, compilation.Assembly) &&
               named.TypeKind == TypeKind.Class && named.IsSealed;
    }
}
