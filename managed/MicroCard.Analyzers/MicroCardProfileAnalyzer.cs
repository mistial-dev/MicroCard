using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;
using MicroCard.Build;

namespace MicroCard.Analyzers;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class MicroCardProfileAnalyzer : DiagnosticAnalyzer
{
    private readonly struct CallSite
    {
        public CallSite(IMethodSymbol target, Location location)
        {
            Target = target;
            Location = location;
        }

        public IMethodSymbol Target { get; }
        public Location Location { get; }
    }

    private readonly struct AllocationSite
    {
        public AllocationSite(long bytes, Location location)
        {
            Bytes = bytes;
            Location = location;
        }

        public long Bytes { get; }
        public Location Location { get; }
    }

    private const string Category = "MicroCard";
    private static readonly DiagnosticDescriptor LanguageFeature = Rule(
        "MCA0001", "Language feature is outside the MicroCard profile",
        "'{0}' is outside the MicroCard execution profile");
    private static readonly DiagnosticDescriptor TypeRule = Rule(
        "MCA0002", "Type is outside the MicroCard profile",
        "Type '{0}' is outside the MicroCard execution profile");
    private static readonly DiagnosticDescriptor ShapeRule = Rule(
        "MCA0003", "Declaration cannot be lowered by MicroCard",
        "{0}");
    private static readonly DiagnosticDescriptor ExternalCall = Rule(
        "MCA0004", "Call is outside the trusted MicroCard ABI",
        "Call to '{0}' is outside the trusted MicroCard framework ABI");
    private static readonly DiagnosticDescriptor Lifecycle = Rule(
        "MCA0005", "Invalid assembly lifecycle declaration",
        "{0}");
    private static readonly DiagnosticDescriptor ExportPolicy = Rule(
        "MCA0006", "Invalid dependency export policy",
        "{0}");
    private static readonly DiagnosticDescriptor DependencyPolicy = Rule(
        "MCA0007", "Invalid dependency declaration",
        "{0}");
    private static readonly DiagnosticDescriptor TransactionSafety = Rule(
        "MCA0008", "Call cannot participate in a transaction",
        "Method '{0}' can execute in a transaction and cannot call irreversible operation '{1}'");
    private static readonly DiagnosticDescriptor CallGraph = Rule(
        "MCA0009", "Call graph exceeds the MicroCard frame profile",
        "{0}");
    private static readonly DiagnosticDescriptor LocalLimit = Rule(
        "MCA0010", "Method exceeds the MicroCard locals profile",
        "Method '{0}' declares {1} locals; the MicroCard limit is 64");
    private static readonly DiagnosticDescriptor AllocationLimit = Rule(
        "MCA0011", "Allocation cannot fit the MicroCard arena",
        "Array allocation requires {0} bytes; the MicroCard transient arena is 16384 bytes");
    private static readonly DiagnosticDescriptor RepeatedAllocation = Rule(
        "MCA0012", "Repeated allocation can exhaust the MicroCard arena",
        "Allocation inside a loop can repeatedly consume the 16384-byte transient arena");
    private static readonly DiagnosticDescriptor AggregateAllocation = Rule(
        "MCA0013", "Method allocations cannot fit the MicroCard arena",
        "Method '{0}' has {1} bytes of unconditional, statically sized allocations; the MicroCard transient arena is 16384 bytes");
    private static readonly DiagnosticDescriptor CallAllocation = Rule(
        "MCA0014", "Managed call path cannot fit the MicroCard arena",
        "Method '{0}' and its unconditional managed calls require at least {1} bytes of statically sized allocations; the MicroCard transient arena is 16384 bytes");
    private static readonly DiagnosticDescriptor SwitchLimit = Rule(
        "MCA0015", "Switch exceeds the MicroCard profile",
        "Switch has {0} targets; the MicroCard limit is 256");
    private static readonly DiagnosticDescriptor ObjectLimit = Rule(
        "MCA0016", "Managed call path exceeds the MicroCard object profile",
        "Method '{0}' and its unconditional managed calls allocate at least {1} transient objects; the MicroCard limit is 256");
    private static readonly DiagnosticDescriptor ParameterLimit = Rule(
        "MCA0017", "Method exceeds the MicroCard parameter profile",
        "Method '{0}' declares {1} parameters; the MicroCard limit is 32");
    private static readonly DiagnosticDescriptor DependencyLimit = Rule(
        "MCA0018", "Assembly exceeds the MicroCard dependency profile",
        "Assembly declares {0} dependencies; the MicroCard limit is 16");
    private static readonly DiagnosticDescriptor EntryPointLimit = Rule(
        "MCA0019", "Assembly exceeds the MicroCard entry-point profile",
        "Assembly declares {0} entry points; the MicroCard limit is 4");
    private static readonly DiagnosticDescriptor MethodRowLimit = Rule(
        "MCA0020", "Assembly exceeds the MC04 method table profile",
        "Assembly emits {0} methods; the MC04 limit is 256");
    private static readonly DiagnosticDescriptor TypeRowLimit = Rule(
        "MCA0021", "Assembly exceeds the MC04 type table profile",
        "Assembly emits {0} type definitions including the module row; the MC04 limit is 253");
    private static readonly DiagnosticDescriptor FieldRowLimit = Rule(
        "MCA0022", "Assembly exceeds the MC04 field table profile",
        "Assembly emits {0} fields; the MC04 limit is 1022");
    private static readonly DiagnosticDescriptor PersistentSchema = Rule(
        "MCA0024", "Invalid persistent storage declaration",
        "{0}");
    private static readonly DiagnosticDescriptor PersistentAccess = Rule(
        "MCA0025", "Persistent storage access is outside the signed schema",
        "{0}");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
        ImmutableArray.Create(LanguageFeature, TypeRule, ShapeRule, ExternalCall, Lifecycle,
            ExportPolicy, DependencyPolicy, TransactionSafety, CallGraph, LocalLimit,
            AllocationLimit, RepeatedAllocation, AggregateAllocation, CallAllocation,
            SwitchLimit, ObjectLimit, ParameterLimit, DependencyLimit, EntryPointLimit,
            MethodRowLimit, TypeRowLimit, FieldRowLimit, PersistentSchema,
            PersistentAccess);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSyntaxNodeAction(AnalyzeUnsupportedSyntax,
            SyntaxKind.AwaitExpression,
            SyntaxKind.YieldReturnStatement,
            SyntaxKind.YieldBreakStatement,
            SyntaxKind.LockStatement,
            SyntaxKind.UnsafeStatement,
            SyntaxKind.FixedStatement,
            SyntaxKind.StackAllocArrayCreationExpression,
            SyntaxKind.ImplicitStackAllocArrayCreationExpression,
            SyntaxKind.PointerType,
            SyntaxKind.FunctionPointerType,
            SyntaxKind.TryStatement,
            SyntaxKind.ThrowStatement,
            SyntaxKind.ThrowExpression,
            SyntaxKind.TypeOfExpression,
            SyntaxKind.InitAccessorDeclaration,
            SyntaxKind.UsingStatement,
            SyntaxKind.SimpleLambdaExpression,
            SyntaxKind.ParenthesizedLambdaExpression,
            SyntaxKind.AnonymousMethodExpression,
            SyntaxKind.LocalFunctionStatement);
        context.RegisterSyntaxNodeAction(AnalyzeLocalCount,
            SyntaxKind.MethodDeclaration,
            SyntaxKind.ConstructorDeclaration);
        context.RegisterSyntaxNodeAction(AnalyzeLocalDeclaration,
            SyntaxKind.LocalDeclarationStatement);
        context.RegisterSyntaxNodeAction(AnalyzeSwitch,
            SyntaxKind.SwitchStatement,
            SyntaxKind.SwitchExpression);
        context.RegisterSymbolAction(AnalyzeType, SymbolKind.NamedType);
        context.RegisterSymbolAction(AnalyzeMethod, SymbolKind.Method);
        context.RegisterSymbolAction(AnalyzeField, SymbolKind.Field);
        context.RegisterSymbolAction(AnalyzePropertySymbol, SymbolKind.Property);
        context.RegisterSymbolAction(AnalyzeEvent, SymbolKind.Event);
        context.RegisterOperationAction(AnalyzeInvocation, OperationKind.Invocation);
        context.RegisterOperationAction(AnalyzeObjectCreation, OperationKind.ObjectCreation);
        context.RegisterOperationAction(AnalyzeArrayCreation, OperationKind.ArrayCreation);
        context.RegisterOperationAction(AnalyzeCollectionExpression, OperationKind.CollectionExpression);
        context.RegisterOperationAction(AnalyzeVariable, OperationKind.VariableDeclarator);
        context.RegisterOperationAction(AnalyzeProperty, OperationKind.PropertyReference);
        context.RegisterOperationAction(AnalyzeFieldUse, OperationKind.FieldReference);
        context.RegisterCompilationAction(AnalyzeExportPolicy);
        context.RegisterCompilationAction(AnalyzeDependencies);
        context.RegisterCompilationStartAction(startContext =>
        {
            var calls = new ConcurrentDictionary<ISymbol, ConcurrentBag<CallSite>>(
                SymbolEqualityComparer.Default);
            var allocations = new ConcurrentDictionary<ISymbol, ConcurrentBag<AllocationSite>>(
                SymbolEqualityComparer.Default);
            var allocationCalls = new ConcurrentDictionary<ISymbol, ConcurrentBag<CallSite>>(
                SymbolEqualityComparer.Default);
            startContext.RegisterOperationAction(operationContext =>
            {
                if (operationContext.ContainingSymbol is IMethodSymbol method &&
                    operationContext.Operation is IInvocationOperation invocation)
                    calls.GetOrAdd(method, static _ => new ConcurrentBag<CallSite>())
                        .Add(new CallSite(invocation.TargetMethod, invocation.Syntax.GetLocation()));
            }, OperationKind.Invocation);
            startContext.RegisterOperationAction(operationContext =>
            {
                if (operationContext.ContainingSymbol is IMethodSymbol method &&
                    operationContext.Operation is IObjectCreationOperation creation &&
                    creation.Constructor is { } constructor)
                    calls.GetOrAdd(method, static _ => new ConcurrentBag<CallSite>())
                        .Add(new CallSite(constructor, creation.Syntax.GetLocation()));
            }, OperationKind.ObjectCreation);
            startContext.RegisterOperationAction(operationContext =>
                RecordStaticAllocation(operationContext, allocations),
                OperationKind.ArrayCreation, OperationKind.CollectionExpression,
                OperationKind.ObjectCreation);
            startContext.RegisterOperationAction(operationContext =>
                RecordAllocationCall(operationContext, allocationCalls),
                OperationKind.Invocation, OperationKind.ObjectCreation);
            startContext.RegisterCompilationEndAction(endContext =>
            {
                AnalyzeTransactions(endContext, calls);
                AnalyzeCallGraphs(endContext, calls);
                AnalyzeStaticAllocationTotals(endContext, allocations);
                AnalyzeCallAllocationTotals(endContext, allocations, allocationCalls);
            });
        });
    }

    private static void AnalyzeSwitch(SyntaxNodeAnalysisContext context)
    {
        int targets = context.Node switch
        {
            SwitchStatementSyntax statement => statement.Sections.Sum(
                static section => section.Labels.Count(
                    static label => label is not DefaultSwitchLabelSyntax)),
            SwitchExpressionSyntax expression => expression.Arms.Count(
                static arm => arm.Pattern is not DiscardPatternSyntax),
            _ => 0,
        };
        if (targets > 256)
            context.ReportDiagnostic(Diagnostic.Create(
                SwitchLimit, context.Node.GetLocation(), targets));
    }

    private static void AnalyzeLocalCount(SyntaxNodeAnalysisContext context)
    {
        var declaration = (BaseMethodDeclarationSyntax)context.Node;
        int count = declaration.DescendantNodes().OfType<VariableDeclaratorSyntax>().Count();
        if (count > 64)
            context.ReportDiagnostic(Diagnostic.Create(LocalLimit,
                declaration.GetLocation(), declaration switch
                {
                    MethodDeclarationSyntax method => method.Identifier.ValueText,
                    ConstructorDeclarationSyntax constructor => constructor.Identifier.ValueText,
                    _ => "method"
                }, count));
    }

    private static void AnalyzeLocalDeclaration(SyntaxNodeAnalysisContext context)
    {
        var declaration = (LocalDeclarationStatementSyntax)context.Node;
        if (declaration.UsingKeyword != default && !IsTransactionScopeDeclaration(context, declaration))
            context.ReportDiagnostic(Diagnostic.Create(LanguageFeature,
                declaration.UsingKeyword.GetLocation(), "using declaration"));
    }

    private static bool IsTransactionScopeDeclaration(
        SyntaxNodeAnalysisContext context,
        LocalDeclarationStatementSyntax declaration)
    {
        if (declaration.Declaration.Variables.Count != 1 ||
            declaration.Declaration.Variables[0].Initializer?.Value is not ObjectCreationExpressionSyntax creation)
            return false;
        var symbol = context.SemanticModel.GetSymbolInfo(creation, context.CancellationToken).Symbol;
        return symbol is IMethodSymbol { MethodKind: MethodKind.Constructor, Parameters.Length: 0 } constructor &&
               IsTransactionScope(constructor.ContainingType);
    }

    private static DiagnosticDescriptor Rule(string id, string title, string message) =>
        new(id, title, message, Category, DiagnosticSeverity.Error, isEnabledByDefault: true,
            description: "Reported before IL preprocessing; device verification remains authoritative.");

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
            .SelectMany(method => method.GetAttributes()
                .Where(IsLifecycleAttribute)
                .Select(attribute => (Method: method, Name: attribute.AttributeClass!.Name)))
            .ToArray();
        if (entry is null)
        {
            foreach (var hook in hooks)
                Report(context, Lifecycle, hook.Method.Locations[0],
                    $"[{TrimAttribute(hook.Name)}] requires [Assembly] on '{type.Name}'");
            return;
        }

        if (entry.ConstructorArguments.Length != 1 ||
            entry.ConstructorArguments[0].Value is not string aid || !ValidAid(aid))
            Report(context, Lifecycle, location, "Assembly AID must be 5 to 16 bytes of hexadecimal");
        foreach (var group in hooks.GroupBy(static hook => hook.Name, StringComparer.Ordinal))
            if (group.Count() != 1)
                Report(context, Lifecycle, location,
                    $"Assembly '{type.Name}' has more than one [{TrimAttribute(group.Key)}] method");
        if (!hooks.Any(static hook => hook.Name == "ProcessAttribute"))
            Report(context, Lifecycle, location, $"Assembly '{type.Name}' requires one [Process] method");
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

        foreach (var attribute in method.GetAttributes().Where(IsLifecycleAttribute))
            if (!method.IsStatic || method.Parameters.Length != 0 || !method.ReturnsVoid || method.Arity != 0)
                Report(context, Lifecycle, location,
                    $"[{TrimAttribute(attribute.AttributeClass!.Name)}] method '{method.Name}' must be static parameterless void");
    }

    private static void AnalyzeField(SymbolAnalysisContext context)
    {
        var field = (IFieldSymbol)context.Symbol;
        if (field.IsImplicitlyDeclared || !field.Locations.Any(static location => location.IsInSource))
            return;
        var location = field.Locations.First(static item => item.IsInSource);
        if (field.IsConst && field.Type.SpecialType == SpecialType.System_Int32)
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

    private static void AnalyzeArrayCreation(OperationAnalysisContext context)
    {
        var operation = (IArrayCreationOperation)context.Operation;
        if (operation.Type is not null && !IsSupportedType(operation.Type, context.Compilation))
            Report(context, TypeRule, operation.Syntax.GetLocation(), operation.Type.ToDisplayString());
        ReportRepeatedAllocation(context, operation);
        if (operation.Type is not IArrayTypeSymbol { ElementType.SpecialType: var elementType } ||
            operation.DimensionSizes.Length != 1 ||
            operation.DimensionSizes[0].ConstantValue is not { HasValue: true, Value: int count } ||
            count < 0)
            return;
        int elementBytes = ElementBytes(elementType);
        long bytes = ObjectBytes((long)count * elementBytes);
        if (elementBytes != 0 && bytes > 16384)
            Report(context, AllocationLimit, operation.Syntax.GetLocation(), bytes);
    }

    private static void RecordStaticAllocation(OperationAnalysisContext context,
        ConcurrentDictionary<ISymbol, ConcurrentBag<AllocationSite>> allocations)
    {
        if (context.ContainingSymbol is not IMethodSymbol method ||
            !IsUnconditionalOperation(context.Operation) ||
            StaticArrayBytes(context.Operation) is not long bytes)
            return;
        allocations.GetOrAdd(method, static _ => new ConcurrentBag<AllocationSite>())
            .Add(new AllocationSite(bytes, context.Operation.Syntax.GetLocation()));
    }

    private static void RecordAllocationCall(OperationAnalysisContext context,
        ConcurrentDictionary<ISymbol, ConcurrentBag<CallSite>> calls)
    {
        if (context.ContainingSymbol is not IMethodSymbol method ||
            !IsUnconditionalOperation(context.Operation))
            return;
        IMethodSymbol? target = context.Operation switch
        {
            IInvocationOperation invocation => invocation.TargetMethod,
            IObjectCreationOperation creation => creation.Constructor,
            _ => null
        };
        if (target is null || !SymbolEqualityComparer.Default.Equals(
                target.ContainingAssembly, context.Compilation.Assembly))
            return;
        calls.GetOrAdd(method, static _ => new ConcurrentBag<CallSite>())
            .Add(new CallSite(target, context.Operation.Syntax.GetLocation()));
    }

    private static long? StaticArrayBytes(IOperation operation)
    {
        if (operation is IObjectCreationOperation { Type: INamedTypeSymbol type })
        {
            long fields = type.GetMembers().OfType<IFieldSymbol>()
                .LongCount(static field => !field.IsStatic);
            return ObjectBytes(fields * 4);
        }
        if (operation.Type is not IArrayTypeSymbol { ElementType.SpecialType: var elementType })
            return null;
        int elementBytes = ElementBytes(elementType);
        if (elementBytes == 0)
            return null;
        int? count = operation switch
        {
            IArrayCreationOperation array when array.DimensionSizes.Length == 1 &&
                array.DimensionSizes[0].ConstantValue is { HasValue: true, Value: int value } &&
                value >= 0 => value,
            ICollectionExpressionOperation collection when
                collection.Elements.All(static element => element is not ISpreadOperation) =>
                collection.Elements.Length,
            _ => null
        };
        return count is int length ? ObjectBytes((long)length * elementBytes) : null;
    }

    // Six-byte header, two-byte handle, and an even-sized payload.
    private static long ObjectBytes(long payload) => 8 + ((payload + 1) & ~1L);

    private static int ElementBytes(SpecialType type) =>
        type == SpecialType.System_Int32 ? 4 : type == SpecialType.System_Byte ? 1 : 0;

    private static bool IsUnconditionalOperation(IOperation operation)
    {
        foreach (var ancestor in operation.Syntax.Ancestors())
        {
            if (ancestor is BaseMethodDeclarationSyntax)
                return true;
            if (ancestor is IfStatementSyntax or SwitchStatementSyntax or SwitchExpressionSyntax or
                ConditionalExpressionSyntax or ForStatementSyntax or ForEachStatementSyntax or
                WhileStatementSyntax or DoStatementSyntax or ConditionalAccessExpressionSyntax ||
                ancestor is BinaryExpressionSyntax binary &&
                (binary.IsKind(SyntaxKind.LogicalAndExpression) ||
                 binary.IsKind(SyntaxKind.LogicalOrExpression) ||
                 binary.IsKind(SyntaxKind.CoalesceExpression)))
                return false;
        }
        return false;
    }

    private static void AnalyzeStaticAllocationTotals(CompilationAnalysisContext context,
        ConcurrentDictionary<ISymbol, ConcurrentBag<AllocationSite>> allocations)
    {
        foreach (var pair in allocations)
        {
            var sites = pair.Value
                .OrderBy(static site => site.Location.SourceSpan.Start)
                .ToArray();
            long total = 0;
            foreach (var site in sites.Where(static site => site.Bytes <= 16384))
            {
                total += site.Bytes;
                if (total <= 16384)
                    continue;
                context.ReportDiagnostic(Diagnostic.Create(AggregateAllocation, site.Location,
                    pair.Key.Name, total));
                break;
            }
            if (sites.Length > 256)
                context.ReportDiagnostic(Diagnostic.Create(ObjectLimit, sites[256].Location,
                    pair.Key.Name, sites.Length));
        }
    }

    private static void AnalyzeCallAllocationTotals(CompilationAnalysisContext context,
        ConcurrentDictionary<ISymbol, ConcurrentBag<AllocationSite>> allocations,
        ConcurrentDictionary<ISymbol, ConcurrentBag<CallSite>> calls)
    {
        var methods = new HashSet<ISymbol>(allocations.Keys, SymbolEqualityComparer.Default);
        methods.UnionWith(calls.Keys);
        var byteMemo = new Dictionary<ISymbol, long>(SymbolEqualityComparer.Default);
        var objectMemo = new Dictionary<ISymbol, long>(SymbolEqualityComparer.Default);
        foreach (var method in methods.OfType<IMethodSymbol>())
        {
            long direct = DirectAllocationBytes(method, allocations);
            var location = method.Locations.FirstOrDefault(static item => item.IsInSource);
            if (direct <= 16384 &&
                TryCallAllocationBytes(method, allocations, calls, byteMemo,
                    new HashSet<ISymbol>(SymbolEqualityComparer.Default), out long total) &&
                total > 16384 && location is not null)
                context.ReportDiagnostic(Diagnostic.Create(CallAllocation, location,
                    method.Name, total));
            long directObjects = DirectAllocationObjects(method, allocations);
            if (directObjects <= 256 &&
                TryCallAllocationObjects(method, allocations, calls, objectMemo,
                    new HashSet<ISymbol>(SymbolEqualityComparer.Default), out long objects) &&
                objects > 256 && location is not null)
                context.ReportDiagnostic(Diagnostic.Create(ObjectLimit, location,
                    method.Name, objects));
        }
    }

    private static long DirectAllocationBytes(ISymbol method,
        ConcurrentDictionary<ISymbol, ConcurrentBag<AllocationSite>> allocations) =>
        allocations.TryGetValue(method, out var sites)
            ? sites.Sum(static site => site.Bytes)
            : 0;

    private static long DirectAllocationObjects(ISymbol method,
        ConcurrentDictionary<ISymbol, ConcurrentBag<AllocationSite>> allocations) =>
        allocations.TryGetValue(method, out var sites) ? sites.Count : 0;

    private static bool TryCallAllocationBytes(ISymbol method,
        ConcurrentDictionary<ISymbol, ConcurrentBag<AllocationSite>> allocations,
        ConcurrentDictionary<ISymbol, ConcurrentBag<CallSite>> calls,
        Dictionary<ISymbol, long> memo, HashSet<ISymbol> active, out long total)
    {
        if (memo.TryGetValue(method, out total))
            return true;
        if (!active.Add(method))
        {
            total = 0;
            return false;
        }
        total = DirectAllocationBytes(method, allocations);
        if (total > 16384 || !calls.TryGetValue(method, out var sites))
        {
            active.Remove(method);
            if (total <= 16384)
                memo[method] = total;
            return total <= 16384;
        }
        foreach (var site in sites.OrderBy(static site => site.Location.SourceSpan.Start))
        {
            if (!TryCallAllocationBytes(site.Target, allocations, calls, memo, active,
                    out long called))
            {
                active.Remove(method);
                return false;
            }
            total = called > long.MaxValue - total ? long.MaxValue : total + called;
        }
        active.Remove(method);
        memo[method] = total;
        return true;
    }

    private static bool TryCallAllocationObjects(ISymbol method,
        ConcurrentDictionary<ISymbol, ConcurrentBag<AllocationSite>> allocations,
        ConcurrentDictionary<ISymbol, ConcurrentBag<CallSite>> calls,
        Dictionary<ISymbol, long> memo, HashSet<ISymbol> active, out long total)
    {
        if (memo.TryGetValue(method, out total))
            return true;
        if (!active.Add(method))
        {
            total = 0;
            return false;
        }
        total = DirectAllocationObjects(method, allocations);
        if (calls.TryGetValue(method, out var sites))
            foreach (var site in sites.OrderBy(static site => site.Location.SourceSpan.Start))
            {
                if (!TryCallAllocationObjects(site.Target, allocations, calls, memo, active,
                        out long called))
                {
                    active.Remove(method);
                    return false;
                }
                total = called > long.MaxValue - total ? long.MaxValue : total + called;
            }
        active.Remove(method);
        memo[method] = total;
        return true;
    }

    private static void ReportRepeatedAllocation(OperationAnalysisContext context, IOperation operation)
    {
        if (operation.Syntax.Ancestors().Any(static ancestor => ancestor is
                ForStatementSyntax or ForEachStatementSyntax or WhileStatementSyntax or
                DoStatementSyntax))
            Report(context, RepeatedAllocation, operation.Syntax.GetLocation());
    }

    private static void AnalyzeCollectionExpression(OperationAnalysisContext context)
    {
        var operation = (ICollectionExpressionOperation)context.Operation;
        if (operation.Type is IArrayTypeSymbol)
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
        if (IsProjectedSystemCryptography(member))
            return true;
        if (member is IMethodSymbol transactionMethod && IsExplicitTransactionCall(transactionMethod))
            return true;
        if (member.ContainingAssembly?.Name == "MicroCard.Framework" &&
            member.ContainingNamespace?.ToDisplayString() == "MicroCard.Framework")
            return true;
        return member.ContainingAssembly is { } provider &&
               provider.GetAttributes().Any(IsDependencyExportAttribute) &&
               compilation.Assembly.GetAttributes().Any(attribute =>
                   IsDependencyAttribute(attribute) &&
                   attribute.ConstructorArguments.Length > 0 &&
                   ((attribute.NamedArguments.FirstOrDefault(argument => argument.Key == "ReferenceAssembly").Value.Value as string)
                    ?? (attribute.ConstructorArguments[0].Value as string)) == provider.Name);
    }

    private static bool IsProjectedSystemCryptography(ISymbol member)
    {
        if (member is not IMethodSymbol { IsStatic: true } method ||
            member.ContainingNamespace?.ToDisplayString() != "System.Security.Cryptography" ||
            member.ContainingAssembly?.Name != "System.Security.Cryptography" ||
            method.ReturnType is not IArrayTypeSymbol result ||
            result.ElementType.SpecialType != SpecialType.System_Byte || method.Parameters.Length != 1)
            return false;
        if (method is { Name: "HashData", ContainingType.Name: "SHA256" } &&
            method.Parameters[0].Type is IArrayTypeSymbol input)
            return input.ElementType.SpecialType == SpecialType.System_Byte;
        return method is { Name: "GetBytes", ContainingType.Name: "RandomNumberGenerator" } &&
               method.Parameters[0].Type.SpecialType == SpecialType.System_Int32;
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
            named.Name is "SecurityDomain" or "DomainStorage" or "DomainKeys" or "KeyHandle")
            return true;
        if (IsTransactionScope(named))
            return true;
        return SymbolEqualityComparer.Default.Equals(named.ContainingAssembly, compilation.Assembly) &&
               named.TypeKind == TypeKind.Class && named.IsSealed;
    }

    private static bool IsAssemblyAttribute(AttributeData attribute) =>
        IsFrameworkAttribute(attribute, "AssemblyAttribute");

    private static bool IsLifecycleAttribute(AttributeData attribute) =>
        attribute.AttributeClass?.Name is "InstallAttribute" or "SelectAttribute" or
            "DeselectAttribute" or "ProcessAttribute" or "UninstallAttribute" &&
        attribute.AttributeClass.ContainingAssembly?.Name == "MicroCard.Framework" &&
        attribute.AttributeClass.ContainingNamespace?.ToDisplayString() == "MicroCard.Framework";

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

    private static bool IsIrreversibleFrameworkCall(IMethodSymbol method) =>
        method.Name == "Write" && method.ContainingType?.Name == "Hardware" &&
        method.ContainingAssembly?.Name == "MicroCard.Framework" &&
        method.ContainingNamespace?.ToDisplayString() == "MicroCard.Framework";

    private static bool IsTransactionScope(ITypeSymbol? type) =>
        type?.Name == "TransactionScope" &&
        type.ContainingNamespace?.ToDisplayString() == "System.Transactions" &&
        type.ContainingAssembly?.Name == "System.Transactions.Local";

    private static bool IsExplicitTransactionCall(IMethodSymbol method) =>
        IsTransactionScope(method.ContainingType) &&
        (method is { MethodKind: MethodKind.Constructor, Parameters.Length: 0 } ||
         method is { Name: "Complete", Parameters.Length: 0, ReturnsVoid: true });

    private static void AnalyzeTransactions(
        CompilationAnalysisContext context,
        ConcurrentDictionary<ISymbol, ConcurrentBag<CallSite>> calls)
    {
        foreach (var method in calls.Keys.OfType<IMethodSymbol>().Where(method =>
                     method.DeclaredAccessibility == Accessibility.Public ||
                     method.GetAttributes().Any(IsLifecycleAttribute)))
        {
            bool explicitControl = ReachesExplicitTransaction(context.Compilation, calls, method,
                new HashSet<ISymbol>(SymbolEqualityComparer.Default));
            if (explicitControl)
                AnalyzeTransactionMethod(context, calls, method, method,
                    new HashSet<ISymbol>(SymbolEqualityComparer.Default));
        }
    }

    private static bool ReachesExplicitTransaction(
        Compilation compilation,
        ConcurrentDictionary<ISymbol, ConcurrentBag<CallSite>> calls,
        IMethodSymbol method,
        HashSet<ISymbol> visited)
    {
        if (!visited.Add(method) || !calls.TryGetValue(method, out var invocations))
            return false;
        foreach (var call in invocations)
        {
            if (IsExplicitTransactionCall(call.Target))
                return true;
            if (SymbolEqualityComparer.Default.Equals(
                    call.Target.ContainingAssembly, compilation.Assembly) &&
                ReachesExplicitTransaction(compilation, calls, call.Target, visited))
                return true;
        }
        return false;
    }

    private static void AnalyzeTransactionMethod(
        CompilationAnalysisContext context,
        ConcurrentDictionary<ISymbol, ConcurrentBag<CallSite>> calls,
        IMethodSymbol root,
        IMethodSymbol method,
        HashSet<ISymbol> visited)
    {
        if (!visited.Add(method) || !calls.TryGetValue(method, out var invocations))
            return;
        foreach (var call in invocations)
        {
            if (IsIrreversibleFrameworkCall(call.Target))
                context.ReportDiagnostic(Diagnostic.Create(TransactionSafety,
                    call.Location, root.Name, call.Target.ToDisplayString()));
            else if (SymbolEqualityComparer.Default.Equals(
                         call.Target.ContainingAssembly,
                         context.Compilation.Assembly))
                AnalyzeTransactionMethod(context, calls, root, call.Target, visited);
        }
    }

    private static void AnalyzeCallGraphs(
        CompilationAnalysisContext context,
        ConcurrentDictionary<ISymbol, ConcurrentBag<CallSite>> calls)
    {
        foreach (var root in calls.Keys.OfType<IMethodSymbol>().Where(method =>
                     method.DeclaredAccessibility == Accessibility.Public ||
                     method.GetAttributes().Any(IsLifecycleAttribute)))
        {
            var active = new HashSet<ISymbol>(SymbolEqualityComparer.Default);
            AnalyzeCallGraph(context, calls, root, root, 1, active);
        }
    }

    private static bool AnalyzeCallGraph(
        CompilationAnalysisContext context,
        ConcurrentDictionary<ISymbol, ConcurrentBag<CallSite>> calls,
        IMethodSymbol root,
        IMethodSymbol method,
        int depth,
        HashSet<ISymbol> active)
    {
        active.Add(method);
        if (calls.TryGetValue(method, out var invocations))
            foreach (var call in invocations)
            {
                var target = call.Target;
                if (!SymbolEqualityComparer.Default.Equals(
                        target.ContainingAssembly, context.Compilation.Assembly))
                    continue;
                if (active.Contains(target))
                {
                    context.ReportDiagnostic(Diagnostic.Create(CallGraph,
                        call.Location,
                        $"Call graph from '{root.Name}' contains recursion through '{target.Name}'"));
                    active.Remove(method);
                    return true;
                }
                if (depth >= 32)
                {
                    context.ReportDiagnostic(Diagnostic.Create(CallGraph,
                        call.Location,
                        $"Call graph from '{root.Name}' exceeds the 32-frame limit"));
                    active.Remove(method);
                    return true;
                }
                if (AnalyzeCallGraph(context, calls, root, target, depth + 1, active))
                {
                    active.Remove(method);
                    return true;
                }
            }
        active.Remove(method);
        return false;
    }

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

    private static string TrimAttribute(string name) =>
        name.EndsWith("Attribute", StringComparison.Ordinal)
            ? name.Substring(0, name.Length - "Attribute".Length)
            : name;

    private static void Report(SymbolAnalysisContext context, DiagnosticDescriptor rule,
        Location location, params object[] arguments) =>
        context.ReportDiagnostic(Diagnostic.Create(rule, location, arguments));

    private static void Report(OperationAnalysisContext context, DiagnosticDescriptor rule,
        Location location, params object[] arguments) =>
        context.ReportDiagnostic(Diagnostic.Create(rule, location, arguments));
}
