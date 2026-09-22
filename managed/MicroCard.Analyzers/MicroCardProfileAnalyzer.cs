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
public sealed partial class MicroCardProfileAnalyzer : DiagnosticAnalyzer
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

    private static DiagnosticDescriptor Rule(string id, string title, string message) =>
        new(id, title, message, Category, DiagnosticSeverity.Error, isEnabledByDefault: true,
            description: "Reported before IL preprocessing; device verification remains authoritative.");

    private static void Report(SymbolAnalysisContext context, DiagnosticDescriptor rule,
        Location location, params object[] arguments) =>
        context.ReportDiagnostic(Diagnostic.Create(rule, location, arguments));

    private static void Report(OperationAnalysisContext context, DiagnosticDescriptor rule,
        Location location, params object[] arguments) =>
        context.ReportDiagnostic(Diagnostic.Create(rule, location, arguments));
}

