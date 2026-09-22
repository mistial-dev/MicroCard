using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace MicroCard.Analyzers;

public sealed partial class MicroCardProfileAnalyzer
{
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

    private static void AnalyzeCallGraphs(
        CompilationAnalysisContext context,
        ConcurrentDictionary<ISymbol, ConcurrentBag<CallSite>> calls)
    {
        foreach (var root in calls.Keys.OfType<IMethodSymbol>().Where(method =>
                     method.DeclaredAccessibility == Accessibility.Public || IsLifecycleMethod(method)))
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
}

