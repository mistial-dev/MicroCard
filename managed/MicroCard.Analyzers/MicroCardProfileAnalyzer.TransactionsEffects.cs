using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace MicroCard.Analyzers;

public sealed partial class MicroCardProfileAnalyzer
{
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

    private static bool IsIrreversibleFrameworkCall(IMethodSymbol method) =>
        method.Name == "Write" && method.ContainingType?.Name == "Hardware" &&
        method.ContainingAssembly?.Name == "MicroCard.Framework" &&
        method.ContainingNamespace?.ToDisplayString() == "MicroCard.Framework";

    private static bool IsTransactionScope(ITypeSymbol? type) =>
        type?.Name == "TransactionScope" &&
        type.ContainingNamespace?.ToDisplayString() == "System.Transactions" &&
        type.ContainingAssembly?.Name == "System.Transactions.Local";

    private static bool IsTransactionType(ITypeSymbol? type) =>
        type?.Name is "Transaction" or "TransactionInformation" or "TransactionStatus" &&
        type.ContainingNamespace?.ToDisplayString() == "System.Transactions" &&
        type.ContainingAssembly?.Name == "System.Transactions.Local";

    private static bool IsAmbientTransactionProperty(IPropertySymbol property)
    {
        if (property.Parameters.Length != 0 ||
            property.ContainingNamespace?.ToDisplayString() != "System.Transactions" ||
            property.ContainingAssembly?.Name != "System.Transactions.Local")
            return false;

        return property is { Name: "Current", IsStatic: true } &&
                   property.ContainingType.Name == "Transaction" &&
                   property.Type.Name == "Transaction" ||
               property is { Name: "TransactionInformation", IsStatic: false } &&
                   property.ContainingType.Name == "Transaction" &&
                   property.Type.Name == "TransactionInformation" ||
               property is { Name: "Status", IsStatic: false } &&
                   property.ContainingType.Name == "TransactionInformation" &&
                   property.Type.Name == "TransactionStatus";
    }

    private static bool IsExplicitTransactionCall(IMethodSymbol method) =>
        IsTransactionScope(method.ContainingType) &&
        (method is { MethodKind: MethodKind.Constructor, Parameters.Length: 0 } ||
         method is { Name: "Complete", Parameters.Length: 0, ReturnsVoid: true });

    private static void AnalyzeTransactions(
        CompilationAnalysisContext context,
        ConcurrentDictionary<ISymbol, ConcurrentBag<CallSite>> calls)
    {
        foreach (var method in calls.Keys.OfType<IMethodSymbol>().Where(method =>
                     method.DeclaredAccessibility == Accessibility.Public || IsLifecycleMethod(method)))
        {
            bool explicitControl = ReachesExplicitTransaction(context.Compilation, calls, method,
                new HashSet<ISymbol>(SymbolEqualityComparer.Default));
            if (explicitControl && IsLifecycleMethod(method) && method.Name != "Process")
                context.ReportDiagnostic(Diagnostic.Create(Lifecycle,
                    method.Locations.First(static location => location.IsInSource),
                    $"Lifecycle method '{method.Name}' cannot open a transaction"));
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
}
