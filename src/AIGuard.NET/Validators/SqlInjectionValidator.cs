using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using AIGuard.NET.Abstractions;

namespace AIGuard.NET.Validators;

/// <summary>
/// Detects hazardous SQL injection tokens, tautologies, and syntax anomalies.
/// </summary>
public sealed class SqlInjectionValidator : IGuardValidator
{
    private static readonly Regex[] SqlPatterns = new[]
    {
        // UNION SELECT
        new Regex(@"\bUNION\s+(?:ALL\s+)?SELECT\b", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        
        // Tautologies like OR 1=1 or OR 'a'='a'
        new Regex(@"\b(?:OR|AND)\s+['""\d\w]+\s*=\s*['""\d\w]+", RegexOptions.Compiled | RegexOptions.IgnoreCase),

        // Destructive DDL / DML
        new Regex(@"\b(?:DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE|ALTER\s+TABLE)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase),

        // Stored procedure execution
        new Regex(@"\b(?:EXEC|EXECUTE)\s+(?:sp_|xp_)\w+", RegexOptions.Compiled | RegexOptions.IgnoreCase),

        // Inline SQL comment sequences
        new Regex(@"(?:--|;--|/\*[\s\S]*?\*/)", RegexOptions.Compiled)
    };

    public string Name => "SqlInjectionValidator";

    public Task<GuardResult> ValidateAsync(string content, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            return Task.FromResult(GuardResult.Pass(content));
        }

        var violations = new List<string>();

        foreach (var pattern in SqlPatterns)
        {
            if (pattern.IsMatch(content))
            {
                violations.Add($"Potential SQL injection pattern detected: '{pattern}'");
            }
        }

        if (violations.Count > 0)
        {
            return Task.FromResult(GuardResult.Fail(violations, content));
        }

        return Task.FromResult(GuardResult.Pass(content));
    }
}
