using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Guardrails.NET.Abstractions;

namespace Guardrails.NET.Validators;

/// <summary>
/// Scans content for blocked words or toxic terms and can redact or reject them.
/// </summary>
public sealed class ToxicWordValidator : IGuardValidator
{
    private readonly HashSet<string> _blockedWords;

    public string Name => "ToxicWordValidator";
    public string ReplacementToken { get; set; } = "[BLOCKED]";

    public ToxicWordValidator(IEnumerable<string> blockedWords)
    {
        ArgumentNullException.ThrowIfNull(blockedWords);
        _blockedWords = new HashSet<string>(blockedWords, StringComparer.OrdinalIgnoreCase);
    }

    public Task<GuardResult> ValidateAsync(string content, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(content) || _blockedWords.Count == 0)
        {
            return Task.FromResult(GuardResult.Pass(content));
        }

        var violations = new List<string>();
        string sanitized = content;

        foreach (var word in _blockedWords)
        {
            if (string.IsNullOrWhiteSpace(word)) continue;

            string pattern = $@"\b{Regex.Escape(word)}\b";
            if (Regex.IsMatch(sanitized, pattern, RegexOptions.IgnoreCase))
            {
                violations.Add($"Prohibited term detected: '{word}'");
                sanitized = Regex.Replace(sanitized, pattern, ReplacementToken, RegexOptions.IgnoreCase);
            }
        }

        if (violations.Count > 0)
        {
            return Task.FromResult(GuardResult.Fail(violations, sanitized));
        }

        return Task.FromResult(GuardResult.Pass(content));
    }
}
