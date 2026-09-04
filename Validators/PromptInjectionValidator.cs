using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Guardrails.NET.Abstractions;

namespace Guardrails.NET.Validators;

/// <summary>
/// Scans content for prompt injection attacks, jailbreak patterns, and system delimiter spoofing.
/// </summary>
public sealed class PromptInjectionValidator : IGuardValidator
{
    private static readonly Regex[] BuiltInPatterns = new[]
    {
        // 1. Direct instruction overrides
        new Regex(
            @"\b(?:ignore|disregard|forget|bypass|override)\s+(?:all\s+|your\s+|all\s+your\s+|any\s+|the\s+)?(?:previous|prior|above|initial|system)?\s*(?:instructions|prompts|rules|commands|constraints|directives)\b",
            RegexOptions.Compiled | RegexOptions.IgnoreCase),

        // 2. Jailbreak personas (DAN, Developer Mode, Unrestricted)
        new Regex(
            @"\b(?:you\s+are\s+now|act\s+as)\s+(?:unfiltered|unrestricted|DAN|jailbroken|evil|an\s+AI\s+without\s+rules)\b",
            RegexOptions.Compiled | RegexOptions.IgnoreCase),

        new Regex(
            @"\b(?:do\s+anything\s+now|jailbreak\s+mode|developer\s+mode\s+(?:enabled|output)|unrestricted\s+mode)\b",
            RegexOptions.Compiled | RegexOptions.IgnoreCase),

        // 3. System prompt / role spoofing
        new Regex(
            @"\b(?:new\s+system\s+instruction|system\s+prompt\s+override|switch\s+to\s+developer\s+mode)\b",
            RegexOptions.Compiled | RegexOptions.IgnoreCase),

        // 4. Delimiter and token spoofing (Llama / ChatML / Anthropic faking)
        new Regex(
            @"(?:<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>|\[INST\]\s*<<SYS>>|---\s*BEGIN\s+SYSTEM\s+(?:PROMPT|MESSAGE)\s*---|===\s*SYSTEM\s*===)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase),

        // 5. Encoded / eval execution tricks
        new Regex(
            @"(?:\bbase64_decode\b|\beval\s*\(|\batob\s*\()",
            RegexOptions.Compiled | RegexOptions.IgnoreCase)
    };

    public string Name => "PromptInjectionValidator";

    public string ReplacementToken { get; set; } = "[BLOCKED_INJECTION]";

    /// <summary>
    /// Custom regex patterns to add to the check.
    /// </summary>
    public List<Regex> CustomPatterns { get; } = new();

    public Task<GuardResult> ValidateAsync(string content, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            return Task.FromResult(GuardResult.Pass(content));
        }

        var violations = new List<string>();
        string sanitized = content;

        // Check built-in patterns
        foreach (var pattern in BuiltInPatterns)
        {
            if (pattern.IsMatch(sanitized))
            {
                violations.Add($"Prompt injection or jailbreak attempt detected: match on pattern '{pattern}'.");
                sanitized = pattern.Replace(sanitized, ReplacementToken);
            }
        }

        // Check custom patterns
        foreach (var pattern in CustomPatterns)
        {
            if (pattern.IsMatch(sanitized))
            {
                violations.Add($"Custom prompt injection pattern detected: '{pattern}'.");
                sanitized = pattern.Replace(sanitized, ReplacementToken);
            }
        }

        if (violations.Count > 0)
        {
            return Task.FromResult(GuardResult.Fail(violations, sanitized));
        }

        return Task.FromResult(GuardResult.Pass(content));
    }
}
