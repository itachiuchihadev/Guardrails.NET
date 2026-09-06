using System;
using System.Collections.Generic;
using System.Linq;

namespace Guardrails.NET.Abstractions;

/// <summary>
/// Result of running a guard validation against content.
/// </summary>
public sealed class GuardResult
{
    public bool IsValid { get; }
    public IReadOnlyList<string> Violations { get; }
    public string? SanitizedContent { get; }

    private static readonly IReadOnlyList<string> EmptyViolations = [];
    public static GuardResult Success { get; } = new(true, EmptyViolations, null);

    [System.Text.Json.Serialization.JsonConstructor]
    public GuardResult(bool isValid, IReadOnlyList<string>? violations = null, string? sanitizedContent = null)
    {
        IsValid = isValid;
        Violations = violations ?? EmptyViolations;
        SanitizedContent = sanitizedContent;
    }

    public GuardResult(bool isValid, IEnumerable<string>? violations, string? sanitizedContent = null)
        : this(isValid, violations?.ToList(), sanitizedContent)
    {
    }

    public static GuardResult Pass(string? sanitizedContent = null) =>
        sanitizedContent is null ? Success : new(true, EmptyViolations, sanitizedContent);

    public static GuardResult Fail(string violation, string? sanitizedContent = null) =>
        new(false, [violation], sanitizedContent);

    public static GuardResult Fail(IEnumerable<string> violations, string? sanitizedContent = null) =>
        new(false, violations, sanitizedContent);
}
