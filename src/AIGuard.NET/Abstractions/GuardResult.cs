using System;
using System.Collections.Generic;
using System.Linq;

namespace AIGuard.NET.Abstractions;

/// <summary>
/// Result of running a guard validation against content.
/// </summary>
public sealed class GuardResult
{
    public bool IsValid { get; }
    public IReadOnlyList<string> Violations { get; }
    public string? SanitizedContent { get; }

    public GuardResult(bool isValid, IEnumerable<string>? violations = null, string? sanitizedContent = null)
    {
        IsValid = isValid;
        Violations = violations?.ToList() ?? (IReadOnlyList<string>)Array.Empty<string>();
        SanitizedContent = sanitizedContent;
    }

    public static GuardResult Pass(string? sanitizedContent = null) =>
        new(true, null, sanitizedContent);

    public static GuardResult Fail(string violation, string? sanitizedContent = null) =>
        new(false, new[] { violation }, sanitizedContent);

    public static GuardResult Fail(IEnumerable<string> violations, string? sanitizedContent = null) =>
        new(false, violations, sanitizedContent);
}
