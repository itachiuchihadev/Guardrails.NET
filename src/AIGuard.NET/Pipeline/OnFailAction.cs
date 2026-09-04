using System;
using System.Collections.Generic;

namespace AIGuard.NET.Pipeline;

/// <summary>
/// Action to take when a guard validator discovers a violation.
/// </summary>
public enum OnFailAction
{
    /// <summary>
    /// Throws a GuardViolationException immediately.
    /// </summary>
    ThrowException,

    /// <summary>
    /// Automatically replaces offending text with sanitized/redacted tokens.
    /// </summary>
    Sanitize,

    /// <summary>
    /// Records the violation in the result but leaves the content untouched.
    /// </summary>
    LogOnly
}

/// <summary>
/// Exception thrown when content fails guard validation under OnFailAction.ThrowException.
/// </summary>
public class GuardViolationException : Exception
{
    public IReadOnlyList<string> Violations { get; }

    public GuardViolationException(string message, IReadOnlyList<string> violations)
        : base(message)
    {
        Violations = violations;
    }
}
