using System;
using System.Collections.Generic;

namespace Guardrails.NET.Tools;

/// <summary>
/// Represents the context of a tool/function invocation by an LLM agent.
/// </summary>
public sealed class ToolCallContext
{
    public ToolCallContext(string functionName, IDictionary<string, object?>? arguments = null, string? callId = null)
    {
        FunctionName = functionName ?? throw new ArgumentNullException(nameof(functionName));
        Arguments = arguments ?? new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        CallId = callId ?? Guid.NewGuid().ToString("N");
    }

    /// <summary>
    /// Unique identifier for the tool call.
    /// </summary>
    public string CallId { get; set; }

    /// <summary>
    /// The name of the function/tool requested by the LLM.
    /// </summary>
    public string FunctionName { get; set; }

    /// <summary>
    /// The arguments passed to the function by the LLM.
    /// </summary>
    public IDictionary<string, object?> Arguments { get; set; }

    /// <summary>
    /// Gets or sets whether this tool call has been blocked by a validator or hook.
    /// </summary>
    public bool IsBlocked { get; set; }

    /// <summary>
    /// Reason or policy violation message if the tool call was blocked.
    /// </summary>
    public string? BlockReason { get; set; }

    /// <summary>
    /// Optional result to feed back to the LLM or caller when blocked or sanitized.
    /// </summary>
    public object? CustomResult { get; set; }

    /// <summary>
    /// Searches for an argument value matching any of the candidate parameter names (case-insensitive).
    /// </summary>
    public object? FindArgumentValue(params string[] candidateNames) =>
        FindArgumentValue((IReadOnlyList<string>)candidateNames);

    /// <summary>
    /// Searches for an argument value matching any of the candidate parameter names (case-insensitive).
    /// </summary>
    public object? FindArgumentValue(IReadOnlyList<string> candidateNames)
    {
        if (Arguments == null || Arguments.Count == 0 || candidateNames == null || candidateNames.Count == 0)
        {
            return null;
        }

        for (int i = 0; i < candidateNames.Count; i++)
        {
            string name = candidateNames[i];
            foreach (var kvp in Arguments)
            {
                if (string.Equals(kvp.Key, name, StringComparison.OrdinalIgnoreCase))
                {
                    return kvp.Value;
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Searches for a string argument value matching candidate parameter names.
    /// </summary>
    public string? FindStringArgument(params string[] candidateNames) =>
        FindStringArgument((IReadOnlyList<string>)candidateNames);

    /// <summary>
    /// Searches for a string argument value matching candidate parameter names.
    /// </summary>
    public string? FindStringArgument(IReadOnlyList<string> candidateNames)
    {
        var val = FindArgumentValue(candidateNames);
        return Guardrails.NET.Internal.GuardHelper.TryExtractString(val, out var str) ? str : null;
    }
}
