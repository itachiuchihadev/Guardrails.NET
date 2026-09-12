using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Guardrails.NET.Internal;
using Guardrails.NET.Tools;

namespace Guardrails.NET.Abstractions;

/// <summary>
/// Convenient abstract base class for implementing guard validators that can be used across input, output, and tool pipelines.
/// </summary>
public abstract class GuardValidatorBase : IGuardValidator
{
    public abstract string Name { get; }

    /// <summary>
    /// Validates and optionally sanitizes input/output text content.
    /// Default implementation returns <see cref="GuardResult.Pass(string?)"/>.
    /// </summary>
    public virtual Task<GuardResult> ValidateAsync(string content, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(GuardResult.Pass(content));
    }

    /// <summary>
    /// Validates a tool invocation context and its arguments during tool execution.
    /// Default implementation iterates over all string arguments and runs <see cref="ValidateAsync(string, CancellationToken)"/>.
    /// </summary>
    public virtual async Task<GuardResult> ValidateToolCallAsync(ToolCallContext context, CancellationToken cancellationToken = default)
    {
        GuardHelper.ThrowIfNull(context);

        if (context.Arguments == null || context.Arguments.Count == 0)
        {
            return GuardResult.Pass(context.FunctionName);
        }

        var allViolations = new List<string>();

        foreach (var kvp in context.Arguments)
        {
            if (GuardHelper.TryExtractString(kvp.Value, out var strVal) && !string.IsNullOrWhiteSpace(strVal))
            {
                var result = await ValidateAsync(strVal, cancellationToken);
                if (!result.IsValid)
                {
                    for (int i = 0; i < result.Violations.Count; i++)
                    {
                        allViolations.Add($"Parameter '{kvp.Key}': {result.Violations[i]}");
                    }
                    if (result.SanitizedContent != null && result.SanitizedContent != strVal)
                    {
                        context.Arguments[kvp.Key] = result.SanitizedContent;
                    }
                }
            }
        }

        if (allViolations.Count > 0)
        {
            return GuardResult.Fail(allViolations, context.FunctionName);
        }

        return GuardResult.Pass(context.FunctionName);
    }
}
