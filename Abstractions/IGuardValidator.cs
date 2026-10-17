using System.Threading;
using System.Threading.Tasks;
using Guardrails.NET.Tools;

namespace Guardrails.NET.Abstractions;

/// <summary>
/// Unified interface for content, output, and tool guardrail validators.
/// </summary>
public interface IGuardValidator
{
    /// <summary>
    /// Descriptive name of the guard validator.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Validates and optionally sanitizes input/output text content.
    /// </summary>
    Task<GuardResult> ValidateAsync(string content, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates a tool invocation context and its arguments during tool execution.
    /// </summary>
    Task<GuardResult> ValidateToolCallAsync(ToolCallContext context, CancellationToken cancellationToken = default);
}

