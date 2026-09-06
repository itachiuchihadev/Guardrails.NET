using System.Threading;
using System.Threading.Tasks;
using Guardrails.NET.Abstractions;

namespace Guardrails.NET.Tools;

/// <summary>
/// Defines a validator that inspects tool/function invocations requested by LLM agents.
/// </summary>
public interface IToolCallValidator
{
    /// <summary>
    /// The unique name of this tool validator.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Validates a tool invocation context.
    /// </summary>
    Task<GuardResult> ValidateToolCallAsync(ToolCallContext context, CancellationToken cancellationToken = default);
}
