using System.Threading;
using System.Threading.Tasks;

namespace Guardrails.NET.Abstractions;

/// <summary>
/// Interface for content validation and sanitization guardrails.
/// </summary>
public interface IGuardValidator
{
    /// <summary>
    /// Descriptive name of the guard validator.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Validates and optionally sanitizes the input content.
    /// </summary>
    Task<GuardResult> ValidateAsync(string content, CancellationToken cancellationToken = default);
}
