using System.Threading;
using System.Threading.Tasks;
using Guardrails.NET.Abstractions;

namespace Guardrails.NET.Tools;

/// <summary>
/// Defines a validator that inspects tool/function invocations requested by LLM agents.
/// All tool validators implement <see cref="IGuardValidator"/> and can be used across all pipelines.
/// </summary>
public interface IToolCallValidator : IGuardValidator
{
}

