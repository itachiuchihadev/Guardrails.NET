using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Guardrails.NET.Abstractions;

namespace Guardrails.NET.Pipeline;

/// <summary>
/// Orchestrates execution of a sequence of guard validators.
/// </summary>
public sealed class GuardPipeline
{
    private readonly List<IGuardValidator> _validators = new();

    public IReadOnlyList<IGuardValidator> Validators => _validators;

    public OnFailAction FailAction { get; set; } = OnFailAction.Sanitize;

    /// <summary>
    /// Message returned when FailAction is set to ReturnFallback and violations occur.
    /// </summary>
    public string FallbackMessage { get; set; } = "I am unable to fulfill this request as it violates safety guidelines.";

    public GuardPipeline AddValidator(IGuardValidator validator)
    {
        ArgumentNullException.ThrowIfNull(validator);
        _validators.Add(validator);
        return this;
    }

    public async Task<GuardResult> ValidateAsync(string content, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(content))
        {
            return GuardResult.Pass(content);
        }

        string currentContent = content;
        var allViolations = new List<string>();

        foreach (var validator in _validators)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var result = await validator.ValidateAsync(currentContent, cancellationToken);
            if (!result.IsValid)
            {
                allViolations.AddRange(result.Violations);

                if (FailAction == OnFailAction.ThrowException)
                {
                    throw new GuardViolationException(
                        $"Guard validator '{validator.Name}' detected violations: {string.Join("; ", result.Violations)}",
                        allViolations);
                }

                if (FailAction == OnFailAction.Sanitize && result.SanitizedContent != null)
                {
                    currentContent = result.SanitizedContent;
                }
            }
        }

        bool overallValid = allViolations.Count == 0;
        string finalContent;
        if (!overallValid && FailAction == OnFailAction.ReturnFallback)
        {
            finalContent = FallbackMessage;
        }
        else if (FailAction == OnFailAction.Sanitize)
        {
            finalContent = currentContent;
        }
        else
        {
            finalContent = content;
        }

        return new GuardResult(
            overallValid,
            allViolations,
            finalContent);
    }
}
