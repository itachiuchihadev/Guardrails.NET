using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Guardrails.NET.Abstractions;
using Guardrails.NET.Internal;
using Microsoft.Extensions.Logging;

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

    /// <summary>
    /// Gets or sets an optional logger for recording guardrail evaluations.
    /// </summary>
    public ILogger? Logger { get; set; }

    public GuardPipeline()
    {
    }

    public GuardPipeline(params IGuardValidator[] validators)
    {
        if (validators != null)
        {
            AddValidators(validators);
        }
    }

    public GuardPipeline(IEnumerable<IGuardValidator> validators, OnFailAction failAction = OnFailAction.Sanitize)
    {
        if (validators != null)
        {
            AddValidators(validators);
        }
        FailAction = failAction;
    }

    public GuardPipeline AddValidator(IGuardValidator validator)
    {
        GuardHelper.ThrowIfNull(validator);
        _validators.Add(validator);
        return this;
    }

    public GuardPipeline AddValidators(params IGuardValidator[] validators)
    {
        GuardHelper.ThrowIfNull(validators);
        foreach (var validator in validators)
        {
            AddValidator(validator);
        }
        return this;
    }

    public GuardPipeline AddValidators(IEnumerable<IGuardValidator> validators)
    {
        GuardHelper.ThrowIfNull(validators);
        foreach (var validator in validators)
        {
            AddValidator(validator);
        }
        return this;
    }

    public async Task<GuardResult> ValidateAsync(string content, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(content))
        {
            return GuardResult.Pass(content);
        }

        if (Logger != null && Logger.IsEnabled(LogLevel.Debug))
        {
            Logger.LogDebug("Validating content (length {Length}) against {ValidatorCount} guard validator(s).", content.Length, _validators.Count);
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

                if (Logger != null && Logger.IsEnabled(LogLevel.Warning))
                {
                    Logger.LogWarning("Guard validator '{ValidatorName}' detected {Count} violation(s): {Violations}",
                        validator.Name, result.Violations.Count, string.Join("; ", result.Violations));
                }

                if (FailAction == OnFailAction.ThrowException)
                {
                    throw new GuardViolationException(
                        $"Guard validator '{validator.Name}' detected violations: {string.Join("; ", result.Violations)}",
                        allViolations);
                }

                if (FailAction == OnFailAction.Sanitize && result.SanitizedContent != null)
                {
                    if (Logger != null && Logger.IsEnabled(LogLevel.Information))
                    {
                        Logger.LogInformation("Guard validator '{ValidatorName}' sanitized content.", validator.Name);
                    }
                    currentContent = result.SanitizedContent;
                }
            }
        }

        bool overallValid = allViolations.Count == 0;
        string finalContent;
        if (!overallValid && FailAction == OnFailAction.ReturnFallback)
        {
            if (Logger != null && Logger.IsEnabled(LogLevel.Warning))
            {
                Logger.LogWarning("Guard pipeline validation failed with {ViolationCount} violation(s). Returning fallback response.", allViolations.Count);
            }
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

        if (overallValid && Logger != null && Logger.IsEnabled(LogLevel.Debug))
        {
            Logger.LogDebug("Guard pipeline validation passed with 0 violations.");
        }

        return new GuardResult(
            overallValid,
            allViolations,
            finalContent);
    }
}

