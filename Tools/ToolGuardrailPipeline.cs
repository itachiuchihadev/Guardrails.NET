using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Guardrails.NET.Abstractions;
using Guardrails.NET.Internal;
using Guardrails.NET.Pipeline;

namespace Guardrails.NET.Tools;

/// <summary>
/// Orchestrates pre-tool execution hooks and safety validators for agent tool/function invocations.
/// </summary>
public sealed class ToolGuardrailPipeline
{
    private readonly List<IToolCallValidator> _validators = new();
    private readonly List<Func<ToolCallContext, CancellationToken, Task>> _preToolHooks = new();

    public IReadOnlyList<IToolCallValidator> Validators => _validators;
    public IReadOnlyList<Func<ToolCallContext, CancellationToken, Task>> PreToolHooks => _preToolHooks;

    /// <summary>
    /// Gets or sets the action taken when a tool call fails validation. Defaults to <see cref="OnToolFailAction.ReturnFeedbackToModel"/>.
    /// </summary>
    public OnToolFailAction FailAction { get; set; } = OnToolFailAction.ReturnFeedbackToModel;

    /// <summary>
    /// Fallback message returned to the user when FailAction is <see cref="OnToolFailAction.ReturnFallbackToUser"/>.
    /// </summary>
    public string FallbackMessage { get; set; } = "The requested tool action was blocked due to safety guidelines.";

    public ToolGuardrailPipeline()
    {
    }

    public ToolGuardrailPipeline(params IToolCallValidator[] validators)
    {
        if (validators != null)
        {
            AddValidators(validators);
        }
    }

    public ToolGuardrailPipeline(IEnumerable<IToolCallValidator> validators, OnToolFailAction failAction = OnToolFailAction.ReturnFeedbackToModel)
    {
        if (validators != null)
        {
            AddValidators(validators);
        }
        FailAction = failAction;
    }

    /// <summary>
    /// Adds a tool call validator to the pipeline.
    /// </summary>
    public ToolGuardrailPipeline AddValidator(IToolCallValidator validator)
    {
        GuardHelper.ThrowIfNull(validator);
        _validators.Add(validator);
        return this;
    }

    /// <summary>
    /// Adds multiple tool call validators to the pipeline.
    /// </summary>
    public ToolGuardrailPipeline AddValidators(params IToolCallValidator[] validators)
    {
        GuardHelper.ThrowIfNull(validators);
        foreach (var validator in validators)
        {
            AddValidator(validator);
        }
        return this;
    }

    /// <summary>
    /// Adds multiple tool call validators to the pipeline.
    /// </summary>
    public ToolGuardrailPipeline AddValidators(IEnumerable<IToolCallValidator> validators)
    {
        GuardHelper.ThrowIfNull(validators);
        foreach (var validator in validators)
        {
            AddValidator(validator);
        }
        return this;
    }

    /// <summary>
    /// Adds a custom pre-tool-calling hook to the pipeline.
    /// </summary>
    public ToolGuardrailPipeline AddPreToolHook(Func<ToolCallContext, CancellationToken, Task> hook)
    {
        GuardHelper.ThrowIfNull(hook);
        _preToolHooks.Add(hook);
        return this;
    }

    /// <summary>
    /// Validates a tool invocation context against all registered validators and pre-tool hooks.
    /// </summary>
    public async Task<GuardResult> ValidateAsync(ToolCallContext context, CancellationToken cancellationToken = default)
    {
        GuardHelper.ThrowIfNull(context);

        var allViolations = new List<string>();

        // 1. Run Pre-Tool Hooks
        foreach (var hook in _preToolHooks)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await hook(context, cancellationToken);

            if (context.IsBlocked)
            {
                string reason = context.BlockReason ?? "Tool call was blocked by a pre-invocation hook.";
                allViolations.Add(reason);
                break;
            }
        }

        // 2. Run Tool Validators (if not already blocked)
        if (allViolations.Count == 0)
        {
            foreach (var validator in _validators)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var result = await validator.ValidateToolCallAsync(context, cancellationToken);

                if (!result.IsValid)
                {
                    allViolations.AddRange(result.Violations);
                    context.IsBlocked = true;
                    context.BlockReason = string.Join("; ", result.Violations);
                    break;
                }
            }
        }

        bool isValid = allViolations.Count == 0;

        if (!isValid)
        {
            if (FailAction == OnToolFailAction.BlockAndThrow)
            {
                throw new GuardViolationException(
                    $"Tool '{context.FunctionName}' violated safety policy: {string.Join("; ", allViolations)}",
                    allViolations);
            }

            if (FailAction == OnToolFailAction.ReturnFeedbackToModel && context.CustomResult == null)
            {
                context.CustomResult = $"[Security Error]: Tool execution '{context.FunctionName}' was blocked. Violations: {string.Join("; ", allViolations)}";
            }
        }

        return new GuardResult(isValid, allViolations, context.FunctionName);
    }
}
