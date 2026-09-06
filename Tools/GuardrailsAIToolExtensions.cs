using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Guardrails.NET.Abstractions;
using Guardrails.NET.Internal;
using Guardrails.NET.Pipeline;
using Guardrails.NET.Validators;
using Microsoft.Extensions.AI;

namespace Guardrails.NET.Tools;

/// <summary>
/// Extension methods for effortlessly converting Guardrails validators and pipelines into Microsoft.Extensions.AI AITool / AIFunction instances.
/// </summary>
public static class GuardrailsAIToolExtensions
{
    /// <summary>
    /// Converts an IGuardValidator into an AIFunction tool that can be directly passed to an LLM via ChatOptions.Tools.
    /// </summary>
    public static AIFunction AsAITool(
        this IGuardValidator validator,
        string? name = null,
        string? description = null)
    {
        GuardHelper.ThrowIfNull(validator);

        string toolName = name ?? GetDefaultToolName(validator);
        string toolDesc = description ?? GetDefaultToolDescription(validator);

        return AIFunctionFactory.Create(
            async (string content, CancellationToken cancellationToken) =>
            {
                var result = await validator.ValidateAsync(content, cancellationToken);
                return result;
            },
            name: toolName,
            description: toolDesc);
    }

    /// <summary>
    /// Converts an entire GuardPipeline into a single composite AIFunction tool.
    /// </summary>
    public static AIFunction AsAITool(
        this GuardPipeline pipeline,
        string name = "validate_guardrails",
        string description = "Validates content through all safety guardrail rules in the pipeline.")
    {
        GuardHelper.ThrowIfNull(pipeline);

        return AIFunctionFactory.Create(
            async (string content, CancellationToken cancellationToken) =>
            {
                var result = await pipeline.ValidateAsync(content, cancellationToken);
                return result;
            },
            name: name,
            description: description);
    }

    /// <summary>
    /// Converts all validators in the pipeline into individual AITool instances.
    /// </summary>
    public static IList<AITool> AsAITools(this GuardPipeline pipeline)
    {
        GuardHelper.ThrowIfNull(pipeline);

        var list = new List<AITool>(pipeline.Validators.Count);
        foreach (var validator in pipeline.Validators)
        {
            list.Add(validator.AsAITool());
        }
        return list;
    }

    private static string GetDefaultToolName(IGuardValidator validator) => validator switch
    {
        NoPiiValidator => "sanitize_pii",
        PromptInjectionValidator => "check_prompt_injection",
        SecretsValidator => "redact_secrets",
        SqlInjectionValidator => "verify_sql_safety",
        FileAccessValidator => "validate_file_path",
        SsrfProtectionValidator => "validate_url_safety",
        ToxicWordValidator => "check_toxic_words",
        _ => validator.Name.Replace("Validator", "").ToLowerInvariant() + "_guard"
    };

    private static string GetDefaultToolDescription(IGuardValidator validator) => validator switch
    {
        NoPiiValidator => "Scans text for Personally Identifiable Information (PII) including emails, SSNs, credit cards, and phone numbers, and returns sanitized text.",
        PromptInjectionValidator => "Scans input prompts for jailbreak attacks, prompt injection, and delimiter spoofing.",
        SecretsValidator => "Scans content and redacts API keys, credentials, tokens, and private keys.",
        SqlInjectionValidator => "Analyzes SQL queries for hazardous injection tokens, tautologies, and destructive operations.",
        FileAccessValidator => "Validates file paths against sandbox directory roots, path traversal, and protected file policies.",
        SsrfProtectionValidator => "Validates URLs against SSRF attacks, internal/private IP ranges, cloud metadata, and domain whitelists.",
        ToxicWordValidator => "Scans and redacts prohibited or toxic terms from text.",
        _ => $"Executes safety guardrail validation for '{validator.Name}'."
    };
}
