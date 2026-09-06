using System;
using System.Collections.Generic;
using Guardrails.NET.Abstractions;
using Guardrails.NET.Pipeline;
using Guardrails.NET.Tools;
using Guardrails.NET.Validators;

namespace Guardrails.NET.Factories;

/// <summary>
/// Factory for creating configured validators, pipelines, and tool safety guardrails.
/// </summary>
public static class GuardrailsFactory
{
    /// <summary>
    /// Creates an input safety pipeline with any collection of custom or built-in validators.
    /// </summary>
    public static GuardPipeline CreateInputPipeline(params IGuardValidator[] validators)
    {
        return new GuardPipeline(validators) { FailAction = OnFailAction.ReturnFallback };
    }

    /// <summary>
    /// Creates an input safety pipeline with custom/built-in validators and explicit fail action.
    /// </summary>
    public static GuardPipeline CreateInputPipeline(
        IEnumerable<IGuardValidator> validators,
        OnFailAction failAction = OnFailAction.ReturnFallback,
        string? fallbackMessage = null)
    {
        var pipeline = new GuardPipeline(validators, failAction);
        if (fallbackMessage != null)
        {
            pipeline.FallbackMessage = fallbackMessage;
        }
        return pipeline;
    }

    /// <summary>
    /// Creates an output safety pipeline with any collection of custom or built-in validators.
    /// </summary>
    public static GuardPipeline CreateOutputPipeline(params IGuardValidator[] validators)
    {
        return new GuardPipeline(validators) { FailAction = OnFailAction.Sanitize };
    }

    /// <summary>
    /// Creates an output safety pipeline with custom/built-in validators and explicit fail action.
    /// </summary>
    public static GuardPipeline CreateOutputPipeline(
        IEnumerable<IGuardValidator> validators,
        OnFailAction failAction = OnFailAction.Sanitize)
    {
        return new GuardPipeline(validators, failAction);
    }

    /// <summary>
    /// Creates a tool guardrail pipeline with any collection of custom or built-in tool validators.
    /// </summary>
    public static ToolGuardrailPipeline CreateToolPipeline(params IToolCallValidator[] validators)
    {
        return new ToolGuardrailPipeline(validators);
    }

    /// <summary>
    /// Creates a tool guardrail pipeline with custom/built-in tool validators and explicit fail action.
    /// </summary>
    public static ToolGuardrailPipeline CreateToolPipeline(
        IEnumerable<IToolCallValidator> validators,
        OnToolFailAction failAction = OnToolFailAction.ReturnFeedbackToModel)
    {
        return new ToolGuardrailPipeline(validators, failAction);
    }

    /// <summary>
    /// Creates a FileAccessValidator with explicitly specified workspace root, protected file patterns, and extension whitelist.
    /// </summary>
    public static FileAccessValidator CreateFileAccessValidator(
        string? workspaceRoot = null,
        IEnumerable<string>? protectedPatterns = null,
        IEnumerable<string>? allowedExtensions = null,
        bool readOnly = false,
        bool disallowPathTraversal = true)
    {
        var options = new FileAccessOptions
        {
            AllowedRoots = string.IsNullOrWhiteSpace(workspaceRoot) ? null : [workspaceRoot!],
            AllowedExtensions = allowedExtensions,
            ReadOnly = readOnly,
            DisallowPathTraversal = disallowPathTraversal
        };

        if (protectedPatterns != null)
        {
            options.ProtectedPatterns = protectedPatterns;
        }

        return new FileAccessValidator(options);
    }

    /// <summary>
    /// Creates an SsrfProtectionValidator with explicit domain whitelist, blacklist, and private IP blocking settings.
    /// </summary>
    public static SsrfProtectionValidator CreateSsrfValidator(
        IEnumerable<string>? allowedDomains = null,
        IEnumerable<string>? blockedDomains = null,
        bool blockPrivateIps = true,
        IEnumerable<string>? allowedSchemes = null)
    {
        var options = new SsrfProtectionOptions
        {
            AllowedDomains = allowedDomains,
            BlockedDomains = blockedDomains,
            BlockPrivateIpAddresses = blockPrivateIps
        };

        if (allowedSchemes != null)
        {
            options.AllowedSchemes = allowedSchemes;
        }

        return new SsrfProtectionValidator(options);
    }

    /// <summary>
    /// Creates a RegexArgumentValidator to validate a specific tool parameter pattern.
    /// </summary>
    public static RegexArgumentValidator CreateRegexArgumentValidator(
        string argumentName,
        string pattern,
        string? targetFunctionName = null,
        string? errorMessage = null)
    {
        return new RegexArgumentValidator(argumentName, pattern, targetFunctionName, errorMessage);
    }

    /// <summary>
    /// Creates a ToolPermissionValidator with explicit allowed and blocked tool names.
    /// </summary>
    public static ToolPermissionValidator CreateToolPermissionValidator(
        IEnumerable<string>? allowedTools = null,
        IEnumerable<string>? blockedTools = null,
        Func<string, bool>? permissionChecker = null)
    {
        return new ToolPermissionValidator(allowedTools, blockedTools, permissionChecker);
    }

    /// <summary>
    /// Creates a ready-to-use PII sanitizer AITool for passing directly to an agent via ChatOptions.Tools.
    /// </summary>
    public static Microsoft.Extensions.AI.AIFunction CreatePiiAITool(string? name = null, string? description = null) =>
        new NoPiiValidator().AsAITool(name, description);

    /// <summary>
    /// Creates a prompt injection detection AITool for passing directly to an agent via ChatOptions.Tools.
    /// </summary>
    public static Microsoft.Extensions.AI.AIFunction CreatePromptInjectionAITool(string? name = null, string? description = null) =>
        new PromptInjectionValidator().AsAITool(name, description);

    /// <summary>
    /// Creates a secrets & credential redaction AITool for passing directly to an agent via ChatOptions.Tools.
    /// </summary>
    public static Microsoft.Extensions.AI.AIFunction CreateSecretsAITool(string? name = null, string? description = null) =>
        new SecretsValidator().AsAITool(name, description);

    /// <summary>
    /// Creates a SQL injection safety checker AITool for passing directly to an agent via ChatOptions.Tools.
    /// </summary>
    public static Microsoft.Extensions.AI.AIFunction CreateSqlSafetyAITool(string? name = null, string? description = null) =>
        new SqlInjectionValidator().AsAITool(name, description);

    /// <summary>
    /// Creates a file path sandbox validator AITool for passing directly to an agent via ChatOptions.Tools.
    /// </summary>
    public static Microsoft.Extensions.AI.AIFunction CreateFileAccessAITool(
        string? workspaceRoot = null,
        IEnumerable<string>? protectedPatterns = null,
        IEnumerable<string>? allowedExtensions = null,
        string? name = null,
        string? description = null)
    {
        var validator = CreateFileAccessValidator(workspaceRoot, protectedPatterns, allowedExtensions);
        return validator.AsAITool(name, description);
    }

    /// <summary>
    /// Creates an SSRF URL validator AITool for passing directly to an agent via ChatOptions.Tools.
    /// </summary>
    public static Microsoft.Extensions.AI.AIFunction CreateSsrfAITool(
        IEnumerable<string>? allowedDomains = null,
        IEnumerable<string>? blockedDomains = null,
        bool blockPrivateIps = true,
        string? name = null,
        string? description = null)
    {
        var validator = CreateSsrfValidator(allowedDomains, blockedDomains, blockPrivateIps);
        return validator.AsAITool(name, description);
    }

    /// <summary>
    /// Converts a collection of validators into a list of AITool instances for ChatOptions.Tools.
    /// </summary>
    public static IList<Microsoft.Extensions.AI.AITool> CreateAITools(params IGuardValidator[] validators)
    {
        var list = new List<Microsoft.Extensions.AI.AITool>(validators.Length);
        foreach (var v in validators)
        {
            list.Add(v.AsAITool());
        }
        return list;
    }
}
