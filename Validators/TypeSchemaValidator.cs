using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Guardrails.NET.Abstractions;

namespace Guardrails.NET.Validators;

/// <summary>
/// Validates that content is valid JSON conforming to target type T and passes System.ComponentModel.DataAnnotations validation.
/// </summary>
/// <typeparam name="T">The expected C# class or record structure.</typeparam>
public sealed class TypeSchemaValidator<T> : GuardValidatorBase where T : class
{
    private static readonly TimeSpan DefaultRegexTimeout = TimeSpan.FromSeconds(1);

    private static readonly Regex MarkdownCodeFenceRegex = new(
        @"```(?:json)?\s*([\s\S]*?)\s*```",
        RegexOptions.Compiled | RegexOptions.IgnoreCase,
        DefaultRegexTimeout);

    public override string Name => $"TypeSchemaValidator<{typeof(T).Name}>";

    public JsonSerializerOptions JsonOptions { get; set; } = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public override Task<GuardResult> ValidateAsync(string content, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            return Task.FromResult(GuardResult.Fail($"Content was empty; expected JSON matching type '{typeof(T).Name}'."));
        }

        // 1. Extract JSON from markdown fence or find outer brackets
        string jsonCandidate = ExtractJsonCandidate(content);

        // 2. Attempt JSON Deserialization
        T? instance;
        try
        {
            instance = JsonSerializer.Deserialize<T>(jsonCandidate, JsonOptions);
            if (instance == null)
            {
                return Task.FromResult(GuardResult.Fail($"Deserialized JSON for type '{typeof(T).Name}' evaluated to null."));
            }
        }
        catch (JsonException ex)
        {
            return Task.FromResult(GuardResult.Fail(
                $"Content failed JSON deserialization for '{typeof(T).Name}': {ex.Message}"));
        }

        // 3. Validate DataAnnotations
        var validationResults = new List<ValidationResult>();
        var validationContext = new ValidationContext(instance);
        bool isValid = Validator.TryValidateObject(instance, validationContext, validationResults, validateAllProperties: true);

        if (!isValid)
        {
            var errors = validationResults
                .Select(r => $"Property validation failed: {r.ErrorMessage}")
                .ToList();

            return Task.FromResult(GuardResult.Fail(errors, jsonCandidate));
        }

        // Passes validation; return clean JSON as sanitized content
        return Task.FromResult(GuardResult.Pass(jsonCandidate));
    }

    private static string ExtractJsonCandidate(string content)
    {
        var match = MarkdownCodeFenceRegex.Match(content);
        if (match.Success && match.Groups.Count > 1)
        {
            return match.Groups[1].Value.Trim();
        }

        int firstBrace = content.IndexOfAny(new[] { '{', '[' });
        int lastBrace = content.LastIndexOfAny(new[] { '}', ']' });

        if (firstBrace >= 0 && lastBrace > firstBrace)
        {
            return content.Substring(firstBrace, lastBrace - firstBrace + 1).Trim();
        }

        return content.Trim();
    }

    public override async Task<GuardResult> ValidateToolCallAsync(Guardrails.NET.Tools.ToolCallContext context, CancellationToken cancellationToken = default)
    {
        Guardrails.NET.Internal.GuardHelper.ThrowIfNull(context);

        if (context.Arguments == null || context.Arguments.Count == 0)
        {
            return GuardResult.Pass(context.FunctionName);
        }

        // Search for JSON candidate argument (e.g. json, payload, data, body, content) or first string
        string? targetJson = context.FindStringArgument("json", "payload", "data", "body", "content", "model", "input");

        if (targetJson == null)
        {
            foreach (var kvp in context.Arguments)
            {
                if (Guardrails.NET.Internal.GuardHelper.TryExtractString(kvp.Value, out var str) &&
                    (str.TrimStart().StartsWith("{") || str.TrimStart().StartsWith("[")))
                {
                    targetJson = str;
                    break;
                }
            }
        }

        if (targetJson != null)
        {
            return await ValidateAsync(targetJson, cancellationToken);
        }

        return GuardResult.Pass(context.FunctionName);
    }
}

