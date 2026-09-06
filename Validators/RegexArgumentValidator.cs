using System;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Guardrails.NET.Abstractions;
using Guardrails.NET.Internal;
using Guardrails.NET.Tools;

namespace Guardrails.NET.Validators;

/// <summary>
/// Validates a specific tool argument value against a regular expression pattern.
/// </summary>
public sealed class RegexArgumentValidator : IToolCallValidator
{
    private static readonly TimeSpan DefaultRegexTimeout = TimeSpan.FromSeconds(1);
    private readonly string _argumentName;
    private readonly Regex _regex;
    private readonly string? _targetFunctionName;
    private readonly string? _errorMessage;

    public RegexArgumentValidator(
        string argumentName,
        string pattern,
        string? targetFunctionName = null,
        string? errorMessage = null,
        RegexOptions options = RegexOptions.None,
        TimeSpan? matchTimeout = null)
    {
        GuardHelper.ThrowIfNull(argumentName);
        GuardHelper.ThrowIfNull(pattern);

        _argumentName = argumentName;
        _regex = new Regex(pattern, options | RegexOptions.Compiled, matchTimeout ?? DefaultRegexTimeout);
        _targetFunctionName = targetFunctionName;
        _errorMessage = errorMessage;
    }

    public string Name => $"RegexArgumentValidator({_argumentName})";

    public Task<GuardResult> ValidateToolCallAsync(ToolCallContext context, CancellationToken cancellationToken = default)
    {
        GuardHelper.ThrowIfNull(context);

        // If targetFunctionName is specified and does not match, skip
        if (_targetFunctionName != null &&
            !string.Equals(context.FunctionName, _targetFunctionName, StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(GuardResult.Pass(context.FunctionName));
        }

        string? argVal = context.FindStringArgument(_argumentName);
        if (argVal == null)
        {
            return Task.FromResult(GuardResult.Pass(context.FunctionName));
        }

        if (!_regex.IsMatch(argVal))
        {
            string violation = _errorMessage ??
                $"Argument '{_argumentName}' with value '{argVal}' does not match required pattern '{_regex}'.";

            return Task.FromResult(GuardResult.Fail(new[] { violation }, argVal));
        }

        return Task.FromResult(GuardResult.Pass(argVal));
    }
}
