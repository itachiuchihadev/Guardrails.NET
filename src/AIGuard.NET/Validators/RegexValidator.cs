using System;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using AIGuard.NET.Abstractions;

namespace AIGuard.NET.Validators;

/// <summary>
/// Validates content against a customizable regular expression.
/// </summary>
public sealed class RegexValidator : IGuardValidator
{
    private readonly Regex _regex;
    private readonly string _name;

    public string Name => _name;
    public string ViolationMessage { get; set; }
    public bool MustMatch { get; set; }
    public string? Replacement { get; set; }

    public RegexValidator(
        string pattern,
        string violationMessage = "Content failed regex validation rule.",
        bool mustMatch = false,
        string? replacement = null,
        string name = "RegexValidator",
        RegexOptions options = RegexOptions.None)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pattern);
        _regex = new Regex(pattern, options);
        ViolationMessage = violationMessage;
        MustMatch = mustMatch;
        Replacement = replacement;
        _name = name;
    }

    public Task<GuardResult> ValidateAsync(string content, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(content))
        {
            return Task.FromResult(MustMatch
                ? GuardResult.Fail(ViolationMessage)
                : GuardResult.Pass(content));
        }

        bool isMatch = _regex.IsMatch(content);

        if (MustMatch && !isMatch)
        {
            return Task.FromResult(GuardResult.Fail(ViolationMessage));
        }

        if (!MustMatch && isMatch)
        {
            string? sanitized = Replacement != null ? _regex.Replace(content, Replacement) : null;
            return Task.FromResult(GuardResult.Fail(ViolationMessage, sanitized));
        }

        return Task.FromResult(GuardResult.Pass(content));
    }
}
