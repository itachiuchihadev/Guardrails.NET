using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Guardrails.NET.Abstractions;

namespace Guardrails.NET.Validators;

/// <summary>
/// Scans content for Personally Identifiable Information (PII) including emails, SSNs, credit cards, and phone numbers.
/// </summary>
public sealed class NoPiiValidator : IGuardValidator
{
    private static readonly Regex EmailRegex = new(
        @"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex SsnRegex = new(
        @"\b\d{3}-\d{2}-\d{4}\b",
        RegexOptions.Compiled);

    private static readonly Regex PhoneRegex = new(
        @"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        RegexOptions.Compiled);

    private static readonly Regex CreditCardRegex = new(
        @"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{15,16}\b",
        RegexOptions.Compiled);

    public string Name => "NoPiiValidator";

    public bool ScanEmails { get; set; } = true;
    public bool ScanSsns { get; set; } = true;
    public bool ScanPhones { get; set; } = true;
    public bool ScanCreditCards { get; set; } = true;

    public string EmailMask { get; set; } = "[REDACTED_EMAIL]";
    public string SsnMask { get; set; } = "[REDACTED_SSN]";
    public string PhoneMask { get; set; } = "[REDACTED_PHONE]";
    public string CreditCardMask { get; set; } = "[REDACTED_CREDIT_CARD]";

    public Task<GuardResult> ValidateAsync(string content, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(content))
        {
            return Task.FromResult(GuardResult.Pass(content));
        }

        var violations = new List<string>();
        string sanitized = content;

        if (ScanEmails && EmailRegex.IsMatch(sanitized))
        {
            violations.Add("Email address detected.");
            sanitized = EmailRegex.Replace(sanitized, EmailMask);
        }

        if (ScanSsns && SsnRegex.IsMatch(sanitized))
        {
            violations.Add("US Social Security Number detected.");
            sanitized = SsnRegex.Replace(sanitized, SsnMask);
        }

        if (ScanCreditCards && CreditCardRegex.IsMatch(sanitized))
        {
            violations.Add("Credit card number detected.");
            sanitized = CreditCardRegex.Replace(sanitized, CreditCardMask);
        }

        if (ScanPhones && PhoneRegex.IsMatch(sanitized))
        {
            violations.Add("Phone number detected.");
            sanitized = PhoneRegex.Replace(sanitized, PhoneMask);
        }

        if (violations.Count > 0)
        {
            return Task.FromResult(GuardResult.Fail(violations, sanitized));
        }

        return Task.FromResult(GuardResult.Pass(content));
    }
}
