using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Guardrails.NET.Abstractions;

namespace Guardrails.NET.Validators;

/// <summary>
/// Scans content for sensitive credentials and API secrets including OpenAI, Anthropic, AWS, GitHub tokens, JWTs, and Private Keys.
/// </summary>
public sealed class SecretsValidator : IGuardValidator
{
    private static readonly (string Description, Regex Regex, string Mask)[] SecretRules = new[]
    {
        // Anthropic API Keys
        ("Anthropic API key",
         new Regex(@"\bsk-ant-[-A-Za-z0-9_]{20,}\b", RegexOptions.Compiled),
         "[REDACTED_ANTHROPIC_KEY]"),

        // OpenAI API Keys
        ("OpenAI API key",
         new Regex(@"\bsk-(?!ant-)(?:proj-|live-)?[-A-Za-z0-9_]{20,}\b", RegexOptions.Compiled),
         "[REDACTED_OPENAI_KEY]"),

        // AWS Access Key ID
        ("AWS Access Key ID",
         new Regex(@"\bAKIA[0-9A-Z]{16}\b", RegexOptions.Compiled),
         "[REDACTED_AWS_KEY]"),

        // GitHub Personal Access Token (classic & fine-grained)
        ("GitHub Token",
         new Regex(@"\b(?:ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{22,})\b", RegexOptions.Compiled),
         "[REDACTED_GITHUB_TOKEN]"),

        // Slack Bot Token
        ("Slack Bot Token",
         new Regex(@"\bxoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}\b", RegexOptions.Compiled),
         "[REDACTED_SLACK_TOKEN]"),

        // Private Key headers
        ("Private Key block",
         new Regex(@"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", RegexOptions.Compiled),
         "[REDACTED_PRIVATE_KEY]"),

        // JSON Web Token (JWT)
        ("JSON Web Token (JWT)",
         new Regex(@"\beyJ[-A-Za-z0-9_]{10,}\.eyJ[-A-Za-z0-9_]{10,}\.[-A-Za-z0-9_./+=]{10,}\b", RegexOptions.Compiled),
         "[REDACTED_JWT]")
    };

    public string Name => "SecretsValidator";

    public string DefaultMask { get; set; } = "[REDACTED_SECRET]";
    public bool UseSpecificMasks { get; set; } = true;

    public Task<GuardResult> ValidateAsync(string content, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            return Task.FromResult(GuardResult.Pass(content));
        }

        var violations = new List<string>();
        string sanitized = content;

        foreach (var (description, regex, mask) in SecretRules)
        {
            if (regex.IsMatch(sanitized))
            {
                violations.Add($"Credential leak detected: {description}.");
                string replacement = UseSpecificMasks ? mask : DefaultMask;
                sanitized = regex.Replace(sanitized, replacement);
            }
        }

        if (violations.Count > 0)
        {
            return Task.FromResult(GuardResult.Fail(violations, sanitized));
        }

        return Task.FromResult(GuardResult.Pass(content));
    }
}
