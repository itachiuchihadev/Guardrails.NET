using System.Threading.Tasks;
using Guardrails.NET.Validators;
using Xunit;

namespace Guardrails.NET.Tests;

public class SecretsValidatorTests
{
    private readonly SecretsValidator _validator = new();

    [Fact]
    public async Task ValidateAsync_WithOpenAiKey_Redacts()
    {
        string input = "Here is my key: sk-abcdef1234567890abcdef1234567890 use it safely.";
        var result = await _validator.ValidateAsync(input);

        Assert.False(result.IsValid);
        Assert.Contains("OpenAI API key", result.Violations[0]);
        Assert.Contains("[REDACTED_OPENAI_KEY]", result.SanitizedContent);
        Assert.DoesNotContain("sk-abcdef1234567890abcdef1234567890", result.SanitizedContent);
    }

    [Fact]
    public async Task ValidateAsync_WithAnthropicKey_Redacts()
    {
        string input = "Anthropic secret: sk-ant-api03-abcdef1234567890abcdef1234567890.";
        var result = await _validator.ValidateAsync(input);

        Assert.False(result.IsValid);
        Assert.Contains("Anthropic API key", result.Violations[0]);
        Assert.Contains("[REDACTED_ANTHROPIC_KEY]", result.SanitizedContent);
    }

    [Fact]
    public async Task ValidateAsync_WithAwsKey_Redacts()
    {
        string input = "AWS credentials: AKIAIOSFODNN7EXAMPLE";
        var result = await _validator.ValidateAsync(input);

        Assert.False(result.IsValid);
        Assert.Contains("AWS Access Key ID", result.Violations[0]);
        Assert.Contains("[REDACTED_AWS_KEY]", result.SanitizedContent);
    }

    [Fact]
    public async Task ValidateAsync_WithGitHubToken_Redacts()
    {
        string input = "GitHub token: ghp_111122223333444455556666777788889999";
        var result = await _validator.ValidateAsync(input);

        Assert.False(result.IsValid);
        Assert.Contains("GitHub Token", result.Violations[0]);
        Assert.Contains("[REDACTED_GITHUB_TOKEN]", result.SanitizedContent);
    }

    [Fact]
    public async Task ValidateAsync_WithPrivateKeyBlock_Redacts()
    {
        string input = @"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y1+examplecontenthere
-----END RSA PRIVATE KEY-----";

        var result = await _validator.ValidateAsync(input);

        Assert.False(result.IsValid);
        Assert.Contains("Private Key block", result.Violations[0]);
        Assert.Contains("[REDACTED_PRIVATE_KEY]", result.SanitizedContent);
    }

    [Fact]
    public async Task ValidateAsync_WithBenignText_Passes()
    {
        string input = "Normal text discussing cloud infrastructure without credentials.";
        var result = await _validator.ValidateAsync(input);

        Assert.True(result.IsValid);
        Assert.Empty(result.Violations);
        Assert.Equal(input, result.SanitizedContent);
    }
}
