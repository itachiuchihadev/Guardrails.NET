using System.Threading.Tasks;
using AIGuard.NET.Validators;
using Xunit;

namespace AIGuard.NET.Tests;

public class PiiValidatorTests
{
    [Fact]
    public async Task ValidateAsync_DetectsAndRedactsEmails()
    {
        var validator = new NoPiiValidator();
        string input = "Contact our CEO directly at alice.smith@enterprise.org for questions.";

        var result = await validator.ValidateAsync(input);

        Assert.False(result.IsValid);
        Assert.Contains(result.Violations, v => v.Contains("Email"));
        Assert.Equal("Contact our CEO directly at [REDACTED_EMAIL] for questions.", result.SanitizedContent);
    }

    [Fact]
    public async Task ValidateAsync_DetectsAndRedactsSsn()
    {
        var validator = new NoPiiValidator();
        string input = "My federal identification number is 123-45-6789.";

        var result = await validator.ValidateAsync(input);

        Assert.False(result.IsValid);
        Assert.Contains(result.Violations, v => v.Contains("Social Security"));
        Assert.Equal("My federal identification number is [REDACTED_SSN].", result.SanitizedContent);
    }

    [Fact]
    public async Task ValidateAsync_DetectsAndRedactsCreditCards()
    {
        var validator = new NoPiiValidator();
        string input = "Please charge 4111-2222-3333-4444 for the transaction.";

        var result = await validator.ValidateAsync(input);

        Assert.False(result.IsValid);
        Assert.Contains(result.Violations, v => v.Contains("Credit card"));
        Assert.Equal("Please charge [REDACTED_CREDIT_CARD] for the transaction.", result.SanitizedContent);
    }

    [Fact]
    public async Task ValidateAsync_PassesCleanContent()
    {
        var validator = new NoPiiValidator();
        string input = "The quick brown fox jumps over the lazy dog.";

        var result = await validator.ValidateAsync(input);

        Assert.True(result.IsValid);
        Assert.Empty(result.Violations);
        Assert.Equal(input, result.SanitizedContent);
    }
}
