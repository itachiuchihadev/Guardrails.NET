using System.Threading.Tasks;
using Guardrails.NET.Validators;
using Xunit;

namespace Guardrails.NET.Tests;

public class ToxicWordValidatorTests
{
    [Fact]
    public async Task ValidateAsync_DetectsAndRedactsProhibitedWords()
    {
        var validator = new ToxicWordValidator(new[] { "confidential", "internal_only", "restricted" });
        string input = "This is a confidential document and is marked as internal_only.";

        var result = await validator.ValidateAsync(input);

        Assert.False(result.IsValid);
        Assert.Equal(2, result.Violations.Count);
        Assert.Equal("This is a [BLOCKED] document and is marked as [BLOCKED].", result.SanitizedContent);
    }

    [Fact]
    public async Task ValidateAsync_IsCaseInsensitive()
    {
        var validator = new ToxicWordValidator(new[] { "badword" });
        string input = "This contains BADWORD and BadWord.";

        var result = await validator.ValidateAsync(input);

        Assert.False(result.IsValid);
        Assert.Equal("This contains [BLOCKED] and [BLOCKED].", result.SanitizedContent);
    }

    [Fact]
    public async Task ValidateAsync_RespectsWordBoundaries()
    {
        var validator = new ToxicWordValidator(new[] { "cat" });
        string input = "The catch was cataloged by the cat.";

        var result = await validator.ValidateAsync(input);

        Assert.False(result.IsValid);
        Assert.Single(result.Violations);
        // Only standalone "cat" is redacted, not "catch" or "cataloged"
        Assert.Equal("The catch was cataloged by the [BLOCKED].", result.SanitizedContent);
    }

    [Fact]
    public async Task ValidateAsync_PassesCleanContent()
    {
        var validator = new ToxicWordValidator(new[] { "forbidden" });
        string input = "This is a safe and permitted sentence.";

        var result = await validator.ValidateAsync(input);

        Assert.True(result.IsValid);
        Assert.Empty(result.Violations);
        Assert.Equal(input, result.SanitizedContent);
    }
}
