using System.Threading.Tasks;
using Guardrails.NET.Validators;
using Xunit;

namespace Guardrails.NET.Tests;

public class RegexValidatorTests
{
    [Fact]
    public async Task ValidateAsync_MustMatch_PassesWhenPatternMatches()
    {
        // Must match a valid ticket format: ABC-1234
        var validator = new RegexValidator(@"^[A-Z]{3}-\d{4}$", mustMatch: true, violationMessage: "Invalid ticket format.");
        
        var validResult = await validator.ValidateAsync("PRJ-4521");
        Assert.True(validResult.IsValid);

        var invalidResult = await validator.ValidateAsync("invalid-ticket");
        Assert.False(invalidResult.IsValid);
        Assert.Equal("Invalid ticket format.", invalidResult.Violations[0]);
    }

    [Fact]
    public async Task ValidateAsync_MustNotMatch_RedactsWhenReplacementSpecified()
    {
        // Must NOT match internal code patterns
        var validator = new RegexValidator(@"\bINT-[0-9]+\b", mustMatch: false, replacement: "[REDACTED_INT_CODE]", violationMessage: "Internal code leaked.");

        var result = await validator.ValidateAsync("Ref INT-9921 resolved.");
        Assert.False(result.IsValid);
        Assert.Equal("Ref [REDACTED_INT_CODE] resolved.", result.SanitizedContent);
    }

    [Fact]
    public async Task ValidateAsync_WithEmptyContent_HandlesGracefully()
    {
        var validator = new RegexValidator(@"\d+", mustMatch: false);
        var result = await validator.ValidateAsync("");

        Assert.True(result.IsValid);
    }
}
