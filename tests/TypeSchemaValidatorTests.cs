using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using Guardrails.NET.Validators;
using Xunit;

namespace Guardrails.NET.Tests;

public class SampleUserDto
{
    [Required]
    public string Name { get; set; } = string.Empty;

    [Range(18, 120)]
    public int Age { get; set; }

    [EmailAddress]
    public string Email { get; set; } = string.Empty;
}

public class TypeSchemaValidatorTests
{
    private readonly TypeSchemaValidator<SampleUserDto> _validator = new();

    [Fact]
    public async Task ValidateAsync_WithValidJson_Passes()
    {
        string json = "{\"name\": \"Alice\", \"age\": 30, \"email\": \"alice@example.com\"}";
        var result = await _validator.ValidateAsync(json);

        Assert.True(result.IsValid);
        Assert.Empty(result.Violations);
        Assert.Equal(json, result.SanitizedContent);
    }

    [Fact]
    public async Task ValidateAsync_WithMarkdownWrappedJson_ExtractsAndPasses()
    {
        string response = "Here is the user profile:\n```json\n{\"name\": \"Bob\", \"age\": 25, \"email\": \"bob@example.com\"}\n```\nHope that helps!";
        var result = await _validator.ValidateAsync(response);

        Assert.True(result.IsValid);
        Assert.Empty(result.Violations);
        Assert.Equal("{\"name\": \"Bob\", \"age\": 25, \"email\": \"bob@example.com\"}", result.SanitizedContent);
    }

    [Fact]
    public async Task ValidateAsync_WithInvalidJsonSyntax_Fails()
    {
        string invalidJson = "{\"name\": \"Bob\", age: not_a_number}";
        var result = await _validator.ValidateAsync(invalidJson);

        Assert.False(result.IsValid);
        Assert.Contains("failed JSON deserialization", result.Violations[0]);
    }

    [Fact]
    public async Task ValidateAsync_WithAnnotationViolations_Fails()
    {
        // Age is out of range (< 18), email is not a valid email address
        string badData = "{\"name\": \"Charlie\", \"age\": 12, \"email\": \"invalid-email\"}";
        var result = await _validator.ValidateAsync(badData);

        Assert.False(result.IsValid);
        Assert.NotEmpty(result.Violations);
        Assert.Contains(result.Violations, v => v.Contains("Property validation failed"));
    }
}
