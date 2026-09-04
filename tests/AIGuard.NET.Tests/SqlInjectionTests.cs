using System.Threading.Tasks;
using AIGuard.NET.Validators;
using Xunit;

namespace AIGuard.NET.Tests;

public class SqlInjectionTests
{
    private readonly SqlInjectionValidator _validator = new();

    [Theory]
    [InlineData("admin' UNION SELECT * FROM users--")]
    [InlineData("SELECT name FROM accounts WHERE id = 5 OR 1=1")]
    [InlineData("'; DROP TABLE customers;--")]
    [InlineData("EXEC sp_executesql N'SELECT 1'")]
    public async Task ValidateAsync_FlagsHazardousSql(string harmfulQuery)
    {
        var result = await _validator.ValidateAsync(harmfulQuery);

        Assert.False(result.IsValid);
        Assert.NotEmpty(result.Violations);
    }

    [Theory]
    [InlineData("Find all invoices created last week for customer ACME")]
    [InlineData("Can you summarize our sales performance in Q3?")]
    public async Task ValidateAsync_PassesBenignQueries(string safeQuery)
    {
        var result = await _validator.ValidateAsync(safeQuery);

        Assert.True(result.IsValid);
        Assert.Empty(result.Violations);
    }
}
