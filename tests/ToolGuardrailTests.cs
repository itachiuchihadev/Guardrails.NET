using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Guardrails.NET.Abstractions;
using Guardrails.NET.Extensions;
using Guardrails.NET.Pipeline;
using Guardrails.NET.Tools;
using Guardrails.NET.Validators;
using Microsoft.Extensions.AI;
using Xunit;

namespace Guardrails.NET.Tests;

public class ToolGuardrailTests
{
    [Theory]
    [InlineData("../../etc/passwd")]
    [InlineData("..\\..\\secret.txt")]
    [InlineData("folder/../../../root.txt")]
    [InlineData("folder/%2e%2e/secret.txt")]
    public async Task FileAccessValidator_BlocksPathTraversal(string maliciousPath)
    {
        var validator = new FileAccessValidator();
        var context = new ToolCallContext("read_file", new Dictionary<string, object?> { ["path"] = maliciousPath });

        var result = await validator.ValidateToolCallAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("Path traversal attempt", result.Violations[0]);
    }

    [Theory]
    [InlineData(".env")]
    [InlineData(".env.production")]
    [InlineData("appsettings.json")]
    [InlineData("appsettings.Development.json")]
    [InlineData("id_rsa.key")]
    [InlineData("cert.pem")]
    [InlineData(".git/config")]
    public async Task FileAccessValidator_BlocksProtectedFiles(string protectedPath)
    {
        var validator = new FileAccessValidator();
        var context = new ToolCallContext("edit_file", new Dictionary<string, object?> { ["filePath"] = protectedPath });

        var result = await validator.ValidateToolCallAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("protected file", result.Violations[0]);
    }

    [Fact]
    public async Task FileAccessValidator_AllowsSafeFileWithinAllowedRoots()
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), "GuardrailsSandbox");
        Directory.CreateDirectory(tempRoot);
        string safeFile = Path.Combine(tempRoot, "src", "Program.cs");

        var validator = new FileAccessValidator(new FileAccessOptions
        {
            AllowedRoots = new[] { tempRoot },
            AllowedExtensions = new[] { ".cs", ".json" }
        });

        var context = new ToolCallContext("write_file", new Dictionary<string, object?> { ["filePath"] = safeFile });
        var result = await validator.ValidateToolCallAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task FileAccessValidator_BlocksPrefixSiblingDirectoryTraversal()
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), "GuardrailsSandbox");
        string siblingAttackerDir = Path.Combine(Path.GetTempPath(), "GuardrailsSandbox_Attacker");
        string maliciousFile = Path.Combine(siblingAttackerDir, "secret.txt");

        var validator = new FileAccessValidator(new FileAccessOptions
        {
            AllowedRoots = [tempRoot]
        });

        var context = new ToolCallContext("read_file", new Dictionary<string, object?> { ["filePath"] = maliciousFile });
        var result = await validator.ValidateToolCallAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("outside permitted workspace roots", result.Violations[0]);
    }

    [Fact]
    public void GuardResult_Pass_CachesSuccessInstance()
    {
        var pass1 = GuardResult.Pass();
        var pass2 = GuardResult.Pass(null);

        Assert.Same(GuardResult.Success, pass1);
        Assert.Same(GuardResult.Success, pass2);
        Assert.True(pass1.IsValid);
        Assert.Empty(pass1.Violations);
    }

    [Fact]
    public async Task FileAccessValidator_EnforcesReadOnlyMode()
    {
        var validator = new FileAccessValidator(new FileAccessOptions { ReadOnly = true });
        var context = new ToolCallContext("edit_file", new Dictionary<string, object?> { ["path"] = "src/Service.cs" });

        var result = await validator.ValidateToolCallAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("read-only mode", result.Violations[0]);
    }

    [Theory]
    [InlineData("http://localhost:8080/admin")]
    [InlineData("http://127.0.0.1/status")]
    [InlineData("http://169.254.169.254/latest/meta-data/")] // AWS/GCP/Azure Cloud Metadata
    [InlineData("http://10.0.0.5/api")]
    [InlineData("http://192.168.1.1/router")]
    [InlineData("http://172.16.5.10/internal")]
    [InlineData("file:///etc/passwd")]
    public async Task SsrfProtectionValidator_BlocksPrivateAndRestrictedEndpoints(string targetUrl)
    {
        var validator = new SsrfProtectionValidator();
        var context = new ToolCallContext("fetch_url", new Dictionary<string, object?> { ["url"] = targetUrl });

        var result = await validator.ValidateToolCallAsync(context);

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task SsrfProtectionValidator_AllowsApprovedDomains()
    {
        var validator = new SsrfProtectionValidator(new SsrfProtectionOptions
        {
            AllowedDomains = new[] { "api.github.com", "*.openai.com" }
        });

        var allowedContext = new ToolCallContext("http_get", new Dictionary<string, object?> { ["endpoint"] = "https://api.github.com/repos/microsoft" });
        var resultAllowed = await validator.ValidateToolCallAsync(allowedContext);
        Assert.True(resultAllowed.IsValid);

        var blockedContext = new ToolCallContext("http_get", new Dictionary<string, object?> { ["endpoint"] = "https://malicious-domain.com/data" });
        var resultBlocked = await validator.ValidateToolCallAsync(blockedContext);
        Assert.False(resultBlocked.IsValid);
    }

    [Fact]
    public async Task RegexArgumentValidator_ValidatesParameterPatterns()
    {
        var validator = new RegexArgumentValidator("tableName", "^[a-zA-Z0-9_]+$", errorMessage: "Invalid table name syntax.");

        var validContext = new ToolCallContext("query_table", new Dictionary<string, object?> { ["tableName"] = "users_2026" });
        var validResult = await validator.ValidateToolCallAsync(validContext);
        Assert.True(validResult.IsValid);

        var maliciousContext = new ToolCallContext("query_table", new Dictionary<string, object?> { ["tableName"] = "users; DROP TABLE orders;--" });
        var maliciousResult = await validator.ValidateToolCallAsync(maliciousContext);
        Assert.False(maliciousResult.IsValid);
        Assert.Equal("Invalid table name syntax.", maliciousResult.Violations[0]);
    }

    [Fact]
    public async Task ToolPermissionValidator_EnforcesRBAC()
    {
        var validator = new ToolPermissionValidator(
            allowedTools: new[] { "search_kb", "read_file" },
            blockedTools: new[] { "delete_database", "execute_sql" }
        );

        var allowed = await validator.ValidateToolCallAsync(new ToolCallContext("search_kb"));
        Assert.True(allowed.IsValid);

        var blocked = await validator.ValidateToolCallAsync(new ToolCallContext("delete_database"));
        Assert.False(blocked.IsValid);
        Assert.Contains("blocked by security permissions", blocked.Violations[0]);

        var unlisted = await validator.ValidateToolCallAsync(new ToolCallContext("execute_shell"));
        Assert.False(unlisted.IsValid);
        Assert.Contains("not in the list of allowed tools", unlisted.Violations[0]);
    }

    [Fact]
    public async Task PreToolHook_CanInterceptAndBlockToolInvocation()
    {
        var pipeline = new ToolGuardrailPipeline();
        pipeline.AddPreToolHook(async (ctx, ct) =>
        {
            await Task.Yield();
            if (ctx.FunctionName == "drop_table")
            {
                ctx.IsBlocked = true;
                ctx.BlockReason = "Human confirmation is required for destructive operations.";
            }
        });

        var context = new ToolCallContext("drop_table");
        var result = await pipeline.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("Human confirmation is required", result.Violations[0]);
    }

    [Fact]
    public async Task ToolPipeline_ReturnsFeedbackToModelByDefault()
    {
        var pipeline = new ToolGuardrailPipeline();
        pipeline.AddValidator(new FileAccessValidator());
        pipeline.FailAction = OnToolFailAction.ReturnFeedbackToModel;

        var context = new ToolCallContext("edit_file", new Dictionary<string, object?> { ["filePath"] = ".env" });
        var result = await pipeline.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.NotNull(context.CustomResult);
        Assert.Contains("[Security Error]", context.CustomResult.ToString());
    }

    [Fact]
    public async Task ToolPipeline_ThrowsExceptionWhenConfigured()
    {
        var pipeline = new ToolGuardrailPipeline();
        pipeline.AddValidator(new FileAccessValidator());
        pipeline.FailAction = OnToolFailAction.BlockAndThrow;

        var context = new ToolCallContext("edit_file", new Dictionary<string, object?> { ["filePath"] = ".env" });

        await Assert.ThrowsAsync<GuardViolationException>(() => pipeline.ValidateAsync(context));
    }

    private class CustomRateLimitToolValidator : IToolCallValidator
    {
        private int _callCount = 0;
        public string Name => "CustomRateLimitToolValidator";

        public Task<GuardResult> ValidateToolCallAsync(ToolCallContext context, System.Threading.CancellationToken cancellationToken = default)
        {
            _callCount++;
            if (_callCount > 2)
            {
                return Task.FromResult(GuardResult.Fail(new[] { "Tool call budget exceeded (max 2 calls allowed)." }, context.FunctionName));
            }
            return Task.FromResult(GuardResult.Pass(context.FunctionName));
        }
    }

    [Fact]
    public async Task ToolPipeline_AcceptsUserDefinedCustomToolValidators()
    {
        var customRateLimiter = new CustomRateLimitToolValidator();
        var pipeline = Guardrails.NET.Factories.GuardrailsFactory.CreateToolPipeline(
            customRateLimiter,
            new SsrfProtectionValidator());

        // Call 1: passes
        var res1 = await pipeline.ValidateAsync(new ToolCallContext("fetch_data"));
        Assert.True(res1.IsValid);

        // Call 2: passes
        var res2 = await pipeline.ValidateAsync(new ToolCallContext("fetch_data"));
        Assert.True(res2.IsValid);

        // Call 3: blocked by custom validator
        var res3 = await pipeline.ValidateAsync(new ToolCallContext("fetch_data"));
        Assert.False(res3.IsValid);
        Assert.Contains("budget exceeded", res3.Violations[0]);
    }
}
