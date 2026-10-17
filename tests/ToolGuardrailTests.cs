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

    private class CustomRateLimitToolValidator : GuardValidatorBase
    {
        private int _callCount = 0;
        public override string Name => "CustomRateLimitToolValidator";

        public override Task<GuardResult> ValidateToolCallAsync(ToolCallContext context, System.Threading.CancellationToken cancellationToken = default)
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

    [Fact]
    public async Task ToolPipeline_WithContentValidators_ValidatesToolArgumentsDirectly()
    {
        var pipeline = new ToolGuardrailPipeline(
            new SqlInjectionValidator(),
            new NoPiiValidator(),
            new SecretsValidator());

        // 1. Tool call with SQL injection argument
        var sqlContext = new ToolCallContext("query_db", new Dictionary<string, object?>
        {
            ["sql"] = "SELECT * FROM accounts WHERE id=1 OR 1=1;"
        });
        var sqlResult = await pipeline.ValidateAsync(sqlContext);
        Assert.False(sqlResult.IsValid);
        Assert.Contains(sqlResult.Violations, v => v.Contains("SQL injection"));

        // 2. Tool call with PII argument
        var piiContext = new ToolCallContext("send_email", new Dictionary<string, object?>
        {
            ["recipient"] = "admin@enterprise.com",
            ["body"] = "User SSN is 123-45-6789"
        });
        var piiResult = await pipeline.ValidateAsync(piiContext);
        Assert.False(piiResult.IsValid);
        Assert.Contains(piiResult.Violations, v => v.Contains("Social Security"));
    }

    [Fact]
    public async Task GuardPipeline_WithToolSpecificValidators_ValidatesDirectContent()
    {
        var inputPipeline = new GuardPipeline(
            new FileAccessValidator(new FileAccessOptions { AllowedRoots = [@"C:\App\Data"] }),
            new SsrfProtectionValidator());

        // 1. File traversal path in input
        var pathResult = await inputPipeline.ValidateAsync(@"..\..\secret.config");
        Assert.False(pathResult.IsValid);
        Assert.Contains(pathResult.Violations, v => v.Contains("traversal") || v.Contains("permitted workspace"));

        // 2. Private IP in input
        var urlResult = await inputPipeline.ValidateAsync("http://169.254.169.254/latest/meta-data/");
        Assert.False(urlResult.IsValid);
        Assert.Contains(urlResult.Violations, v => v.Contains("SSRF Protection"));
    }

    [Fact]
    public async Task ToolPipeline_WithJsonElementArguments_ValidatesProperly()
    {
        using var jsonDoc = System.Text.Json.JsonDocument.Parse(@"{
            ""content"": ""SELECT * FROM users WHERE id = 1 OR 1=1"",
            ""apiKey"": ""sk-ant-api03-abcdef1234567890abcdef1234567890"",
            ""email"": ""alice@example.com"",
            ""path"": ""../../protected/.env""
        }");

        var root = jsonDoc.RootElement;
        var args = new Dictionary<string, object?>
        {
            ["content"] = root.GetProperty("content"),
            ["apiKey"] = root.GetProperty("apiKey"),
            ["email"] = root.GetProperty("email"),
            ["path"] = root.GetProperty("path")
        };

        // 1. SqlInjectionValidator with JsonElement
        var sqlValidator = new SqlInjectionValidator();
        var sqlContext = new ToolCallContext("query_db", new Dictionary<string, object?>
        {
            ["content"] = root.GetProperty("content")
        });
        var sqlResult = await sqlValidator.ValidateToolCallAsync(sqlContext);
        Assert.False(sqlResult.IsValid);
        Assert.Contains(sqlResult.Violations, v => v.Contains("SQL injection"));

        // 2. SecretsValidator with JsonElement
        var secretsValidator = new SecretsValidator();
        var secretsContext = new ToolCallContext("set_token", new Dictionary<string, object?>
        {
            ["apiKey"] = root.GetProperty("apiKey")
        });
        var secretsResult = await secretsValidator.ValidateToolCallAsync(secretsContext);
        Assert.False(secretsResult.IsValid);
        Assert.Contains(secretsResult.Violations, v => v.Contains("Anthropic API key"));

        // 3. NoPiiValidator with JsonElement
        var piiValidator = new NoPiiValidator();
        var piiContext = new ToolCallContext("send_message", new Dictionary<string, object?>
        {
            ["email"] = root.GetProperty("email")
        });
        var piiResult = await piiValidator.ValidateToolCallAsync(piiContext);
        Assert.False(piiResult.IsValid);
        Assert.Contains(piiResult.Violations, v => v.Contains("Email address"));

        // 4. FileAccessValidator with JsonElement
        var fileValidator = new FileAccessValidator();
        var fileContext = new ToolCallContext("read_file", new Dictionary<string, object?>
        {
            ["path"] = root.GetProperty("path")
        });
        var fileResult = await fileValidator.ValidateToolCallAsync(fileContext);
        Assert.False(fileResult.IsValid);
        Assert.Contains(fileResult.Violations, v => v.Contains("Path traversal") || v.Contains("protected file"));
    }

    [Fact]
    public void ToolCallContext_FindStringArgument_ExtractsJsonElementAndPrimitives()
    {
        using var jsonDoc = System.Text.Json.JsonDocument.Parse(@"{
            ""stringVal"": ""hello world"",
            ""numVal"": 42,
            ""boolVal"": true
        }");

        var root = jsonDoc.RootElement;
        var context = new ToolCallContext("test_tool", new Dictionary<string, object?>
        {
            ["str"] = root.GetProperty("stringVal"),
            ["num"] = root.GetProperty("numVal"),
            ["flag"] = root.GetProperty("boolVal"),
            ["rawInt"] = 100
        });

        Assert.Equal("hello world", context.FindStringArgument("str"));
        Assert.Equal("42", context.FindStringArgument("num"));
        Assert.Equal("true", context.FindStringArgument("flag"));
        Assert.Equal("100", context.FindStringArgument("rawInt"));
    }

    [Fact]
    public async Task GuardedChatClient_ReturnFeedbackToModel_InjectsFunctionResultContent_ModelSelfCorrects()
    {
        // Turn 1: LLM attempts a dangerous tool call (path traversal in read_file)
        // Turn 2: LLM receives the [Security Error] in a Tool-role message and self-corrects with a safe text reply
        var scriptedClient = new MockScriptedChatClient(
            _ => new ChatResponse(new ChatMessage(ChatRole.Assistant, [
                new FunctionCallContent("call_blocked_1", "read_file", new Dictionary<string, object?>
                {
                    ["path"] = "../../etc/passwd"
                })
            ])),
            messages =>
            {
                // Verify the second turn received the feedback
                var toolMsg = messages.FirstOrDefault(m => m.Role == ChatRole.Tool);
                Assert.NotNull(toolMsg);
                var result = toolMsg.Contents.OfType<FunctionResultContent>().FirstOrDefault();
                Assert.NotNull(result);
                Assert.Equal("call_blocked_1", result.CallId);
                Assert.Contains("[Security Error]", result.Result?.ToString());
                Assert.Contains("Path traversal", result.Result?.ToString());

                return new ChatResponse(new ChatMessage(ChatRole.Assistant, "I apologize, I cannot access that file. Here is the public info."));
            }
        );

        var toolPipeline = new ToolGuardrailPipeline(new FileAccessValidator())
        {
            FailAction = OnToolFailAction.ReturnFeedbackToModel
        };

        var guardedClient = scriptedClient.UseGuard(toolPipeline: toolPipeline);

        var response = await guardedClient.GetResponseAsync("Please read ../../etc/passwd");

        Assert.Equal("I apologize, I cannot access that file. Here is the public info.", response.Text);
        Assert.Equal(2, scriptedClient.CallHistory.Count);
    }

    [Fact]
    public async Task GuardedChatClient_AllowedToolCall_ExecutesAndReturnsResult()
    {
        var calculatorTool = AIFunctionFactory.Create(
            (int a, int b) => a + b,
            name: "add_numbers",
            description: "Adds two integers together.");

        var chatOptions = new ChatOptions { Tools = [calculatorTool] };

        // Turn 1: LLM calls add_numbers(15, 27)
        // Turn 2: LLM receives FunctionResultContent(42) and produces text answer
        var scriptedClient = new MockScriptedChatClient(
            _ => new ChatResponse(new ChatMessage(ChatRole.Assistant, [
                new FunctionCallContent("call_calc_1", "add_numbers", new Dictionary<string, object?>
                {
                    ["a"] = 15,
                    ["b"] = 27
                })
            ])),
            messages =>
            {
                var toolMsg = messages.FirstOrDefault(m => m.Role == ChatRole.Tool);
                Assert.NotNull(toolMsg);
                var result = toolMsg.Contents.OfType<FunctionResultContent>().FirstOrDefault();
                Assert.NotNull(result);
                Assert.Equal("call_calc_1", result.CallId);
                Assert.Equal(42, Convert.ToInt32(result.Result));

                return new ChatResponse(new ChatMessage(ChatRole.Assistant, "The sum of 15 and 27 is 42."));
            }
        );

        var toolPipeline = new ToolGuardrailPipeline(); // Empty pipeline allows all registered tools
        var guardedClient = scriptedClient.UseGuard(toolPipeline: toolPipeline);

        var response = await guardedClient.GetResponseAsync("What is 15 + 27?", chatOptions);

        Assert.Equal("The sum of 15 and 27 is 42.", response.Text);
        Assert.Equal(2, scriptedClient.CallHistory.Count);
    }

    [Fact]
    public async Task GuardedChatClient_ReturnFallbackToUser_ShortCircuitsAtToolCall()
    {
        var scriptedClient = new MockScriptedChatClient(
            _ => new ChatResponse(new ChatMessage(ChatRole.Assistant, [
                new FunctionCallContent("call_fail_1", "read_file", new Dictionary<string, object?>
                {
                    ["path"] = "../../secret.key"
                })
            ]))
        );

        var toolPipeline = new ToolGuardrailPipeline(new FileAccessValidator())
        {
            FailAction = OnToolFailAction.ReturnFallbackToUser,
            FallbackMessage = "File access is restricted."
        };

        var guardedClient = scriptedClient.UseGuard(toolPipeline: toolPipeline);

        var response = await guardedClient.GetResponseAsync("Fetch the secret key.");

        Assert.Equal("File access is restricted.", response.Text);
        Assert.Single(scriptedClient.CallHistory); // Inner client was called ONLY once (no second turn)
    }

    [Fact]
    public async Task GuardedChatClient_MaxToolTurns_ReturnsGracefulMessage()
    {
        // Mock client that endlessly asks to call a tool
        var scriptedClient = new MockScriptedChatClient(
            _ => new ChatResponse(new ChatMessage(ChatRole.Assistant, [
                new FunctionCallContent("call_loop", "noop", new Dictionary<string, object?>())
            ])),
            _ => new ChatResponse(new ChatMessage(ChatRole.Assistant, [
                new FunctionCallContent("call_loop", "noop", new Dictionary<string, object?>())
            ])),
            _ => new ChatResponse(new ChatMessage(ChatRole.Assistant, [
                new FunctionCallContent("call_loop", "noop", new Dictionary<string, object?>())
            ]))
        );

        var guardedClient = scriptedClient.UseGuard(
            toolPipeline: new ToolGuardrailPipeline(),
            options: new GuardChatClientOptions { MaxToolTurns = 3 }
        );

        var response = await guardedClient.GetResponseAsync("Keep doing work.");

        Assert.Equal("I was unable to complete this request within the allowed number of steps.", response.Text);
        Assert.Equal(3, scriptedClient.CallHistory.Count);
    }

    private class MockScriptedChatClient : IChatClient
    {
        private readonly Queue<Func<IEnumerable<ChatMessage>, ChatResponse>> _responses = new();
        public List<List<ChatMessage>> CallHistory { get; } = new();

        public MockScriptedChatClient(params Func<IEnumerable<ChatMessage>, ChatResponse>[] responses)
        {
            foreach (var r in responses) _responses.Enqueue(r);
        }

        public ChatClientMetadata Metadata => new("MockScriptedChatClient");

        public Task<ChatResponse> GetResponseAsync(
            IEnumerable<ChatMessage> chatMessages,
            ChatOptions? options = null,
            System.Threading.CancellationToken cancellationToken = default)
        {
            var msgList = chatMessages.ToList();
            CallHistory.Add(msgList);

            if (_responses.Count > 0)
            {
                var responder = _responses.Dequeue();
                return Task.FromResult(responder(msgList));
            }

            return Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, "Default fallback")));
        }

        public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
            IEnumerable<ChatMessage> chatMessages,
            ChatOptions? options = null,
            [System.Runtime.CompilerServices.EnumeratorCancellation] System.Threading.CancellationToken cancellationToken = default)
        {
            var response = await GetResponseAsync(chatMessages, options, cancellationToken);
            foreach (var msg in response.Messages)
            {
                yield return new ChatResponseUpdate
                {
                    Role = msg.Role,
                    Contents = msg.Contents != null ? new List<AIContent>(msg.Contents) : [new TextContent(msg.Text ?? string.Empty)]
                };
            }
        }

        public object? GetService(Type serviceType, object? key = null) => null;
        public void Dispose() { }
    }
}


